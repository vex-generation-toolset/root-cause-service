# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
import re
import requests

from urllib.parse import (
    quote_plus
)
from bs4 import (
    BeautifulSoup as LinkExtractor
)
from datetime import (
    datetime
)
from loggers import (
    get_logger
)
from typing import (
    List
)

logging = get_logger(__name__)

class BaseLinkManager:
    """
    Base class providing HTTP session handling and HTML parsing.
    """
    def __init__(self, headers: dict = None):
        self.session = requests.Session()
        default_headers = headers or {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            )
        }
        self.session.headers.update(default_headers)

    def fetch(self, url: str) -> str:
        """Fetch raw HTML content from a URL."""
        resp = self.session.get(url)
        if resp.status_code != 200:
            raise Exception(
                f"Failed to access URL {url}, status code: {resp.status_code}"
            )
        return resp.text

    def get_soup(self, url: str):
        """Return a Soup object for a URL."""
        return LinkExtractor(self.fetch(url), "html.parser")
    
class RuleBasedLinkExtractor:
    """
    Extracts and filters URLs based on GitHub-related CVE reference patterns.
    """
    def __init__(self):
        self.target_keywords = [
            "/github",
            "/commit",
            "/pull",
            "/issues",
            "/security/advisories",
            "/tag",
            "/tags",
            "/bitbucket",
            "/sourceware"
            "/commits"
        ]

    def extract_links(self, text: str) -> List[str]:
        urls = re.findall(r"https?://[^\s\"'>]+", text)
        filtered = [
            url for url in urls
            if any(keyword in url for keyword in self.target_keywords)
        ]
        return list(dict.fromkeys(filtered))
    
class NvdLinkManager(BaseLinkManager):
    """
    Link manager for NVD CVE detail pages using rule-based link extraction.
    """

    def __init__(self, extractor: RuleBasedLinkExtractor):
        super().__init__()
        self.extractor = extractor

    def fetch_and_extract_links(self, url: str) -> List[str]:
        text = self.get_soup(url).get_text()
        return self.extractor.extract_links(text)

    def get_vuln_page_urls(self, cve_id: str) -> List[str]:
        return [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]

    def extract_links_for_cve(self, cve_id: str) -> List[str]:
        all_links = []
        for url in self.get_vuln_page_urls(cve_id):
            all_links.extend(self.fetch_and_extract_links(url))
        return list(dict.fromkeys(all_links))   

OSV_ECOSYSTEMS = { 
    "golang": "Go",
    "maven": "Maven",
    "npm": "npm",
    "nuget": "NuGet",
    "pypi": "PyPI",
    "gem": "RubyGems",
}

class OsvLinkManager(BaseLinkManager):
    """
    Link manager for OSV to extract vulnerability IDs and their reference links.
    """
    def fetch_vuln_ids(self, url: str) -> list[str]:
        text = self.get_soup(url).get_text()
        pattern = r"\b(?:CVE|RHSA|GHSA|GO)(?:[-:][A-Za-z0-9]+)+\b"
        return re.findall(pattern, text)

    def get_osv_page_urls(self, cve_id: str, ecosystem: str | None = None) -> list[str]:
        """Return all OSV vulnerability pages that mention *cve_id*,
        filtered to a specific ecosystem when given."""

        ecosystem: str = OSV_ECOSYSTEMS.get((ecosystem or "").lower(), "")
        ecosystem_q: str = quote_plus(ecosystem)

        search_url = f"https://osv.dev/list?q={cve_id}&ecosystem={ecosystem_q}"
        ids = self.fetch_vuln_ids(search_url)

        logging.info(
            f"IDs found form osv",
            extra={
                "cve_id": cve_id,
                "ecosystem": ecosystem,
                "ids": ids,
            },
        )

        return [f"https://osv.dev/vulnerability/{vid}" for vid in ids]

    def extract_reference_links(self, url: str) -> list[str]:
        soup = self.get_soup(url)
        anchors = soup.find_all("a", href=True)
        return [
            a["href"]
            for a in anchors
            if re.search(r"/(commit|pull|issues|security/advisories|tags)", a["href"])
        ]

    def extract_links_for_cve(
        self, cve_id: str, ecosystem: str | None = None
    ) -> list[str]:
        raw_urls = self.get_osv_page_urls(cve_id, ecosystem)
        unique_raw = list(dict.fromkeys(raw_urls))

        refs: list[str] = []
        for url in unique_raw:
            refs.extend(self.extract_reference_links(url))

        return list(dict.fromkeys(refs))


class NvdApiLinkManager(BaseLinkManager):
    """
    Client to fetch CVE details via NVD API and map desired fields.
    """
    def __init__(self):
        super().__init__(
            headers={
                "User-Agent": "python-requests/2.25.1",
                "apiKey": os.getenv("NVD_API_KEY", ""),
            }
        )
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_url_text(self, url: str) -> str:
        try:
            return self.get_soup(url).get_text()
        except Exception:
            return ""

    def _map_cve_entry(self, entry: dict, cve_id: str) -> dict:
        data = entry.get("cve", {})
        if data.get("id") != cve_id:
            return {}
        descs = " ".join(d.get("value", "") for d in data.get("descriptions", []))

        return {descs}

    def get_cve_info(self, cve_id: str) -> dict:
        resp = self.session.get(self.base_url, params={"cveId": cve_id})
        resp.raise_for_status()
        data = resp.json().get("vulnerabilities", [])
        for entry in data:
            mapped = self._map_cve_entry(entry, cve_id)
            if mapped:
                return mapped
        return {}

    @staticmethod
    def get_entire_info(cve_id: str) -> dict:
        """
        Fetch detailed information for a specific CVE ID from the NVD API.
        """
        headers = {
            "User-Agent": "python-requests/2.25.1",
            "apiKey": os.environ["NVD_API_KEY"],
        }
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}
        try:
            response = requests.get(base_url, params=params, headers=headers)
            response.raise_for_status()

            data = response.json()
            return data
        except Exception:
            logging.exception(
                f"Failed to fetch data for CVE",
                stack_info=True,
                exc_info=True,
                extra={
                    "cve_id": cve_id
                }
            )
            return {}

class NvdDateLinkManager(BaseLinkManager):
    """
    Fetches and parses the published date of a CVE via the NVD API.
    """
    def __init__(self):
        api_key = os.getenv("NVD_API_KEY", "")
        super().__init__(headers={"apiKey": api_key})
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def get_publish_date(self, cve_id: str) -> str | None:
        resp = self.session.get(self.base_url, params={"cveId": cve_id})
        resp.raise_for_status()
        vuls = resp.json().get("vulnerabilities", [])
        if not vuls:
            return None
        ts = vuls[0].get("cve", {}).get("published")
        if not ts:
            return None
        return datetime.fromisoformat(ts).date().isoformat()

class DebianCVETracker(BaseLinkManager):
    """
    A managers for extracting GitHub, GitLab, and Sourceware URLs
    from the Debian Security Tracker page of a given CVE.
    Inherits session and parsing methods from BaseLinkManager.
    """
    def __init__(self, cve_id: str):
        """
        Initialize the tracker with a CVE ID and fetch the page.

        Args:
            cve_id (str): CVE identifier, e.g., "CVE-2025-48174".
        """
        super().__init__()
        self.cve_id = cve_id
        self.url = f"https://security-tracker.debian.org/tracker/{cve_id}"
        try:
            self.soup = self.get_soup(self.url)
        except Exception as e:
            self.soup = None
            logging.exception(
                f"Failed to fetch debian cve tracker page",
                stack_info=True,
                exc_info=True,
                extra={
                    "cve_id": cve_id,
                }
            )

    def extract_note_urls(self) -> list[str]:
        """
        Extract GitHub, GitLab, or Sourceware URLs from the notes section which contains relevant urls.

        Returns:
            list[str]: List of filtered external reference URLs.
        """
        if not self.soup:
            return []

        links = self.soup.find_all("a", href=True)
        seen = set()
        urls = []

        for a in links:
            href = a["href"]
            if (
                href.startswith("http")
                and any(
                    site in href
                    for site in ["github.com", "gitlab.com", "sourceware.org"]
                )
                and href not in seen
            ):
                urls.append(href)
                seen.add(href)

        return urls