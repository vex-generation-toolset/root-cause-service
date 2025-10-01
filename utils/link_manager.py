# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

from .websearch_client import (
    OpenAISearchClient
)
from loggers import (
    get_logger
)
from managers import (
    RuleBasedLinkExtractor,
    NvdLinkManager,
    OsvLinkManager,
    DebianCVETracker
)

logging = get_logger(__name__)

class LinkManager:
    """
    Aggregates URLs from multiple sources and returns a list of unique entries.

    Returns:
        list: A list containing unique URLs combined from all sources.
    """
    def __init__(self):
        self.ai = RuleBasedLinkExtractor()
        self.nvd_ai = NvdLinkManager(self.ai)
        self.osv = OsvLinkManager()
        self.tool = OpenAISearchClient()
        self.tracker = None

    def combine_and_extract_unique_links(
            self,
            cve_id: str,
            ecosystem: str
    ) -> list[dict]:
        self.tracker = DebianCVETracker(cve_id)

        links_nvd = [
            {"url": url, "source": "NVD"}
            for url in self.nvd_ai.extract_links_for_cve(cve_id)
        ]
        logging.info(
            "Collected links from NVD",
            extra={
                "cve_id": cve_id,
                "ecosystem": ecosystem,
                "links": links_nvd
            },
        )

        links_osv = [
            {"url": url, "source": "OSV"}
            for url in self.osv.extract_links_for_cve(cve_id, ecosystem)
        ]
        logging.info(
            "Collected links from OSV",
            extra={
                "cve_id": cve_id,
                "ecosystem": ecosystem,
                "links": links_osv
            },
        )

        links_security_debian = [
            {"url": url, "source": "Debian"} for url in self.tracker.extract_note_urls()
        ]
        logging.info(
            "Collected links from Security Debian website",
            extra={
                "cve_id": cve_id,
                "ecosystem": ecosystem,
                "links": links_security_debian
            },
        )

        links_websearch = [
            {"url": url, "source": "WebSearch"}
            for url in self.tool.extract_websearch_links_for_cve(cve_id)
        ]
        logging.info(
            "Collected links from WebSearch",
            extra={
                "cve_id": cve_id,
                "ecosystem": ecosystem,
                "links": links_websearch
            },
        )

        links = [*links_nvd, *links_osv, *links_security_debian, *links_websearch]

        # Deduplicate by URL while keeping the first source
        seen: set = set()
        unique_links: list = list()
        for link in links:
            if link["url"] not in seen:
                seen.add(link["url"])
                unique_links.append(link)

        return unique_links