# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import os

from loggers import (
    get_logger,
)
from openai import (
    OpenAI
)
from managers import (
    NvdApiLinkManager
)
from typing import (
    Optional,
    List
)
from utils import (
    ConsensusStore
)

logging = get_logger(__name__)

class BaseAnalyser:
    """
    Base class for all CVE commit processors (GitHub, GitLab, Sourceware).
    Provides shared utilities for CVE analysis and Output management.
    """
    VALID_EXTENSIONS: tuple = (
        ".java", ".go", ".py", ".c", ".cpp", ".cs", ".js", ".ts", ".php", ".rb", 
        ".groovy", ".rs", ".in", ".jelly", ".inc", ".rh", ".bat"
    )

    def __init__(self) -> None:
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPEN_ROUTER_API_KEY")
        )
        self.api: NvdApiLinkManager = NvdApiLinkManager()
        self._description_cache: dict = {}

    def analyze_commit_for_cve(self, url: str, cve_id: str, source: Optional[str] = None) -> Optional[List[dict]]:
        """
         Base implementation — should be overridden by subclasses.

         Parameters
         ----------
         url : str
            GitHub commit URL to analyze
         cve_id : str
            CVE to analyze
         source : Optional[str]
            Source url

        Returns
        -------
        Optional[List[dict]]
            List of dictionaries describing CVE details

        """
        logging.warning("analyze_commit_for_cve not implemented in BaseProcessor.")
        return None

    @staticmethod
    def get_reference_url(cve_id: str, url: str, source: Optional[str]) -> str:
        """
        Generate the reference URL from the given CVE ID.

        Parameters
        ----------
        cve_id : str
            CVE to analyze
        url : str
            GitHub commit URL to analyze
        source : Optional[str]
            Source url

        Returns
        -------
        str
            This function returns the reference URL from the given CVE ID.
        """
        if source == "NVD":
            return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        elif source == "OSV":
            return f"https://osv.dev/list?q={cve_id}&ecosystem="
        elif source == "Debian":
            return f"https://security-tracker.debian.org/tracker/{cve_id}"
        elif source in {"sourceware", "gitlab"}:
            return url.split(";")[0]
        elif source == "Manual Input":
            parts = url.split("/")
            return "/".join(parts[:5]) if "github.com" in url and len(parts) >= 5 else url
        return url

    @staticmethod
    def write_to_output(url: str, results: List[dict], path: Optional[str]) -> None:
        """
        Write results to output file.

        Parameters
        ----------
        url : str
            GitHub commit URL to analyze
        results : List[dict]
            List of dictionaries describing CVE details
        path : Optional[str]
            Output file path

        Returns
        -------
        None
            This function writes results to output file. Returns nothing.
        """
        if not results or not path:
            return
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\nRoot cause exists in the commit URL: {url}\n")
            json.dump(results, f, indent=2)
        logging.info(f"Results written to {path}")

    def is_valid_source_file(self, filename: str) -> bool:
        """
        Filters out test files and non-code files.
        Only Considers Valid Extensions.

        Parameters
        ----------
        filename : str
            Filename to test

        Returns
        -------
        bool
            Whether the given filename is valid
        """
        return (
            filename.endswith(self.VALID_EXTENSIONS)
            and "test" not in filename.lower()
        )

    def get_cve_description(self, cve_id: str) -> str:
        """
        Fetches and caches the CVE description from NVD.

        Parameters
        ----------
        cve_id : str
            CVE to analyze

        Returns
        -------
        str
            Description of the CVE found
        """
        if cve_id in self._description_cache:
            return self._description_cache[cve_id]

        description = self.api.get_cve_info(cve_id)
        if not description:
            logging.warning(f"No description found for {cve_id}")
            description = f"No description available for {cve_id}"
        self._description_cache[cve_id] = description
        return description

    def log_consensus_entry(
            self,
            filename: str,
            commit_url: str,
            consensus_json: dict,
            cve_id: str,
            source: Optional[str]
    ) -> None:
        """
        Log consensus entry for CVE analysis.

        Parameters
        ----------
        filename : str
            Filename to test
        commit_url : str
            GitHub commit URL to analyze
        consensus_json : dict
            JSON consensus data
        cve_id : str
            CVE to analyze
        source : Optional[str]
            Source url

        Returns
        -------
        None
            This function logs consensus entry for CVE analysis
        """
        reference_url: str = self.get_reference_url(cve_id, commit_url, source)
        consensus_entry: tuple = (
            f"\nRoot cause exists in the commit URL: {commit_url}\n"
            f"Source: {source}\n"
            f"Reference URL: {reference_url}\n"
            + json.dumps([consensus_json], indent=2)
        )
        try:
            ConsensusStore.add(consensus_entry)
            logging.info(f"Consensus added for file: {filename}")
        except Exception as e:
            logging.error(f"Failed to store consensus entry for {filename}: {e}")