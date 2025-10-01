# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import importlib
import json
import os
import requests

from agents import (
    BaseAnalyser
)
from concurrent.futures import (
    ThreadPoolExecutor
)
from loggers import (
    get_logger
)
from parser import (
    extract_clean_json
)

logging = get_logger(__name__)

class GitHubAnalyzer(BaseAnalyser):
    """
    Handles GitHub commit processing and root cause analysis for CVEs.
    """
    def __init__(self):
        super().__init__()
        self.token = os.getenv("GITHUB_TOKEN")

    @staticmethod
    def convert_to_github_api(url: str) -> str | None:
        """
        Converts a GitHub commit URL to a GitHub API URL.

        Parameters
        ----------
        url : str
            GitHub commit URL

        Returns
        -------
        str | None
            GitHub API URL
        """
        try:
            parts = url.split("/")
            owner, repo, commit_hash = parts[3], parts[4], parts[-1]
            return f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"
        except (IndexError, ValueError):
            logging.warning(f"Invalid GitHub URL format: {url}")
            return None

    def fetch_commit_data(self, api_url: str) -> dict | None:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.token}",
        }
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"Failed to fetch GitHub commit data: {e}")
            return None

    @staticmethod
    def extract_commit_metadata(commit_data: dict) -> tuple:
        """
        Extract commit metadata from GitHub commit data

        Parameters
        ----------
        commit_data : dict
            GitHub commit data

        Returns
        -------
        tuple
            Commit metadata
        """
        try:
            commit = commit_data["commit"]
            return commit["message"], commit["author"]["name"], commit["author"]["date"]
        except KeyError:
            logging.warning("Failed to extract commit metadata.")
            return "Unknown", "Unknown", "Unknown"

    def get_security_critical_files(self, commit_data: dict) -> list:
        """
        Get Security critical files from GitHub commit data

        Parameters
        ----------
        commit_data: dict
            GitHub commit data

        Returns
        -------
        list
            Security critical files
        """
        return [
            file for file in commit_data.get("files", [])
            if self.is_valid_source_file(file["filename"])
        ]

    def process_file(
            self,
            file: dict,
            commit_info: dict,
            description: str,
            commit_url: str,
            cve_id: str,
            source: str
    ) -> dict | None:
        """
        Parameters
        ----------
        file : dict
            GitHub commit data
        description : str
            GitHub commit description
        commit_info : dict
            GitHub commit information
        commit_url : str
            GitHub commit URL
        cve_id : str
            CVE ID
        source : str
            GitHub commit source

        Returns
        -------
        dict
            GitHub commit metadata
        """
        filename = file["filename"]
        patch = file.get("patch", "")
        if not patch:
            logging.info(f"Skipping {filename} — No patch available.")
            return None

        message = commit_info["message"]
        author = commit_info["author"]
        date = commit_info["date"]

        formatted_code = (
            f"Commit Message:\n{message}\n\n"
            f"Author: {author}\nDate: {date}\n\n"
            f"**File:** `{filename}`\n```diff\n{patch}\n```"
        )

        _analyze_patch_with_models = importlib.import_module('utils').analyze_patch_with_models
        outputs = _analyze_patch_with_models(self.client, description, filename, formatted_code)

        _generate_consensus = importlib.import_module('utils').generate_consensus
        consensus_result = _generate_consensus(self.client, outputs, filename)

        logging.info(f"Consensus generated for file: {filename}")
        try:
            clean = extract_clean_json(consensus_result)
            consensus_json = json.loads(clean)

            if (
                "root_cause_functions" in consensus_json
                and isinstance(consensus_json["root_cause_functions"], list)
                and len(consensus_json["root_cause_functions"]) > 0
            ):
                self.log_consensus_entry(
                    filename, commit_url, consensus_json, cve_id, source
                )
                return consensus_json

        except Exception as e:
            logging.error(f"Error processing {filename}: {e}")

        return None

    def analyze_commit_for_cve(
            self,
            url: str,
            cve_id: str,
            source: str = "GitHub"
    ) -> list:
        """
        Analyzes a commit for CVEs.

        Parameters
        ----------
        url : str
            GitHub commit URL
        cve_id : str
            CVE ID
        source : str
            GitHub commit source

        Returns
        -------
        list
            A list of CVEs
        """
        if not self.token:
            logging.error("GitHub token not found in environment.")
            return []

        api_url = self.convert_to_github_api(url)
        if not api_url:
            return []

        commit_data = self.fetch_commit_data(api_url)
        if not commit_data:
            return []

        message, author, date = self.extract_commit_metadata(commit_data)
        commit_info = {"message": message, "author": author, "date": date}

        files = self.get_security_critical_files(commit_data)
        if not files:
            logging.warning(f"No valid files to analyze in commit: {url}")
            return []

        description = self.get_cve_description(cve_id)

        final_results = []
        with ThreadPoolExecutor(max_workers=min(15, len(files))) as executor:
            futures = [
                executor.submit(
                    self.process_file, file, commit_info, description, url, cve_id, source
                )
                for file in files
            ]
            for future in futures:
                result = future.result()
                if result:
                    final_results.append(result)

        self.write_to_output(url, final_results, "output.txt")
        logging.info(
            f"\nFinal results for commit {url}: "
            f"{len(final_results)} file(s) with root cause found."
        )
        return final_results