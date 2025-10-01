# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import importlib
import json
import os
import re
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

class GitlabAnalyzer(BaseAnalyser):
    """
    Handles GitLab commit processing and root cause analysis for CVEs.
    """

    def __init__(self):
        super().__init__()
        self.token = os.getenv("GITLAB_TOKEN")

    @staticmethod
    def extract_gitlab_api_url(commit_url: str) -> tuple | None:
        """
        Extracts the GitLab commit API URL components.
        e.g., https://gitlab.com/group/project/-/commit/<hash>

        Parameters
        ----------
        commit_url: str
            GitLab commit URL.

        Returns
        -------
        tuple | None
            Extracts the GitLab commit API URL components.
        """
        match = re.match(r"https://gitlab\.com/(.+?)/-/commit/([a-fA-F0-9]+)", commit_url)
        if not match:
            logging.error(f"Invalid GitLab commit URL: {commit_url}")
            return None

        project_path, commit_sha = match.groups()
        encoded_project_path = project_path.replace("/", "%2F")
        api_url = (
            f"https://gitlab.com/api/v4/projects/"
            f"{encoded_project_path}/repository/commits/{commit_sha}/diff"
        )
        return api_url, commit_sha, project_path

    def fetch_commit_diffs(self, api_url: str) -> list | None:
        """
        Fetches commit diffs from GitLab API.

        Parameters
        ----------
        api_url: str
            GitLab API URL.

        Returns
        -------
        list | None
            A list of commit diffs.
        """
        headers = {}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token

        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f"Failed to fetch GitLab commit data: {e}")
            return None

    def process_file(
            self,
            diff: dict,
            commit_url: str,
            description: str,
            cve_id: str,
            source: str = "GitLab"
    ) -> dict | None:
        """

        """
        filename = diff.get("new_path", "")
        if not self.is_valid_source_file(filename):
            logging.info(f"Skipping invalid or test file: {filename}")
            return None

        patch = diff.get("diff", "")
        if not patch:
            logging.info(f"No patch found for file: {filename}")
            return None

        formatted_code = (
            f"Commit: {commit_url}\n\n"
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
            commit_url: str,
            cve_id: str,
            source: str = "GitLab"
    ) -> list:
        result = self.extract_gitlab_api_url(commit_url)
        if not result:
            return []

        api_url, commit_sha, project_path = result
        diffs = self.fetch_commit_diffs(api_url)
        if not diffs:
            logging.warning(f"No diffs returned for commit: {commit_url}")
            return []

        description = self.get_cve_description(cve_id)
        final_results = []

        with ThreadPoolExecutor(max_workers=min(15, len(diffs))) as executor:
            futures = [
                executor.submit(
                    self.process_file, diff, commit_url, description, cve_id, source
                )
                for diff in diffs
            ]
            for future in futures:
                result = future.result()
                if result:
                    final_results.append(result)

        self.write_to_output(commit_url, final_results, "output.txt")
        logging.info(
            f"\nFinal results for GitLab commit {commit_url}: "
            f"{len(final_results)} file(s) with root cause found."
        )
        return final_results