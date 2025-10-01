# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
import time
import requests

from agents import (
    GitHubAnalyzer
)
from loggers import (
    get_logger
)

logging = get_logger(__name__)

class PullProcessor:
    """
    Processes GitHub pull request URLs to extract and analyze relevant commits.
    Uses GitHub API to identify first and last commits in a PR and analyzes them.
    """

    def __init__(self):
        self.processor = GitHubAnalyzer()
        self.token = os.getenv("GITHUB_TOKEN", "")

    @staticmethod
    def _extract_pr_info(url: str) -> tuple:
        """
        Extracts (owner, repo, pull_number) from a PR URL

        Parameters
        ----------
        url: str
            URL to pull request

        Returns
        -------
        tuple
            Necessary information
        """
        parts = url.strip("/").split("/")
        if len(parts) < 7 or parts[5] != "pull":
            raise ValueError("Invalid GitHub pull request URL.")
        return parts[3], parts[4], parts[6]

    def process(self, url: str, cve_id: str, source: str | None = None):
        """
        Process a GitHub pull request URL to analyze the first and last commit.

        Parameters
        ----------
        url: str
            GitHub pull request URL
        cve_id: str
            CVE identifier
        source: str | None
            Origin label for tracking

        Returns
        -------
        None
            This method does not return anything
        """
        try:
            owner, repo, pull_number = self._extract_pr_info(url)

            api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/commits"
            headers = {
                "Accept": "application/vnd.github.v3+json",
            }
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()
            commits = response.json()

            if not commits:
                return

            first_sha = commits[0]["sha"]
            last_sha = commits[-1]["sha"]

            base_url = f"https://github.com/{owner}/{repo}/commit"
            first_commit_url = f"{base_url}/{first_sha}"
            last_commit_url = f"{base_url}/{last_sha}"

            for commit_url in {first_commit_url, last_commit_url}:
                start = time.time()
                self.processor.analyze_commit_for_cve(commit_url, cve_id, source=source)
                end = time.time()
                logging.info(
                    "Time profiling for root cause analysis",
                    extra={
                        "cve_id": cve_id,
                        "source": source,
                        "_filename": __file__,
                        "url": url,
                        "second": f"{end - start:.2f}s"
                    },
                )

        except Exception as e:
            logging.exception(
                "Skipping",
                stack_info=True,
                exc_info=True,
            )