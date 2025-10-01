# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
import re
import requests

from agents import (
    GitHubAnalyzer
)
from loggers import (
    get_logger
)

logging = get_logger(__name__)

class IssuesProcessor:
    """
    Processes GitHub issue URLs to extract referenced commit URLs.

    This class combines the logic of `process_issues_urls` and 
    `fallback_issue_page` to locate root-cause-related commits
    mentioned in GitHub issues or comments.
    """
    def __init__(self):
        self.processor=GitHubAnalyzer()

    def process(self, url: str, cve_id: str, source: str | None = None) -> None:
        """
        Process a GitHub issue URL to extract and analyze related commits for a given CVE.

        This method performs the following steps:
        1. Parses the owner, repository name, and issue number from the GitHub issue URL.
        2. Queries the GitHub Issues Events API to find commit references based on keywords such as
        "closed", "referenced", "pushed", "fixed", or "commit".
        3. If no commit URLs are found in events, queries the GitHub issue comments to look for
        commit URLs mentioned in the comment body.
        4. Each extracted commit URL is passed to the root cause analyzer for CVE analysis.
        5. If all above methods fail to extract commit URLs, it falls back to scraping the issue page.

        Parameters
        ---------
        url: str
            Full GitHub issue URL
        cve_id: str
            The CVE identifier
        source: str | None
            Label to indicate the source of the analysis

        Returns
        -------
        None
            This method does not return anything
        """
        keywords = ["closed", "referenced", "pushed", "fixed", "commit"]
        parts = url.split("/")
        try:
            owner = parts[3]
            repo = parts[4]
            issue_number = parts[6]
        except IndexError:
            logging.exception(
                "Skipping",
                stack_info=True,
                exc_info=True
            )
            return

        events_url = (
            f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/events"
        )
        comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
        token=os.getenv("GITHUB_TOKEN")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            response_events = requests.get(events_url, headers=headers)
            response_events.raise_for_status()
            events = response_events.json()
            commit_urls = set()
            for event in events:
                event_type = event.get("event")
                commit_url = event.get("commit_url")
                if event_type in keywords and commit_url:
                    if "api.github.com" in commit_url:
                        commit_url = commit_url.replace(
                            "api.github.com/repos", "github.com"
                        ).replace("/commits/", "/commit/")
                    commit_urls.add(commit_url)
        except Exception as e:
            logging.exception(
                "Error fetching events",
                exc_info=True,
                stack_info=True,
                extra={
                    "events_url": events_url,
                }
            )
            commit_urls = set()

        # If no commit URLs found in events, search in comments
        if not commit_urls:
            try:
                response_comments = requests.get(comments_url, headers=headers)
                response_comments.raise_for_status()
                comments = response_comments.json()
                for comment in comments:
                    body = comment.get("body", "")
                    for keyword in keywords:
                        match = re.search(
                            r"(https://github\.com/[^\s]+/commit/[0-9a-f]+)", body
                        )
                        if match:
                            commit_urls.add(match.group(1))
                            break
            except Exception as e:
                logging.exception(
                    "Error fetching comments",
                    exc_info=True,
                    stack_info=True,
                    extra={
                        "comments_url": comments_url,
                    }
                )

        commit_urls_list = list(commit_urls)

        if commit_urls_list:
            for commit_url in commit_urls_list:
                try:
                    self.processor.analyze_commit_for_cve(commit_url, cve_id, source=source)
                except Exception as e:
                    logging.exception(
                        "Error processing commit",
                        exc_info=True,
                        stack_info=True,
                        extra={
                            "commit_url": commit_url,
                            "cve_id": cve_id,
                        }
                    )

            failed_urls = set()
            for commit_url in commit_urls_list:
                try:
                    url_parts = commit_url.split("/")
                    repo_owner = url_parts[3]
                    repo_name = url_parts[4]
                    commit_sha = url_parts[-1]
                except IndexError:
                    logging.exception(
                        "Skipping",
                        stack_info=True,
                        exc_info=True
                    )
                    return

                api_commit_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{commit_sha}"
                try:
                    response_commit = requests.get(api_commit_url, headers=headers)
                    response_commit.raise_for_status()
                    commit_data = response_commit.json()

                    files = commit_data.get("files", [])
                    logging.info(
                        "Changed files",
                        extra={
                            "files": [file for file in files if "test" not in file["filename"]],
                        }
                    )
                except Exception as e:
                    logging.exception(
                        "Error fetching commit details",
                        exc_info=True,
                        stack_info=True,
                        extra={
                            "api_commit_url": api_commit_url,
                        }
                    )
                    failed_urls.add(commit_url)

            if failed_urls:
                logging.info("Skipping")
        else:
            logging.info("No commit found. Skipping")