# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os

from loggers import (
    get_logger
)
from processors import (
    CommitProcessor,
    PatchProcessor,
    PullProcessor,
    IssuesProcessor,
    BitbucketProcessor,
    GitLabProcessor,
    SourcewareProcessor
)
from utils import (
    LinkManager,
    URLClassifier
)

logging = get_logger(__name__)

class MainProcessor:
    """
    Directs URLs to their appropriate processor based on repository type or URL format.

    This class acts as the central coordinator that:
    - Loads environment variables and credentials.
    - Extracts and deduplicates URLs from multiple sources.
    - Classifies URLs by platform or type (e.g., GitHub, GitLab, Bitbucket, etc.).
    - Dispatches each URL to its corresponding processor for root cause analysis.

    Attributes:
        token (str): GitHub token loaded from environment variables.
        endpoint (str): Base endpoint for LLM API.
        model_name (str): The model name to be used with the LLM endpoint.
        link_manager (LinkManager): Manages extraction and combination of all relevant URLs.
        classifier (URLClassifier): Classifies URLs by type/platform.
    """

    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN")
        self.endpoint ="https://openrouter.ai/api/v1"
        self.model_name ="openai/chatgpt-4o-latest"

        with open("output.txt", "w", encoding="utf-8") as f:
            f.truncate(0)

        self.link_manager = LinkManager()
        self.classifier = URLClassifier()

    def run(self, cve_id: str, github_url: str, ecosystem: str | None = None) -> None:
        """
        Runs the helpers processor.

        Parameters
        ----------
        cve_id: str
            CVE's ID
        github_url: str
            GitHub URL
        ecosystem: str | None
            Ecosystem to use

        Returns
        -------
        None
            This method does not return anything
        """
        raw_links = self.link_manager.combine_and_extract_unique_links(
            cve_id, ecosystem
        )

        if github_url:
            raw_links.append({"url": github_url, "source": "Manual Input"})

        url_to_source = {entry["url"]: entry["source"] for entry in raw_links}
        urls = list(url_to_source.keys())

        logging.info(
            "All URLs with Source Tracking",
            extra={
                "urls": urls,
            }
        )

        buckets = self.classifier.classify(urls)

        # Bitbucket
        if buckets.get("bitbucket"):
            logging.info("Processing Bitbucket URLs")
            handler = BitbucketProcessor()
            for url in buckets["bitbucket"]:
                source = url_to_source.get(url, "Unknown")
                handler.process(
                    url,cve_id, source
                )

        # Sourceware
        if buckets.get("sourceware"):
            logging.info("Processing Sourceware URLs")
            handler = SourcewareProcessor()
            for url in buckets["sourceware"]:
                source = url_to_source.get(url, "sourceware")
                handler.process(
                    url,cve_id, source
                )

        # GitLab
        if buckets.get("gitlab"):
            logging.info("Processing GitLab URLs")
            handler = GitLabProcessor()
            for url in buckets["gitlab"]:
                source = url_to_source.get(url, "gitlab")
                handler.process(
                    url,cve_id, source
                )

        # Commit
        if buckets.get("commit"):
            logging.info("Processing commit URLs:")
            handler = CommitProcessor()
            for url in buckets["commit"]:
                source = url_to_source.get(url, "Unknown")
                handler.process(
                    url,cve_id, source
                )

        # Pull
        if buckets.get("pull"):
            logging.info("Processing pull URLs:")
            handler = PullProcessor()
            for url in buckets["pull"]:
                source = url_to_source.get(url, "Unknown")
                handler.process(
                    url,cve_id, source
                )

        # Issues
        if buckets.get("issues"):
            logging.info("Processing issues URLs:")
            handler = IssuesProcessor()
            for url in buckets["issues"]:
                source = url_to_source.get(url, "Unknown")
                handler.process(
                    url,cve_id, source
                )

        # Patch
        if buckets.get("patch"):
            logging.info("Processing Patch URLs:")
            handler = PatchProcessor()
            for url in buckets["patch"]:
                source = url_to_source.get(url, "Unknown")
                handler.process(
                    url,cve_id, source
                )