# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import time

from agents import (
    GitHubAnalyzer
)
from loggers import (
    get_logger
)

logging = get_logger(__name__)

class CommitProcessor:
    """
    Processes commit-related GitHub URLs to identify root cause functions.

    This class encapsulates the logic originally handled by process_commit_urls.
    It invokes GitHubAnalyzer to analyze the commit URL for a given CVE ID.
    """
    def __init__(self):
        self.processor=GitHubAnalyzer()

    def process(self, url: str, cve_id: str, source: str | None = None) -> None:
        """
        Run root cause analysis on a GitHub commit URL.

        Parameters
        ----------
        url: str
            The commit URL to analyze
        cve_id: str
            The CVE identifier
        source: str | None
            Source of the URL (e.g., "GitHub", "Manual Input")

        Returns
        -------
        None
            This method does not return anything.
        """
        if not url:
            raise Exception("No URL provided")

        start = time.time()
        self.processor.analyze_commit_for_cve(url, cve_id, source=source)
        end = time.time()

        logging.info(
            "Time profiling for root cause analysis",
            extra={
                "cve_id": cve_id,
                "source": source,
                "_filename": __file__,
                "url": url,
                "second": f"{end - start:.2f}s"
            }
        )