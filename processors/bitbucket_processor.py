# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

from agents import (
    GitHubAnalyzer
)
from loggers import (
    get_logger
)

logging = get_logger(__name__)

class BitbucketProcessor:
    """
    Processes Bitbucket-related URLs to extract and analyze commits.

    If a direct commit URL is provided, it is passed to the analyzer directly.
    Otherwise, the page content is parsed, and likely commit URLs are extracted
    using an LLM before further analysis.
    """
    def __init__(self):
        self.processor=GitHubAnalyzer()
        self.model_id="gpt-4o"

    def process(self, url: str, cve_id: str, source: str | None = None):
        """
        Process a Bitbucket URL to identify and analyze relevant commit URLs.

        Parameters
        ----------
        url: str
            The Bitbucket URL to analyze
        cve_id: str
            The CVE identifier
        source: str | None
            The origin of the URL (e.g., 'OSV', 'Manual Input')

        Returns
        -------
        None
            This method does not return anything.
        """     
        try:
            if "/commits/" in url:
                self.processor.analyze_commit_for_cve(url, cve_id, source=source)
            else:
                # need to implement what to do
                pass

        except Exception:
            logging.exception(
                "Error occurred",
                exc_info=True,
                stack_info=True,
            )