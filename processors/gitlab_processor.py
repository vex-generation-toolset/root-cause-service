# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import time

from agents import (
    GitlabAnalyzer
)
from loggers import (
    get_logger
)

logging = get_logger(__name__)

class GitLabProcessor:
    """
    Processes GitLab commit URLs to identify root cause functions for a CVE.
    """
    def __init__(self):
        self.processor = GitlabAnalyzer()

    def process(self, url: str, cve_id: str, source=None) -> None:
        """
        Analyze a GitLab commit URL to determine root cause functions for the given CVE.

        Parameters
        ----------
            url: str
                GitLab commit URL
            cve_id: str
                CVE identifier
            source: str
                Source label

        Returns
        -------
        None
            This method does not return anything.
        """        
        start = time.time()

        if not url:
            raise Exception("No URL provided")
        try:
            self.processor.analyze_commit_for_cve(url, cve_id, source=source)
        except Exception as e:
            return

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