# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import time

from agents import (
    SourcewareAnalyser
)
from loggers import (
    get_logger
)

logging = get_logger(__name__)

class SourcewareProcessor:
    """
    Encapsulates the logic of processing sourceware related features in a class.
    """
    def __init__(self):
        self.processor = SourcewareAnalyser()

    def process(self, url: str, cve_id: str, source: str | None = None) -> None:
        """
        Processes a Sourceware commit URL for root cause analysis.

        Parameters
        ----------
        url: str
            The commit URL to analyze
        cve_id: str
            The CVE ID to associate with this analysis
        source: str | None
            source identifier

        Returns
        -------
        None
            This method does not return anything
        """        
        start = time.time()

        if not url:
            raise Exception("No URL provided")

        try:
            self.processor.analyze_commit_for_cve(url, cve_id, source=source)
        except Exception as e:
            logging.exception(
                f"Error analyzing commit",
                exc_info=True,
                stack_info=True,
                extra={
                    "cve_id": cve_id,
                    "source": source,
                    "url": url,
                }
            )
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