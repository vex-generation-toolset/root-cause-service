# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import sys

from pythonjsonlogger import (
    json
)

def get_logger(filename: str) -> logging.Logger:
    """
    Create and return a structured JSON logger.

    Parameters
    ----------
    filename: str
        Name of the log file to write logs to.

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    _logger = logging.getLogger(filename)
    _logger.setLevel(logging.INFO)

    if not _logger.handlers:
        # File handler
        # file_handler = logging.FileHandler(filename)
        stream_handler = logging.StreamHandler(sys.stdout)

        # JSON formatter
        log_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
        formatter = json.JsonFormatter(log_format)

        # file_handler.setFormatter(formatter)
        # _logger.addHandler(file_handler)

        stream_handler.setFormatter(formatter)
        _logger.addHandler(stream_handler)

    return _logger