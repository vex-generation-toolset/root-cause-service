# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import re

from parser import (
    extract_root_cause_functions_from_string,
    VEXBuilder,
)
from helpers import (
    MainProcessor
)
from loggers import (
    get_logger
)
from utils import (
    ConsensusStore
)

logging = get_logger(__name__)

def load_single_entry(path: str) -> dict | None:
    """Load and parse a single-entry JSON file with validation."""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            raw_text = f.read()
    except Exception as e:
        logging.exception(
            "Failed to read",
            stack_info=True,
            exc_info=True,
            extra={
                "file_path": path,
            }
        )
        return None

    raw_text = re.sub(r",\s*([]}])", r"\1", raw_text)

    data: dict | None = None
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        logging.exception(
            f"Failed to parse JSON",
            stack_info=True,
            exc_info=True,
            extra={
                "file_path": path,
                "line_number": e.lineno,
                "colno": e.colno,
                "msg": e.msg,
            }
        )
        return None
        
    return data


def validate_and_extract_fields(pkg_entry: dict) -> tuple:
    """Extract required fields from JSON and validate them."""
    purl: str | None = pkg_entry.get("purl", None)
    repo_url: str | None  = pkg_entry.get("repo", None)
    cve_id: str | None = pkg_entry.get("cve", None)

    if not (purl and repo_url and cve_id):
        logging.error(
            "Missing required fields in input JSON",
            extra={
                "purl": pkg_entry,
            }
        )

    ecosystem: str | None = extract_ecosystem(purl)

    return purl, repo_url, cve_id, ecosystem


def extract_ecosystem(pkg_name: str) -> str | None:
    """Extract ecosystem from package name format."""
    try:
        return pkg_name.split(":", 1)[1].split("/", 1)[0]
    except IndexError:
        logging.exception(
            "Invalid package format",
            stack_info=True,
            exc_info=True,
            extra={
                "package_name": pkg_name,
            }
        )

def run_main_processor(cve_id: str, repo_url: str, ecosystem: str | None) -> None:
    """Execute helpers processing pipeline."""
    processor = MainProcessor()
    processor.run(cve_id, repo_url, ecosystem)


def extract_and_build_output(cve_id: str, pkg_name: str, repo_url: str) -> dict:
    """Parse consensus result and construct VEX output JSON."""
    consensus_string = "\n".join(ConsensusStore.get_all())

    output_content: dict | None = None
    try:
        analysis = extract_root_cause_functions_from_string(consensus_string, repo_url)
        output_content = json.loads(analysis)
    except Exception as e:
        logging.exception(
            f"Failed during analysis/parsing",
            exc_info=True,
            stack_info=True,
            extra={
                "cve_id": cve_id,
                "repo_url": repo_url,
                "package_name": pkg_name,
            })

    builder = VEXBuilder(cve_id, pkg_name, output_content)
    return builder.build_json()


def write_output(path, result):
    """Write result JSON to output file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logging.info(
        f"Output written successfully",
        extra={
            "path": path,
            "result": result
        }
    )