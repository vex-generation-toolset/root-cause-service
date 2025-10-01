# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import argparse

from dotenv import (
    load_dotenv
)
from helper import (
    extract_and_build_output,
    load_single_entry,
    run_main_processor,
    validate_and_extract_fields,
    write_output,
)
from loggers import (
    get_logger
)
from utils import (
    parse_arguments
)

load_dotenv()
logging = get_logger(__name__)

def run() -> None:
    """Main entry point for the script."""

    args: argparse.Namespace = parse_arguments()

    input_file: str = args.input
    output_file: str = args.output

    # Step 1: Load and validate input
    pkg_entry: str = load_single_entry(input_file)
    purl, repo_url, cve_id, ecosystem = validate_and_extract_fields(pkg_entry)

    logging.info(
        "Processing root cause",
             extra={
                 'cve_id': cve_id,
                 'package_name': purl,
                 'repo_url': repo_url,
                 'ecosystem': ecosystem
             }
        )

    # Step 2: Clear output file
    open(output_file, "w", encoding="utf-8").close()

    # Step 3: Run processor
    try:
        run_main_processor(cve_id, repo_url, ecosystem)
    except Exception as e:
        logging.exception(f"MainProcessor failed", stack_info=True, exc_info=True, extra={
            'cve_id': cve_id,
            'package_name': purl,
            'repo_url': repo_url,
        })

    # Step 4: Extract and write output
    result: dict = extract_and_build_output(cve_id, purl, repo_url)
    write_output(output_file, result)

if __name__ == "__main__":
    run()