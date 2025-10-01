# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import argparse

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Process one CVE and extract root-cause info"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to input JSON file")
    parser.add_argument(
        "--output", "-o", required=True, help="Path to output JSON file"
    )

    return parser.parse_args()