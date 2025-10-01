# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import requests

from agents import (
    BaseAnalyser
)
from bs4 import (
    BeautifulSoup as LinkExtractor
)
from concurrent.futures import (
    ThreadPoolExecutor
)
from loggers import (
    get_logger
)
from parser import (
    extract_clean_json
)
from urllib.parse import (
    urljoin,
    urlparse
)

logging = get_logger(__name__)

class SourcewareAnalyser(BaseAnalyser):
    """
    Handles Sourceware commit diff page scraping and CVE root cause analysis.
    """
    def __init__(self):
        super().__init__()

    @staticmethod
    def extract_commit_hash(url: str) -> str | None:
        if url.startswith("http"):
            parsed = urlparse(url)
            parts = parsed.query.split(";")
            for part in parts:
                if part.startswith("h="):
                    return part.split("=", 1)[1]
        return None

    @staticmethod
    def extract_all_file_links(commit_hash: str) -> list[dict]:
        base_url = "https://sourceware.org/git/"
        commit_url = f"{base_url}gitweb.cgi?p=glibc.git;a=commitdiff;h={commit_hash}"

        try:
            response = requests.get(commit_url)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"Failed to fetch commit page: {e}")
            return []

        soup = LinkExtractor(response.text, "html.parser")
        diff_table = soup.find("table", class_="diff_tree")

        if not diff_table:
            logging.warning("Could not find <table class='diff_tree'>")
            return []

        results = []
        for row in diff_table.find_all("tr"):
            columns = row.find_all("td")
            if len(columns) != 3:
                continue

            filename_tag = columns[0].find("a")
            link_tags = columns[2].find_all("a")

            if not filename_tag or len(link_tags) < 3:
                continue

            filename = filename_tag.text.strip()
            results.append({
                "filename": filename,
                "diff": urljoin(base_url, link_tags[0]["href"]),
            })

        return results

    @staticmethod
    def extract_structured_diff_blocks(raw_patch_text: str) -> list[dict]:
        blocks = []
        current_file = None
        current_diff = []

        lines = raw_patch_text.splitlines()
        for line in lines:
            if line.lstrip().startswith("diff --git"):
                if current_file and current_diff:
                    blocks.append({
                        "filename": current_file,
                        "diff": "\n".join(current_diff),
                    })
                    current_diff = []

                parts = line.strip().split(" b/")
                current_file = parts[1].strip() if len(parts) > 1 else "unknown"
                current_diff = [line]
            elif current_file:
                current_diff.append(line)

        if current_file and current_diff:
            blocks.append({
                "filename": current_file,
                "diff": "\n".join(current_diff),
            })

        return blocks

    def process_diff_page(
            self,
            diff_url: str,
            cve_id: str,
            description: str,
            source: str = "Sourceware"
    ) -> list[dict]:
        try:
            response = requests.get(diff_url)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"Failed to fetch diff page {diff_url}: {e}")
            return []

        soup = LinkExtractor(response.text, "html.parser")
        body = soup.find("div", class_="page_body")
        if not body:
            logging.warning("No <div class='page_body'> found in diff page.")
            return []

        raw_text = body.get_text()
        blocks = self.extract_structured_diff_blocks(raw_text)
        if not blocks:
            logging.warning("No structured diff blocks found.")
            return []

        results = []
        for block in blocks:
            filename = block["filename"]
            diff = block["diff"]

            if not self.is_valid_source_file(filename):
                logging.info(f"Skipping {filename} — not valid or a test file.")
                continue

            formatted_code = (
                f"Sourceware Diff URL: {diff_url}\n\n"
                f"**File:** `{filename}`\n"
                f"```diff\n{diff}\n```"
            )

            _analyze_patch_with_models = importlib.import_module('utils').analyze_patch_with_models
            outputs = _analyze_patch_with_models(self.client, description, filename, formatted_code)

            _generate_consensus = importlib.import_module('utils').generate_consensus
            consensus_result = _generate_consensus(self.client, outputs, filename)

            logging.info(f"Consensus generated for file: {filename}")
            try:
                clean = extract_clean_json(consensus_result)
                consensus_json = json.loads(clean)

                if (
                    "root_cause_functions" in consensus_json
                    and isinstance(consensus_json["root_cause_functions"], list)
                    and len(consensus_json["root_cause_functions"]) > 0
                ):
                    self.log_consensus_entry(
                        filename, diff_url, consensus_json, cve_id, source
                    )
                    results.append(consensus_json)

            except Exception as e:
                logging.error(f"Error processing diff block for {filename}: {e}")

        return results

    def analyze_commit_for_cve(
            self,
            url: str,
            cve_id: str,
            source: str = "Sourceware"
    ) -> list[dict]:
        commit_hash = self.extract_commit_hash(url)
        if not commit_hash:
            logging.error("Invalid Sourceware commit URL.")
            return []

        file_links = self.extract_all_file_links(commit_hash)
        if not file_links:
            logging.warning("No file links found for commit.")
            return []

        description = self.get_cve_description(cve_id)
        final_results = []

        patch_link = next(
            (entry["diff"] for entry in file_links if "patch" in entry["diff"]),
            None,
        )
        if patch_link:
            logging.info(f"'patch' link detected. Scraping only this one:\n{patch_link}")
            result = self.process_diff_page(patch_link, cve_id, description, source)
            if result:
                final_results.extend(result)
        else:
            with ThreadPoolExecutor(max_workers=min(15, len(file_links))) as executor:
                futures = [
                    executor.submit(
                        self.process_diff_page, entry["diff"], cve_id, description, source
                    )
                    for entry in file_links
                ]
                for future in futures:
                    result = future.result()
                    if result:
                        final_results.extend(result)

        self.write_to_output(url, final_results)
        logging.info(
            f"\nFinal results for Sourceware commit {url}: "
            f"{len(final_results)} file(s) with root cause found."
        )
        return final_results