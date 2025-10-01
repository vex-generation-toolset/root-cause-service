# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
import re
import requests
import time

from agents import (
    GitHubAnalyzer
)
from google import (
    genai
)
from google.genai.types import (
    Tool,
    GoogleSearch,
    GenerateContentConfig
)
from loggers import (
    get_logger
)
from urllib.parse import (
    urlparse
)

logging = get_logger(__name__)

class PatchProcessor:
    """
    Processes GitHub patch-related URLs to trace associated root cause commits.
    Uses Google's Gemini API to infer release tag URLs, then extracts the associated
    GitHub commit SHA and analyzes it using the GitHubAnalyzer.
    """
    def __init__(self):
        self.processor=GitHubAnalyzer()
        self.model_id="gemini-2.0-flash-exp"

    def process(self, url,cve_id, source=None):
        """
        Process a patch-related GitHub URL to find and analyze the root cause commit.

        Parameters
        ----------
        url: str
            The CVE-specific GitHub patch or advisory URL.
        cve_id: str
            CVE identifier.
        source: str | None
            Origin label.

        Returns
        -------
        None
            This method does not return anything
        """        
        cve_part = url.split("/")[-1]
        genai_client = genai.Client()
        search_tool = Tool(google_search=GoogleSearch())
        config = GenerateContentConfig(
            system_instruction=(
                "You are a helpful assistant that provides up-to-date information "
                "to help the user in their research."
            ),
            tools=[search_tool],
            response_modalities=["TEXT"],
            temperature=0.0,
            candidate_count=1,
        )

        start_gemini = time.time()
        response = genai_client.models.generate_content(
            model=self.model_id,
            contents=(
                f"Find the patched version of {cve_part} from the GitHub associated "
                "website and generate URLs like this: https://github.com/<repo_name>/releases/tag/<version_tag>."
                "Provide only the URLs in JSON format."
            ),
            config=config,
        )
        end_gemini = time.time()
        logging.info(
            "Time profiling for gemini model",
            extra={
                "cve_id": cve_id,
                "source": source,
                "_filename": __file__,
                "url": url,
                "second": f"{end_gemini - start_gemini:.2f}s"
            },
        )

        response_content = response.text.strip()
        urls = list(set(re.findall(r"https?://[^\s\"']+", response_content)))

        if not urls:
            raise Exception("Skipping")
        
        all_urls = []

        for release_url in urls:
            try:
                parsed = urlparse(release_url)
                parts = parsed.path.strip("/").split("/")
                if "tag" not in parts:
                    continue
                tag_index = parts.index("tag")
                owner, repo = parts[0], parts[1]
                tag = parts[tag_index + 1]
                api_base = f"https://api.github.com/repos/{owner}/{repo}"

                ref_resp = requests.get(
                    f"{api_base}/git/ref/tags/{tag}",
                    headers={
                        "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN', '')}"
                    },
                    timeout=10,
                )
                ref_resp.raise_for_status()
                ref_data = ref_resp.json()
                obj_type = ref_data["object"]["type"]
                obj_sha = ref_data["object"]["sha"]

                if obj_type == "tag":
                    tag_obj = requests.get(
                        f"{api_base}/git/tags/{obj_sha}",
                        headers={
                            "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN', '')}"
                        },
                        timeout=10,
                    ).json()
                    commit_sha = tag_obj["object"]["sha"]
                elif obj_type == "commit":
                    commit_sha = obj_sha
                else:
                    continue

                commit_url = f"https://github.com/{owner}/{repo}/commit/{commit_sha}"

                all_urls.append(commit_url)
            except Exception:
                logging.exception(
                    "Skipping due to error",
                    stacklevel=True,
                    exc_info=True
                )

        all_urls = list(dict.fromkeys(all_urls))

        for commit_url in all_urls:
            start = time.time()
            self.processor.analyze_commit_for_cve(commit_url, cve_id, source=source)
            end = time.time()

            logging.info(
                "Time profiling for root cause analysis",
                extra={
                    "cve_id": cve_id,
                    "source": source,
                    "commit_url": commit_url,
                    "_filename": __file__,
                    "url": url,
                    "second": f"{end - start:.2f}s"
                },
            )