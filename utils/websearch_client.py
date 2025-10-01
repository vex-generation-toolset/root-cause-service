# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import os
import re

from openai import (
    OpenAI
)

class OpenAISearchClient:
    """
    Client to interact with OpenAI Web Search API (via OpenRouter)
    to extract commit URLs related to a CVE.
    """

    def __init__(self):
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPEN_ROUTER_API_KEY"),
        )

    def extract_websearch_links_for_cve(self, cve_id: str) -> list[str]:
        """
        Uses OpenAI's GPT-4o search-preview model to extract commit URLs for the given CVE.
        Returns a list of commit URLs extracted from the model response.

        Parameters
        ----------
        cve_id: str
            The CVE to extract URLs for.

        Returns
        -------
        list
            A list of commit URLs extracted from the model response.
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a meticulous vulnerability analyst. "
                    "When the user asks about a CVE you must:\n"
                    "1. Search sources (upstream commit diffs, PRs, tags, security advisories,fix,patch).\n"
                    "2. Never invent information. If nothing is found, reply strictly: NO_PRIMARY_SOURCE_FOUND.\n"
                    "3. If you do find a relevant commit or patch, extract:\n"
                    "   • commit_url  - the canonical URL of the fix,patch or diff\n"
                    "   • file_path   - path to the file that contains the vulnerable code\n"
                    "   • method_name - name of the function or method affected\n"
                    "4. Ignore anything inside *test* folders or methods with names that contain 'Test'.\n"
                    "5. Output exactly one markdown bullet per finding, formatted:\n"
                    "   - <commit_url> | <file_path> | <method_name> |<some info related to that url>|(Mention the source from where url is obtained)\n"
                    "Mention the source from where you get this information too."
                    "6. Cite the identical URL you list as the source, e.g. (source).\n"
                    "Do not add summaries, explanations, or extra text."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Locate the root-cause commit(s) for**{cve_id}**\n"
                    "Return only the bullet list described above—no other prose."
                ),
            },
        ]

        ai_response = self.client.chat.completions.create(
            model="openai/gpt-4o-search-preview",
            messages=messages,
            temperature=0.0,
            top_p=0.0,
            max_tokens=4000,
        )

        response_content: str = ai_response.choices[0].message.content.strip()
        commit_urls: list = re.findall(r"-\s+(https?://[^\s|]+)", response_content)

        return commit_urls