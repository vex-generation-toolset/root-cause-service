# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import re

def parse_chatgpt_json(ai_text: str) -> dict:
    """
    Extracts and parses the JSON object from the output of the agents markdown response.

    Parameters
    ----------
    ai_text: str
        The raw response content from agent.

    Returns
    -------
    dict
        Parsed JSON content as a Python dictionary.
    """
    pattern = r"```(?:json)?\s*(.*?)```"

    match = re.search(pattern, ai_text, re.DOTALL)
    json_str = match.group(1) if match else ai_text

    return json.loads(json_str)


def extract_clean_json(text: str) -> str | None:
    """
    Extracts and returns a clean JSON string from a mixed text.

    Parameters
    ----------
    text: str
        Input string containing JSON.

    Returns
    -------
    str | None
        Cleaned JSON string if valid, otherwise None.
    """
    try:
        match = re.search(r"(\{[\s\S]*}|\[[\s\S]*])", text)
        if match:
            json_str = match.group(1)
            json.loads(json_str)
            return json_str.strip()
    except:
        return None