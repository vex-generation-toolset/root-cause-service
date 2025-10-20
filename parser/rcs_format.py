# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import re

from loggers import (
    get_logger
)
from typing import (
    Dict,
    List
)
from urllib.parse import (
    urlparse
)

logging = get_logger(__name__)

def _owner_base(url: str) -> str:
    """
    Return 'scheme://netloc/owner' from a given URL in lowercase.

    Parameters
    ----------
    url: str
        A repository or commit URL.

    Returns
    -------
    str
        Normalized base URL or empty string if invalid.
    """
    if not url:
        return ""

    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return ""

    path = p.path.lstrip("/")
    owner = path.split("/", 1)[0] if path else ""

    return f"{p.scheme.lower()}://{p.netloc.lower()}/{owner}" if owner else ""


def _commit_matches_repo(commit_url: str, repo_url: str) -> bool:
    """
    Determine whether a commit URL matches the associated repository URL.

    Parameters
    ----------
    commit_url: str
        The commit URL.
    repo_url: str
        The repository URL.

    Returns
    -------
    bool
        True if URLs match or if host is allowed (e.g., GitLab, Sourceware).
    """
    if not repo_url:
        return True

    commit_host = urlparse(commit_url).netloc.lower()

    # Allow all for Sourceware and GitLab
    if any(host in commit_host for host in ["sourceware.org", "gitlab.com"]):
        return True

    return _owner_base(commit_url) == _owner_base(repo_url)


def extract_root_cause_functions_from_string(content: str, repo: str = "") -> str:
    """
    Extract root cause function blocks from formatted content and produce
    a structured JSON array for VEX integration.

    Parameters
    ----------
    content: str
        Raw text including root cause sections.
    repo: str
        Optional repository URL to filter matching commits.

    Returns
    -------
    str
        JSON string of root cause objects.
    """
    blocks: List[str] = re.split(r"Root cause exists in the commit URL:\s*", content)[1:]
    commits: Dict[str, Dict[str, object]] = {}

    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue

        commit_url = lines[0].strip()
        if not _commit_matches_repo(commit_url, repo):
            continue

        source_name = ""
        source_url = ""
        json_block_lines = []

        for line in lines[1:]:
            if line.startswith("Source:"):
                source_name = line.replace("Source:", "").strip()
            elif line.startswith("Reference URL:"):
                source_url = line.replace("Reference URL:", "").strip()
            else:
                json_block_lines.append(line)

        json_block = "\n".join(json_block_lines).strip()
        pkg = ver = ""
        methods: List[str] = []

        if json_block:
            try:
                parsed = json.loads(json_block)
                for entry in parsed:
                    for func in entry.get("root_cause_functions", []):
                        if canonical_names := func.get("canonical_name"):
                            methods.extend(canonical_names)
                        pkg = pkg or func.get("package", "")
                        ver = ver or func.get("version", "")
            except json.JSONDecodeError:
                logging.exception(
                    f"Skipped malformed JSON block",
                    exc_info=True,
                    stack_info=True
                )
                continue

        if not methods:
            continue

        info = commits.setdefault(
            commit_url,
            {
                "package": pkg,
                "version": ver,
                "methods": [],
                "source": {"name": source_name, "url": source_url},
            },
        )

        for m in methods:
            if m not in info["methods"]:
                info["methods"].append(m)

    # Format each commit entry as a JSON object string
    objects = [
        "\n".join([
            "  {",
            f'    "package": "{info["package"]}",',
            f'    "version": "{info["version"]}",',
            f'    "commit": "{commit_url}",',
            '    "source": {',
            f'      "name": "{info["source"]["name"]}",',
            f'      "url": "{info["source"]["url"]}"',
            "    },",
            f'    "methods": {json.dumps(info["methods"])}',
            "  }"
        ])
        for commit_url, info in commits.items()
    ]

    joined_objects = ",\n".join(objects)

    return f"[\n{joined_objects}\n]"