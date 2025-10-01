<!--
SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.

SPDX-License-Identifier: Apache-2.0
-->

# Root Cause Service (RCS)
RCS, or Root Cause Service is a dedicated tool that identifies the root cause of a CVE for any package across different ecosystems like pypi.org, npmjs.com, crates.io, maven.org, golang.org etc.


## Getting Started
1. To get started, follow the following instructions:
    ```bash
    git clone git@github.com:OpenRefactory-Inc/rcs-transition.git
    cd rcs-transition
    ```

2. Create a Python virtual environment and install dependencies:
    ```bash
    python3 -m virtualenv env
    source env/bin/activate
    pip install -r requirements.txt
    ```

3. Create a `.env` file containing the following info:
    ```bash
    GITHUB_TOKEN=<GitHub Personal Access Token(PAT)>
    NVD_API_KEY=<NVD API Kee>
    GOOGLE_API_KEY=<Google Gemini API Key>
    OPEN_ROUTER_API_KEY=<Open Router API Key>
    ```

4. Create an input file in json format named `<intput-filename>` .e.g `input.json` with the following format(example):
    ```json
    {
        "purl": "pkg:maven/org.xerial.snappy/snappy-java@1.1.8.4",
        "repo": "https://github.com/xerial/snappy-java",
        "cve": "CVE-2023-34455"
    }
    ```

5. Then run the script as below:
    ```bash
    python3 main.py --input input.json --output output.json
    ```
    The script will create a file `<output-filename>` .e.g `output.json` where the output will be written.