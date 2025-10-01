# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import re

from datetime import (
    datetime
)
from managers import (
    NvdApiLinkManager
)

class VEXBuilder:
    """
    Parser for NVD and output it in a structured way. Responsible for structurally generating the 
    output.json with RC and VEX object
    """
    def __init__(self, cve_id: str, pkg: str, output_content: list):
        self.api = NvdApiLinkManager()
        self.cve_id = cve_id
        self.pkg = pkg
        self.output_content = output_content
        self.cve_info = self.api.get_entire_info(cve_id)
        self.vuln = self.cve_info["vulnerabilities"][0]["cve"]

    @staticmethod
    def parse_date(ts: str) -> str:
        """
        Parse a date string into a datetime object.

        Parameters
        ----------
        ts : str
            Date string to parse

        Returns
        -------
        str
            Date parsed as a datetime object
        """
        return (
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f").isoformat(
                timespec="milliseconds"
            )
            + "Z"
        )

    def extract_description(self) -> str:
        """
        Extract the description of the vulnerability from the vulnerability object.

        Returns
        -------
        str
            Description of the vulnerability
        """
        for desc in self.vuln.get("descriptions", []):
            if desc["lang"] == "en":
                return desc["value"]
        return ""

    def extract_cvss(self) -> tuple:
        """
        Extract the CVSS score from the vulnerability object.

        Returns
        -------
        tuple
            Necessary CVSS score
        """
        vector = method = score = severity = ""
        metrics = self.vuln.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            vector_string = cvss_data["vectorString"]
            method = vector_string.split("/")[0]
            vector = vector_string[len(method) + 1 :]
            score = str(cvss_data.get("baseScore", ""))
            severity = cvss_data.get("baseSeverity", "").lower()
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            vector_string = cvss_data["vectorString"]
            method = "CVSS:2.0"
            vector = vector_string
            score = str(cvss_data.get("baseScore", ""))
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "").lower()
        return score, severity, vector, method

    def extract_cwes(self) -> list:
        """
        Extract the CWE from the vulnerability object.

        Returns
        -------
        list
            A list of CWE objects
        """
        cwe_list = []
        for weakness in self.vuln.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc["lang"] == "en":
                    match = re.match(r"CWE-(\d+)", desc["value"])
                    if match:
                        cwe_list.append(int(match.group(1)))
        return cwe_list

    def extract_advisories(self) -> list:
        """
        Extract the advisories from the vulnerability object.

        Returns
        -------
        list
            A list of cwe
        """
        seen: set = set()
        advisories: list = []
        for ref in self.vuln.get("references", []):
            url = ref["url"]
            title = ref.get("tags", "Unknown")
            if url not in seen:
                advisories.append({"title": title, "url": url})
                seen.add(url)
        return advisories

    def build_json(self) -> dict:
        """
        Build a structured JSON object from the vulnerability object.

        Returns
        -------
        dict
            Structured JSON object
        """
        description = self.extract_description()
        score, severity, vector, method = self.extract_cvss()
        cwe_list = self.extract_cwes()
        advisories = self.extract_advisories()
        published = self.parse_date(self.vuln.get("published", ""))
        updated = self.parse_date(self.vuln.get("lastModified", ""))
        created = updated
        return {
            "cve": self.cve_id,
            "package": self.pkg,
            "root_cause_functions": self.output_content,
            "vex": {
                "sources": [
                    {
                        "source": {
                            "name": "NVD",
                            "url": f"https://nvd.nist.gov/vuln/detail/{self.cve_id}",
                        }
                    },
                    {
                        "source": {
                            "name": "OSV DEV",
                            "url": f"https://osv.dev/vulnerability/{self.cve_id}"
                        }
                    },
                     {
                        "source": {
                            "name": "Debian Security Tracker",
                            "url": f"https://security-tracker.debian.org/tracker/{self.cve_id}",
                     }
                    }
                ],
                "ratings": [
                    {
                        "source": {
                            "name": "NVD",
                            "url": f"https://nvd.nist.gov/vuln/detail/{self.cve_id}",
                        },
                        "score": score,
                        "severity": severity,
                        "vector": vector,
                        "method": method,
                    }
                ],
                "cwes": cwe_list,
                # Use the same value for both 'description' and 'detail' to maintain consistency
                # because NVD and Security Tracker use term 'description', while osv.dev uses the term 'detail' having same value.
                # Both fields are required for VEX schema.
                "description": description,
                "detail": description,
                "recommendation": "",
                "references": [
                {   # No unique ID field available from NVD; left as empty string
                    "id": "", 
                    "source": {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"
                    }
                },
                {   # No unique ID field available from OSV; left as empty string
                    "id": "", 
                    "source": {
                        "name": "OSV DEV",
                        "url": f"https://osv.dev/vulnerability/{self.cve_id}"
                    }
                },
                {
                        "source": {
                            "name": "Debian Security Tracker",
                            "url": f"https://security-tracker.debian.org/tracker/{self.cve_id}",
                     }
                }
                ],
                "advisories": advisories,
                "created": created,
                "published": published,
                "updated": updated,
                "credits": {"individuals": [{"name": ""}]},
            },
        }