# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

class URLClassifier:
    """
   Classify a list of URLs into source types based on known patterns.

   Args:
    unique_links (list[str]): List of raw URLs.

   Returns:
    dict[str, list[str]]: Grouped URLs by category.
   """
    def __init__(self):
        self.commit_urls = []
        self.pull_urls = []
        self.issues_urls = []
        self.patch_urls = []
        self.bitbucket_urls = []
        self.github_urls = []
        self.gitlab_urls = []
        self.sourceware_urls = []
        self.other_urls = []

    def classify(self, unique_links: list[str]) -> dict[str, list[str]]:
        """
        Classify a list of URLs into source types based on known patterns.

        Parameters
        ----------
        unique_links: list[str]
            List of raw URLs.

        Returns
        -------
        dict[str, list[str]]
            Grouped URLs by category.
        """
        excludes = ["redhat", "netapp"]

        for url in unique_links:
            if "bitbucket" in url:
                self.bitbucket_urls.append(url)
            elif "sourceware.org" in url and ("commitdiff" in url or "blobdiff" in url or ";h=" in url):
                self.sourceware_urls.append(url)
            elif "gitlab.com" in url and "/-/commit" in url:
                self.gitlab_urls.append(url)
            elif "/commit" in url and all(item not in url for item in excludes):
                self.commit_urls.append(url)
            elif "/pull" in url and all(item not in url for item in excludes):
                self.pull_urls.append(url)
            elif "/issues" in url and all(item not in url for item in excludes):
                self.issues_urls.append(url)
            elif "/security/advisories" in url or "/tag" in url:
                self.patch_urls.append(url)
            elif "github" in url and not any(
                sub in url
                for sub in [
                    "/commit",
                    "/pull",
                    "/issues",
                    "/security/advisories",
                    "/tag",
                ]
            ):
                self.github_urls.append(url)
            else:
                self.other_urls.append(url)

        return {
            "bitbucket": self.bitbucket_urls,
            "sourceware": self.sourceware_urls,
            "gitlab": self.gitlab_urls,
            "commit": self.commit_urls,
            "pull": self.pull_urls,
            "issues": self.issues_urls,
            "patch": self.patch_urls,
            "github": self.github_urls,
            "other": self.other_urls,
        }