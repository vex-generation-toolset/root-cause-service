# ******************************************************************************************************* #
#                                                                                                         #
#  OPENREFACTORY CONFIDENTIAL                                                                             #
#  __________________                                                                                     #
#                                                                                                         #
#  Copyright (c) 2025 OpenRefactory, Inc. All Rights Reserved.                                            #
#                                                                                                         #
#  NOTICE: All information contained herein is, and remains the property of OpenRefactory, Inc. The       #
#  intellectual and technical concepts contained herein are proprietary to OpenRefactory, Inc. and        #
#  may be covered by U.S. and Foreign Patents, patents in process, and are protected by trade secret      #
#  or copyright law. Dissemination of this information or reproduction of this material is strictly       #
#  forbidden unless prior written permission is obtained from OpenRefactory, Inc.                         #
#                                                                                                         #
#  Author: Nur Hossain Raton (OpenRefactory, Inc.) - Initial Agent implementation                         #
#  Contributors: Al Arafat Tanin (OpenRefactory, Inc.)                                                    #
#                Syed Tehjeebuzzaman (OpenRefactory, Inc.)                                                #
# ******************************************************************************************************* #
import os
import json
import re
import requests
import threading

from .canonical_format_examples import (
    CANONICAL_FORMAT_EXAMPLES
)
from .consensus_store import (
    ConsensusStore
)
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed
)
from loggers import (
    get_logger
)

from openai import (
    OpenAI
)

logger = get_logger(__name__)

class CodeChangeAnalyzer:
    """Analyzes commit changes and categorizes them into Addition, Deletion, and Replacement changes.
    Filters out test files and non-code files from analysis."""

    def __init__(self):

        api_key = os.getenv("OPEN_ROUTER_API_KEY")
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )

        self.all_function_names = set()

        # Store all canonical format names
        self.all_canonical_names = set()

        # Map function names to their canonical formats
        self.function_to_canonical = {}

        self.code_extensions = {
            "javascript": [".js", ".jsx", ".mjs", ".cjs"],
            "typescript": [".ts", ".tsx"],
            "python": [".py", ".pyx", ".pyi"],
            "java": [".java"],
            "c": [".c", ".h"],
            "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh"],
            "csharp": [".cs"],
            "go": [".go"],
            "rust": [".rs"],
            "php": [".php"],
            "ruby": [".rb"],
        }

        self.analysis_log = {
            "ignored_files": [],
            "kept_files": [],
            "regions_by_type": {"Addition": [], "Deletion": [], "Replacement": []},
            "regions_to_functions": [],
            "rejected_regions": [],
            "root_cause_analysis": {},
            "cross_reference": {},
            "non_intersecting_functions": [],
        }

        self.canonical_format_examples = CANONICAL_FORMAT_EXAMPLES
        
        # Fix version mapping for structured processing
        self.fix_version_mapping = {}
        self.vulnerable_version_results = {}
        
        # Store LLM analysis results with full details (explanation, role, confidence, etc.)
        # Format: {commit_url: {(func_name, start_line, end_line): {...llm_analysis_data}}}
        self.function_llm_analysis = {}
        
        # Thread safety for parallel processing
        self._results_lock = threading.Lock()
        self._print_lock = threading.Lock()

        self.reset_analyzer_state()
    
    def reset_analyzer_state(self):
        """Reset analyzer state for processing a new package"""
        self.fix_version_mapping = {}
        self.vulnerable_version_results = {}
        self.all_function_names = set()
        self.all_canonical_names = set()
        self.function_to_canonical = {}

    @staticmethod
    def get_github_raw_url(commit_url: str, file_path: str) -> str:
        """
        Get the raw URL of the file from the commit URL
        """
        m = re.match(
        r"https://github\.com/([^/]+)/([^/]+)/(?:commit|pull/\d+/commits)/([a-f0-9]+)",
        commit_url
        )

        if not m:
            return None
        owner, repo, commit_sha = m.groups()

        return f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_sha}/{file_path}"
    
    def get_language_from_extension(self, file_path: str) -> str:
        """
        Determine the programming language from file extension.

        Parameters
        ----------
        file_path: str
            Path to the file

        Returns
        -------
            str: Language name or 'unknown' if not recognized
        """
        _, ext = os.path.splitext(file_path.lower())

        # Check against our code_extensions mapping
        for language, extensions in self.code_extensions.items():
            if ext in extensions:
                return language

        return "unknown"

    def get_line_numbers_then_canonical_name(
            self,
            commit_url: str,
            file_path: str,
            func_name: str,
    ) -> tuple[str, int, int]:
        raw_url = self.get_github_raw_url(commit_url, file_path)
        language = self.get_language_from_extension(file_path)
        logger.info(f"Getting line numbers for function '{func_name}' in file '{file_path}' (language: {language})")
        logger.info(f"Raw URL: {raw_url}")
        
        try:
            response = requests.get(raw_url)
            if response.status_code != 200:
                return []
            full_file_code=response.text
            full_file_code_numbered = "\n".join(
                f"{i+1:04d}: {line}" for i, line in enumerate(full_file_code.splitlines())
            )
        except:
            return []
        
        prompt = (
            f"""Full file code (with line numbers on the left):
            {full_file_code_numbered}

            Function name to locate:
            {func_name}
            """

            f"""
            You are a code analysis assistant.

            Task:
            Given a full source code file and a function name in {language} programming language, identify
            all the function(s) and their starting and ending line numbers of that name.

            Instructions:
            - try to identify how many functions with the given name are there in the file.
            - Then, return **only the function name(s) and the starting and ending line number(s) of the function(s) that match the name**.
            - ***Do not return any function that is not of the specified function name.***
            - return a list of JSON objects, each containing:
                - "function_name": Name of the function (already given)
                - "start_line": Starting line number of the function
                - "end_line": Ending line number of the function
            - If the code file has no function of the specified name then, return an empty list.
            """

            """
            
            ***IMPORTANT:
            -There maybe many function but you only need to consider the method(s) or function(s) which have the specified name.
            - Return the answer only as a JSON list, without any explanation, extra text, or formatting. Do not include markdown. Do not write anything outside the JSON list.
            """

            """
            **Answer in list of JSONs**:
            [
                {
                    "function_name": "<name of the function>",
                    "start_line": <starting line number>
                    "end_line": <ending line number>
                },
                ...
            ] 
        """
        )

        response = self.client.chat.completions.create(
        model="anthropic/claude-sonnet-4",  # or another LLM you prefer
        messages=[
                {"role": "system", "content": "You are a helpful code analysis assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,  # deterministic output
        )
        result_str = response.choices[0].message.content
        result=self.extract_json_list(result_str)

        # Extract commit SHA from URL
        commit_sha = commit_url.split('/')[-1] if '/' in commit_url else commit_url
        # with open(f"{commit_sha}.txt", "a") as f:
        #     f.write(f"LLM response filtered for {file_path}: {result}\n")
        if result:
            names=[]
            for item in result:
                names.append(self.get_canonical_format(commit_url, file_path, func_name, language, item.get("start_line", -1),item.get("end_line", -1)))
            return names
        else:
            logger.warning("no json found in llm response!")
            return []

    @staticmethod
    def extract_json_list(text: str) -> list:
        """
        Extracts all JSON objects from a given text and returns them as a list of dictionaries.
        
        Parameters
        ----------
        text: str
            The input text containing JSON objects.
            
        Returns
        -------
        list
            A list of parsed JSON dictionaries.
        """
        json_list = []

        # Regex to roughly match JSON objects
        # This will match {...} including nested braces
        #json_pattern = re.compile(r'\{(?:[^{}]|(?R))*\}', re.DOTALL)
        json_pattern = re.compile(r'\{.*?\}', re.DOTALL)

        # Find all JSON-like substrings
        matches = json_pattern.findall(text)
        
        for match in matches:
            try:
                parsed = json.loads(match)
                json_list.append(parsed)
            except:
                logger.exception(
                    "invalid json block",
                    extra={
                        "json_to_parse": match,
                        "_filename": __file__
                    },
                    exc_info=True,
                    stack_info=True
                )
                continue
    
        return json_list

    def get_function_column(self, code: str, func_name: str, line_number: int) -> int | None:
        """
        Given JS code, function name, and line number, returns the column number (1-based)
        where the function or arrow function starts.
        Supports both named and anonymous functions.
        For arrow functions, walks backward from '=>' and finds the matching '('.
        """
        lines = code.splitlines()
        if line_number < 1 or line_number > len(lines):
            return None

        line = lines[line_number - 1]

        # ---------- Anonymous Function Case ----------
        if func_name.lower() == "anonymous function":
            # Case 1: normal 'function' keyword
            func_match = re.search(r'\bfunction\b', line)
            if func_match:
                return func_match.start() + 1

            # Case 2: arrow function
            arrow_match = re.search(r'=>', line)
            if arrow_match:
                arrow_pos = arrow_match.start()

                # Walk backward to find the matching '('
                depth = 0
                for i in range(arrow_pos - 1, -1, -1):
                    ch = line[i]
                    if ch == ')':
                        depth += 1
                    elif ch == '(':
                        depth -= 1
                        if depth == 0:
                            # Found the matching '('
                            return i + 1  # 1-based index

                # If no '(' found, maybe single param (x => ...)
                single_param = re.search(r'\b[a-zA-Z_$][\w$]*\b(?=\s*=>)', line)
                if single_param:
                    return single_param.start() + 1

                # fallback: start of arrow
                return arrow_pos + 1

            return None

        # ---------- Named Function Case ----------
        patterns = [
            rf'\bfunction\s+{re.escape(func_name)}\b',           # function funcName(
            rf'\[?{re.escape(func_name)}\]?\s*\(',               # funcName(
            rf'\b{re.escape(func_name)}\s*=\s*function\b',       # funcName = function(
            rf'\b{re.escape(func_name)}\s*=\s*\(?.*?\)?\s*=>',   # funcName = (...) => {
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.start() + 1  # 1-based index

        return None

    def get_canonical_format(
        self,
        commit_url: str,
        file_path: str,
        function_name: str,
        language: str,
        line_number: int,
        end_line_number: int
    ) -> str:
        """
        Get the canonical format of the function name

        Parameters
        ----------
        commit_url: str
        file_path: str
        function_name: str
        language: str
        line_number: int
        end_line_number: int

        Returns
        -------
            str: Canonical format of the function name
        """       
        language = language.lower()

        module_context = ""
        actual_module_name = ""

        raw_url = self.get_github_raw_url(commit_url, file_path)
        response = requests.get(raw_url)
        if response.status_code != 200:
            return "UNKNOWN"
        file_content = response.text

        if language in ["javascript", "typescript"]:
            package_json_url = self.get_github_raw_url(commit_url, "package.json")
            try:
                pkg_response = requests.get(package_json_url)
                if pkg_response.status_code == 200:
                    pkg_data = json.loads(pkg_response.text)
                    actual_module_name = pkg_data.get("name", "")+"/"+file_path.rsplit('.', 1)[0]
                    if actual_module_name:
                        module_context = (
                            f"Package name from package.json: {actual_module_name}\n"
                        )
            except:
                logger.exception(
                    "unknow exception occurred",
                    extra={
                        "_filename": __file__
                    },
                    exc_info=True,
                    stack_info=True
                )
                pass

        actual_module_name, module_context = (
            self.extract_actual_module_name_and_context(
                file_content, language, file_path,actual_module_name,module_context
            )
        )
        prompt = f"""
        You are a brilliant assistant that gets the canonical format of the function name in {language} programming language.
        Below are some examples of how to convert a function definition to its canonical format in {language}:
        """

        # Handle unknown language gracefully
        if language not in self.canonical_format_examples:
            logger.warning(f"Unknown language '{language}' for file {file_path}, skipping canonical format generation")
            return "UNKNOWN"

        # Replace placeholders with actual module name in examples
        for example in self.canonical_format_examples[language]:
            example_input = example["input"]
            example_output = example["output"]

            # Replace all possible placeholder variations
            replacements = {
                "moduleName": actual_module_name,
                "ModuleName": actual_module_name,
                "module_name": actual_module_name,
                "file.c": f"{actual_module_name}.c",  # For C examples
                "TestNamespace": actual_module_name,  # For C#/PHP examples
                "TestModule": actual_module_name,  # For Ruby examples
                "testnamespace": actual_module_name.lower(),  # For C++ examples
                "testgo": actual_module_name,  # For Go examples
            }

            for placeholder, replacement in replacements.items():
                example_input = example_input.replace(placeholder, replacement)
                example_output = example_output.replace(placeholder, replacement)

            prompt += f"""
            Example:
            Input: {example_input}
            Output: {example_output}
            """
        # Special handling for Ruby global functions
        if language == "ruby" and not actual_module_name:
            prompt_module_part = ""
            prompt_instruction = "For Ruby: This is a global function, so use only the function name without any module prefix."
        else:
            prompt_module_part = f" using the actual module name '{actual_module_name}'"
            prompt_instruction = f"Use the actual module name '{actual_module_name}' from the context above, not placeholder names"

        raw_url = self.get_github_raw_url(commit_url, file_path)
        response = requests.get(raw_url)
        if response.status_code != 200:
            return "UNKNOWN"
        file_content = response.text

        prompt += f"""
        Module context:
        {module_context}
        File path: {file_path}
        Instructions:
        - CAREFULLY EXTRACT THE FUNCTION SIGNATURE (From Code snippet 1).
        - For multiple parameters: use commas to separate (From Code snippet 1).
        - {prompt_instruction}
        - For JavaScript/TypeScript: Replace 'moduleName' in examples with the actual module name (From Code snippet 2)
        - For Rust: If the function is inside an impl block, use the format crate::StructName::function_name (From Code snippet 2)
        - For Ruby: Use :: for class/module separators and # for instance methods, . for class methods. For global functions, use only the function name without any prefix.
        - For C#: Use full type names (System.Int32, System.String) for parameters when multiple params
        - Look at the surrounding code context to determine if the function belongs to a struct/class/impl/namespace block (From Code snippet 2)
        - For JS: Look at the surrounding code context to determine if the function is assigned to some other variable (use the variable name) or if the function is using a computed property name (find and use the original name) -> (From Code snippet 2)
        - If there is no matched example in the examples above, use your own knowledge to generate the canonical format name for the function.
        Now, given the following 2 code snippets from {file_path} (function '{function_name}' at line {line_number}), generate the canonical format name for the function.
        Code snippet 1:
        {self.extract_function_body_from_content(file_content, line_number, end_line_number)}
        Code snippet 2:
        {file_content}
        Function name: {function_name}
        Line number: {line_number}
        Language: {language}

        Output:
        ***IMPORTANT: Respond only with the canonical format name of the function{prompt_module_part}. This is a crucial step, DO NOT OUTPUT ANYTHING EXCEPT THE CANONICAL NAME***
        """
        try:
            response = self.client.chat.completions.create(
                model="anthropic/claude-sonnet-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=50,
                timeout=30,
            )
        except:
            logger.exception(
                f"error getting canonical format",
                extra={
                    "file_path": file_path,
                    "_filename": __file__
                },
                exc_info=True,
                stack_info=True
            )
            return "UNKNOWN"

        canonical_format = response.choices[0].message.content.strip()

        if language in ["javascript"]:
            canonical_format = canonical_format + f"@{line_number}"
            column_number = self.get_function_column(file_content, function_name, line_number) # get the starting column number of the function definition (1-based index) 
            if column_number:
                canonical_format = canonical_format + f":{column_number}"

        return canonical_format

    @staticmethod
    def extract_function_body_from_content(
            file_content: str,
            start_line_number: int,
            end_line_number: int
    ) -> str:
        """
        Extracts the body of a function given its name and starting line number from file content.
        Works with Python (indentation-based) and C-style languages (braces).
        """
        lines: list[str] = file_content.splitlines()
        idx1,idx2 = start_line_number - 1, end_line_number-1

        if idx1 < 0 or idx1 >= len(lines):
            return f"Line {start_line_number} out of range (file has {len(lines)} lines)"
        if idx2 < 0 or idx2 >= len(lines):
            return f"Line {end_line_number} out of range (file has {len(lines)} lines)"

        return "\n".join(lines[idx1:idx2])

    @staticmethod
    def extract_actual_module_name_and_context(
            file_content: str,
            language: str,
            file_path: str,
            module_name: str,
            module_context: str
    ) -> tuple[str, str]:
        """
        Extracts the actual module/namespace/package name and its context for the given language.
        Falls back to the file name if no declaration is found.
        Returns (actual_module_name, module_context).
        """

        if language == "php":
            namespace_match = re.search(
                r"namespace\s+([A-Za-z0-9_\\]+)\s*;", file_content
            )
            if namespace_match:
                return (
                    namespace_match.group(1),
                    f"Namespace from file: {namespace_match.group(1)}\n",
                )

        elif language == "go":
            package_match = re.search(r"package\s+([A-Za-z0-9_]+)", file_content)
            if package_match:
                return (
                    package_match.group(1),
                    f"Package from file: {package_match.group(1)}\n",
                )

        elif language == "ruby":
            module_match = re.search(
                r"^\s*module\s+([A-Za-z0-9_]+)", file_content, re.MULTILINE
            )
            if module_match:
                return (
                    module_match.group(1),
                    f"Module from file: {module_match.group(1)}\n",
                )

        elif language == "cpp":
            namespace_match = re.search(
                r"namespace\s+([A-Za-z0-9_]+)\s*\{", file_content
            )
            if namespace_match:
                return (
                    namespace_match.group(1),
                    f"Namespace from file: {namespace_match.group(1)}\n",
                )

        elif language == "csharp":
            namespace_match = re.search(
                r"namespace\s+([A-Za-z0-9_.]+)\s*\{", file_content
            )
            if namespace_match:
                return (
                    namespace_match.group(1),
                    f"Namespace from file: {namespace_match.group(1)}\n",
                )

        elif language in ["javascript", "typescript"]:
            return module_name, module_context
            # This block is for fallback only; actual logic may use package.json elsewhere
            
        return "", "No module/namespace declaration found in file\n"