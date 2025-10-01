# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import time

from loggers import (
    get_logger
)

logging = get_logger(__name__)

def get_prompt_messages(description: str, filename: str, formatted_code: str) -> list:
    """
    Constructs the prompt messages for the LLM to analyze root cause from code changes.

    Parameters
    ----------
    description: str
        The CVE description
    filename: str
        Name of the file being analyzed
    formatted_code: str
        Code diff or formatted code snippet

    Returns
    -------
    list
        A list of system and user message dictionaries for the LLM chat format.
    """
    return [
        {
            "role": "system",
            "content": (
                "You are a security researcher specializing in vulnerability detection, specifically in identifying the root cause of vulnerabilities in code. "
                "Your task is to determine which method(s) or function(s) are responsible for a specific CVE and analyze the root cause and also their roles ((entry_point, propagation, sink))."
                "Do not provide any unrelated functions or methods or patch-related information."
            )
        },
        {
            "role": "user",
            "content": (
                f"The description of CVE is provided:\n{description}\n\n"
                f"The filename is {filename}"
                f"Now, analyze the following file and its code change:\n{formatted_code}\n\n"
                """***Task 1:***
                Your primary task is to identify which method(s) or function(s) in the provided code are responsible for the CVE or the root cause of the CVE. 
                Provide a brief explanation as to why you consider these method(s) or function(s) the root cause.
                You must only consider the code shown above and provide function/method names. Do **not** mention any variables, constants, or regular expressions by themselves.
                Remember that **root cause** and **patch/fix** are not the same. Do not include patch-related methods or any unrelated functions.
                ***IMPORTANT:
                There maybe many function but you only need to consider the method(s) or function(s) which you will consider as the actual root cause if exist.Dont consider all functions other then the root cause.Be very careful so that it is related to the CVE description.
                Your output structure will be:
                version:
                Root cause function:
                Role: Entrypoint/Propagation/Sink (Identify it correctly)
                Short Explanation why it is considered root cause for the cve:
                If you dont find any function/method then Output as "Did not get vulnerability in this file"
                Be very strict to check if the code is related to CVE description like in terms of package,language,filename etc.If not then mention "The code is not related to CVE description".
                ***REMEMBER***
                Focus solely on identifying **root cause functions/methods**
                - Be very careful to check whether the commit is related to the particular CVE or not.Verify it based on cve description provided to you.If not related dont provide output.
                - Please also include roles (entry_point, propagation, sink) if relevant.Please be very cautious to identify them correctly.Only output the function(s)/method(s) names and their roles.
                - Do not hallucinate or provide any unrelated information. **Focus only on the root cause functions/methods.**
                - Do **not** consider or mention any function/method that appears **only in patch/fix code**.
                - If the same function/method appears in both the code diff and the patch, ensure it is being marked for its **root cause**, not its patch.
                - If no function is clearly responsible, explicitly mention that in your response.
                """
            )
        }
    ]

def analyze_patch_with_models(client, description: str, filename: str, formatted_code: str) -> list:
    """
    Runs root cause analysis using multiple LLM instances in parallel (with the same model).

    Parameters
    ----------
    client
        OpenRouter or OpenAI client to call the model API.
    description: str
        CVE description text.
    filename: str
        The filename where the patch/code change occurred.
    formatted_code: str
        The code diff or formatted content to analyze.

    Returns
    -------
    list
        A List of string responses from each model run, one per instance.
    """
    models = ["anthropic/claude-sonnet-4"] * 6
    outputs = []

    for i, model in enumerate(models, start=1):
        logging.info(
            f"Running analysis with model: {model}",
            extra={
                "iteration number": i,
                "model": model,
            },
        )
        messages = get_prompt_messages(description, filename, formatted_code)
        start_time = time.time()
        response = client.chat.completions.create(
            messages=messages,
            temperature=0.0,
            top_p=1.0,
            max_tokens=500,
            model=model,
            seed=42
        )
        end_time = time.time()
        logging.info(
            f"⏱️ Total Time taken",
            extra={
                'seconds': f"{end_time - start_time:.2f}s"
            }
        )

        if response.choices:
            outputs.append(f"Run {i} | Model: {model}| Filename: {filename}\nResponse:\n{response.choices[0].message.content.strip()}")

    return outputs

def generate_consensus(client, outputs: list, filename: str) -> str:
    """
    Generates a consensus output by analyzing multiple LLM responses and extracting agreement.

    Parameters
    ----------
    client
        OpenRouter or OpenAI client to call the model API.
    outputs: list
        List of individual LLM model responses.
    filename: str
        The filename under consideration.

    Returns
    -------
    str
        A string containing the consensus output in JSON format.
    """    

    summary_prompt = (
        f"You have 6 analysis outputs from different LLMs that attempted to identify the **root cause function(s)** responsible for a vulnerability (CVE) "
        f"in the file `{filename}`.\n\n"
        "### Task:\n"
        "- Determine the **majority-agreed root cause function(s)** (at least 3 matches).\n"
        "- Format your output as JSON:\n\n"
        "```json\n"
        "{\n"
        "  \"root_cause_functions\": [\n"
        "    {\n"
        "      \"function_name\": \"<function>\",\n"
        "      \"filename\": \"<filename>\",\n"
        "      \"role\": \"<role>\",\n"
        "      \"package\": \"<package>\",\n"
        "      \"version\": \"<version>\",\n"
        "      \"Qualified Name\": \"<qualified.name>\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "```"
    )
    messages = [{"role": "user", "content": summary_prompt}]
    for idx, out in enumerate(outputs):
        messages.append({"role": "user", "content": f"Output {idx+1}:\n{out}"})

    response = client.chat.completions.create(
        messages=messages,
        temperature=0.0,
        max_tokens=4096,
        model="anthropic/claude-sonnet-4"
    )
    return response.choices[0].message.content.strip()