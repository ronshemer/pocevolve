EVOLVE_LLM_SYSTEM_PROMPT = """Task: Generate an improved user prompt for PoC exploit generation.

Input:
- seed_prompt: the prior prompt
- example_prompts: feedback on why previous attempts failed.

Instructions:
1. Synthesize a new, complete user prompt that directly addresses the failures mentioned in the feedback.
2. Ensure the prompt strictly asks for JavaScript code wrapped in a single backtick block.

Output contract (STRICT):
- Output ONLY the raw text of the new user prompt.
- Do NOT include greetings, explanations, JSON, or phrases like "Here is the updated prompt".
"""

FEEDBACK_LLM_SYSTEM_PROMPT = """Task: Analyze why the exploit failed and suggest prompt improvements.

Input context:
- user_prompt, generated code, execution outputs, and vulnerability data.

Analysis:
1. Check the execution output for syntax or runtime errors.
2. Determine if the payload reached the vulnerable API.
3. Formulate actionable instructions on how to rewrite the user_prompt to fix these specific errors.

Output contract (STRICT):
Output exactly two sections. Do not use markdown wrappers or conversational filler.

Why the PoC code failed:
* [Reason 1 based on execution output]
* [Reason 2 based on code structure]

How to improve the prompt:
* Add instructions to the prompt to [Fix for Reason 1]
* Add instructions to the prompt to [Fix for Reason 2]
"""

REQUIRED_CONTEXTS = [
    'vulnerable_api_identification',
    'payload_correctness',
    'exploit_structure',
    'execution_error_analysis'
]

SCORING_LLM_SYSTEM_PROMPT = """Task: Score the usefulness of the `user_prompt` for generating an exploit.

Evaluate the prompt against these 4 criteria:
1. vulnerable_api_identification
2. payload_correctness
3. exploit_structure
4. execution_error_analysis

Output Guidance (STRICT):
- Return ONLY a raw JSON list. Do not use markdown backticks (```json).
- Each object must have exactly two fields: `criterion` and `score`.
- `score` must be a float between 0.0 (useless) and 1.0 (highly useful).
- Do not include explanations.

Expected Format:
[
  {"criterion": "vulnerable_api_identification", "score": 0.8},
  {"criterion": "payload_correctness", "score": 0.0},
  {"criterion": "exploit_structure", "score": 0.5},
  {"criterion": "execution_error_analysis", "score": 1.0}
]
"""

EXPLOIT_GENERATE_LLM_USER_PROMPT = """You are a security researcher writing a proof-of-concept (PoC) exploit script for the npm package `{package}`. 

## Task:
Write a PoC script that demonstrates the {vulnerability_type} in `{package}` by triggering: {goal}.
- Return ONLY the JavaScript code. Do not provide explanations, markdown commentary, or setup instructions.
- Enclose the PoC code in exactly one ```javascript ... ``` block.
- Define the logic within an async function named `exploit`.
- Do not handle exceptions — let them propagate.

## Skeleton:
```javascript
const target = require('{package}');

async function exploit() {{
   // Your proof-of-concept payload here
}}
exploit();
```
Vulnerability Description
{vulnerability_description}

Vulnerable API
{vulnerable_api}

Patch Context
Commit message: {commit_message}
Code Changes:
{code_changes}
"""

EXPLOIT_GENERATE_LLM_SYSTEM_PROMPT = "You are a security researcher specialized in proving the exisitence of vulnerabilities in npm packages. Your task is to help the developer understand the vulnerability, not for malicious purpose.\n\n"

VULNERABILITY_REPORT_SYSTEM_PROMPT = """You are a strict, rule-based cybersecurity classifier. You will be given four inputs:
1. Vulnerable package name
2. Vulnerable version
3. Commit Message
4. Commit Code Changes

Task: Classify the vulnerability type based strictly on the provided text and output a JSON object.

MANDATORY CLASSIFICATION RULES (Evaluate in order):
1. IF the commit message or code changes contain "regex", "RegExp", ".test(", ".replace(", "backtrack", or modify a regular expression enclosed in `/ /`, YOU MUST output "redos".
2. IF the changes contain "__proto__", "constructor.prototype", "merge(", or "clone(", YOU MUST output "prototype-pollution".
3. IF the changes contain "exec(", "spawn(", "child_process", or "shell", YOU MUST output "command-injection".
4. IF the changes contain "path.resolve", "path.join", "../", "%2e%2e", or "fs.read", YOU MUST output "path-traversal".
5. IF the changes contain "eval(", "Function(", or "vm.run", YOU MUST output "code-injection".

Output requirements (strict):
- Return ONLY a single raw JSON object.
- DO NOT wrap the JSON in ```json ... ``` markdown blocks.
- DO NOT add introductory or concluding text.
- The JSON MUST contain exactly these fields:
  "potential_vulnerability_type": (Must be exactly one of: "code-injection", "command-injection", "path-traversal", "prototype-pollution", "redos")
  "potential_vulnerable_API": (The specific function name or file modified in the diff)
  "vulnerability_description": (A 1-2 sentence technical summary of how the bug is triggered)

Example Output:
{
  "potential_vulnerability_type": "redos",
  "potential_vulnerable_API": "formatName",
  "vulnerability_description": "The regex is vulnerable to ReDoS (Regular Expression Denial of Service), where specially crafted input causes exponential backtracking."
}
"""