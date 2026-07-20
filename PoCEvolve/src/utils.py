import json
import csv
import subprocess
import time
import urllib.parse
import re
import hashlib

from src.config import COMMAND_TIMEOUT, MODEL_NAME

def load_csv(data_path: str) -> list[dict]:
    """
    Load a CSV file and return a list of dictionaries (one per row).

    The first line is treated as the header. Returns an empty list if the
    file cannot be read or no rows are present.

    :param data_path: Path to the CSV file.
    :return: List of row dictionaries.
    """
    rows: list[dict] = []
    try:
        with open(data_path, mode='r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            for r in reader:
                # Normalize keys (strip whitespace) and keep values as-is
                row = {k.strip() if k else k: v for k, v in r.items()}
                rows.append(row)
    except FileNotFoundError:
        print(f"CSV file not found: {data_path}")
    except Exception as e:
        print(f"Error loading CSV {data_path}: {e}")
    return rows

def hash_messages(messages: list) -> str:
    """
    Create a stable hash for a list of chat messages.
    """
    contents = []
    for message in messages:
        contents.append(message.get("content", ""))
    text = '\n'.join(contents)
    serialized = json.dumps(text, sort_keys=True, ensure_ascii=False)
    serialized += MODEL_NAME
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def _has_exploit_function(code: str) -> bool:
    """Detect exploit function declarations in generated JavaScript blocks."""
    return bool(re.search(r"\b(?:async\s+)?function\s+exploit\s*\(", code))


def extract_triple_backticks(input_text: str) -> str:
    """
    Extracts code blocks wrapped in triple backticks from the input string.

    Args:
        input_text (str): The input string containing code blocks.

    Returns:
        str: The most relevant extracted code block.
    """
    pattern = r"```(?:\w+)?\s*([\s\S]*?)```"
    matches = [match.strip() for match in re.findall(pattern, input_text)]

    for match in matches:
        if _has_exploit_function(match):
            return match

    if matches:
        return matches[0]

    return ""

def extract_js_triple_backticks(input_text: str) -> str:
    """
    Extracts JavaScript code blocks wrapped in triple backticks
    from the input string.

    Args:
        input_text (str): The input string containing code blocks.

    Returns:
        str: The most relevant JavaScript code block.
    """
    pattern = r"```(?:js|javascript)\b[^\n]*\n?([\s\S]*?)```"
    matches = re.findall(pattern, input_text, re.IGNORECASE)
    output = [match.strip() for match in matches]
    for item in output:
        if _has_exploit_function(item):
            return item

    if output:
        return output[0]

    return extract_triple_backticks(input_text)

def url_encode_all_chars(input_str):
    return urllib.parse.quote(input_str, safe='')

def load_json(filepath):
    """
    Loads JSON data from a file.
    
    :param filepath (str): The path to the JSON file.
    :returns: dict: The loaded JSON data as a Python dictionary.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading JSON: {e}")
        return None
    
def load_jsonl(file_path):
    """
    Load a .jsonl file and return a list of JSON objects.
    """
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():  # skip empty lines
                data.append(json.loads(line))
    return data

def dump_json(data, file_path):
    """
    Dumps data into a JSON file.

    :param data: Data to be dumped into the JSON file.
    :param file_path: Path to the JSON file.
    """
    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

def dump_text(data:str, filename:str):
    """
    Dumps a string into a text file.
    
    :param data: String to be saved in the text file.
    :param filename: Name of the text file.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(data)
    except Exception as e:
        print(f"Error writing text to file: {e}")

def load_text(filename:str):
    """
    Loads text data from a file.
    
    :param filename: Name of the text file.
    :return: Content of the text file as a string.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError as e:
        print(f"Error loading text file: {e}")
        return None

def dump_jsonl(data, filename):
    """
    Dumps a list of dictionaries into a JSONL (JSON Lines) file.
    
    :param data: List of dictionaries to be saved as JSONL.
    :param filename: Name of the JSONL file.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for entry in data:
                file.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except Exception as e:
        print(f"Error writing JSONL to file: {e}")


def exec_command(cmd:str, cwd:str=".", timeout=COMMAND_TIMEOUT):
    """
    Execute a command with a specified timeout.
    
    :param cmd: Command to be executed.
    :param timeout: Time (in seconds) after which the command will be terminated.
    :return: Standard output and standard error of the executed command.
    """
    try:
        p = subprocess.Popen(cmd, cwd=cwd, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        start_time = time.time()

        while True:
            if p.poll() is not None:
                break
            elapsed_time = time.time() - start_time
            if timeout and elapsed_time > timeout:
                p.terminate()
                return f"The command reached timeout ({timeout} seconds)", ""
            time.sleep(1)

        out, err = p.communicate()
        return out, err
    except Exception as e:
        return "", str(e)