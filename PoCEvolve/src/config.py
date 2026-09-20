from pathlib import Path
import os


## Paths & Directories
DATASET_LIST = os.getenv("DATASET", "datasets/SecBench.js.PoCGen.vfc.190")
TESTBED_DIR = "testbed"
GEPA_LOG_DIR = Path(os.getenv("RUN_OUTPUT_DIR", "logs"))
GEPA_LOG_DIR.mkdir(parents=True, exist_ok=True)
PROJECT_ROOT = Path(__file__).resolve().parent


COMMAND_TIMEOUT = 60
MAX_WORKERS = 1
MAX_EXEC_OUTPUT_CHARS = 4000
MAX_EXECUTION_OUTPUTS_IN_FEEDBACK = 4


TRAINING_DATA = "datasets/qwen3.7-plus.training-set"
GENERATED_VFC_GLOB = f"{GEPA_LOG_DIR}/vfcs.generated.*.jsonl"
ITERATION = 0 # qwen3.6 is not doing well anyway for GEPA so keeping it short (was 5)
MINIBATCH_SIZE = 3
VERIFY_TIME = 2
SEED = 42
SKIP_GEPA = os.getenv("SKIP_GEPA", "1") == "1"
# MODEL_NAME = "gpt-4o-mini"
# API_KEY = "sk-proj-xxx"
# API_BASE = "https://api.openai.com/v1"
MODEL_NAME = "qwen36-local"
API_KEY = "sk-litellm-local"  # LiteLLM auth token from ~/.claude/settings.json
API_BASE = "http://127.0.0.1:4000"  # Local LiteLLM proxy

# When running inside Docker with network_mode: host, localhost already points to the
# host's network stack where Ollama listens. No override needed.
TEMPERATURE = 1
MAX_RETRY = 2


## Oracle
CWE_MAP = {
    "code-injection": {
        "attack_goal": "execute `process.seteuid(42)`",
        "description": "The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment."
    },
    "command-injection": {
        "attack_goal": "execute the binary `/usr/bin/genpoc`",
        "description": "Many protocols and products have their own custom command language. While OS or shell command strings are frequently discovered and targeted, developers may not realize that these other command languages might also be vulnerable to attacks."
    },
    "path-traversal": {
        "attack_goal": "use path traversal to access `/flag.txt`",
        "description": "Many file operations are intended to take place within a restricted directory. By using special elements such as '..' and '/' separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the '../' sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as '/usr/local/bin' to access unexpected files. This is referred to as absolute path traversal."
    },
    "prototype-pollution": {
        "attack_goal": "pollute the object prototype with a property `exploited`",
        "description": "By adding or modifying attributes of an object prototype, it is possible to create attributes that exist on every object, or replace critical attributes with malicious ones. This can be problematic if the product depends on existence or non-existence of certain attributes, or uses pre-defined attributes of object prototype (such as hasOwnProperty, toString or valueOf). This weakness is usually exploited by using a special attribute of objects called proto, constructor or prototype. Such attributes give access to the object prototype. This weakness is often found in code that assigns object attributes based on user input, or merges or clones objects recursively."
    },
    "redos": {
        "attack_goal": "exceed the backtracking limit of 30000",
        "description": "Some regular expression engines have a feature called 'backtracking'. If the token cannot match, the engine 'backtracks' to a position that may result in a different token that can match. Backtracking becomes a weakness if all of these conditions are met: (1) The number of possible backtracking attempts are exponential relative to the length of the input. (2) The input can fail to match the regular expression. (3) The input can be long enough. Attackers can create crafted inputs that intentionally cause the regular expression to use excessive backtracking in a way that causes the CPU consumption to spike."
    }
}


VALIDATE_FUNC = {
    "code-injection": "resources/validate_functions/code-injection.js",
    "command-injection": "resources/validate_functions/command-injection.fixed.js",
    "path-traversal": "resources/validate_functions/path-traversal.js",
    "redos": "resources/validate_functions/redos.js",
    "prototype-pollution": "resources/validate_functions/prototype-pollution.js",
}


EXPLOIT_CODE_TEMPLATE = """
import test from "node:test";
import assert from 'node:assert';
import {{ createRequire }} from "node:module";
import {{ fileURLToPath }} from 'url';

async function runExploit() {{
{exploit_function}
}}

{validate_function}

test('{attack_type} in "{package}@{vulnerable_version}" ({id})', (t, done) => {{
process.removeAllListeners('unhandledRejection')
process.removeAllListeners('uncaughtException')
process.on("unhandledRejection", () => {{ }});
process.on("uncaughtException", () => {{ }});

global.require = createRequire(import.meta.url);
global.__dirname = fileURLToPath(import.meta.url);

validate(runExploit, done).then((success) => {{
assert.ok(success);
done();
}}
).catch((err) => {{
console.error(err);
done(err);
}});
}});
"""
