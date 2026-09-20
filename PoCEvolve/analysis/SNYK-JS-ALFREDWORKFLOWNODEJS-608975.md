# VFCS Cross-Contamination: alfred-workflow-nodejs (SNYK-JS-ALFREDWORKFLOWNODEJS-608975)

## Bug Description
The VFCS entry for `alfred-workflow-nodejs` in `secbenchjs/vfcs.json`, `secbenchjs/vfcs.filtered.json`, and `secbenchjs/vfcs.testbed.json` carries commit-related fields from a different package (`apex-publish-static-files`).

## Affected Fields
- `commit_message`: `"uses spawn instead of exec"` — belongs to apex-publish-static-files
- `source_code_changes[0].patch`: `execSync → spawnSync` for `upload()` method with `sqlclPath`, `connectString`, `appID` parameters — belongs to apex-publish-static-files
- `vulnerability_fix_commit`: `"https://github.com/vincentmorneau/apex-publish-static-files/commit/2209af8f2b65c24aa55ab757e0e05b958c16f063"` — wrong repo
- `pr_title`, `pr_description`: `"n/a"` (but would refer to apex-publish-static-files PR)

## Correct Information
The real vulnerability is in alfred-workflow-nodejs's `utils.wfVars.remove()` function:

```
alfred-workflow-nodejs is an Alfred workflow nodejs module.
Affected versions of this package are vulnerable to Command Injection.
It is possible to inject arbitrary commands by using a semicolon char 
in any of the key values.

var AlfredNode = require('alfred-workflow-nodejs');
var utils = AlfredNode.utils;
utils.wfVars.remove(' "; whoami>hacked #', false);
```

This is CVE-2018-XXXX (Snyk-only, not GHSA-9jm3-5835-537m which is apex-publish-static-files).

## Why This Happened
Both packages had command injection vulnerabilities fixable by switching from `child_process.execSync` string concatenation to `spawnSync` with array arguments. During SecBench.js dataset construction, the commit diff for apex-publish-static-files was incorrectly matched to the alfred-workflow-nodejs vulnerability entry (SNYK-JS-ALFREDWORKFLOWNODEJS-608975).

The two packages share a similar code pattern and fix approach, making them prone to cross-contamination during automated data matching. Both are npm tools that use child_process for CLI execution.

## Impact
All PoC generation attempts on this entry fail because the LLM targets an `upload()` method that doesn't exist on alfred-workflow-nodejs. In baseline run `baseline_20260910_093811`, all 5 iterations failed with `assert.ok(success)` evaluating to false.

## Fix Required
1. Find the actual GitHub repository for alfred-workflow-nodejs (or the NPM advisory) and extract its real commit_message, source_code_changes, and vulnerability_fix_commit.
2. Update all three VFCS files: `vfcs.json`, `vfcs.filtered.json`, `vfcs.testbed.json`.
3. Alternatively, add pipeline validation that checks patch-to-package alignment before LLM consumption.

## Verification Steps
```bash
# Check if commit_message matches the vulnerable_package
python3 -c "
import json
with open('secbenchjs/vfcs.json') as f:
    data = json.load(f)
for entry in data:
    if entry.get('vulnerable_package') == 'alfred-workflow-nodejs':
        print(json.dumps(entry, indent=2))
        break
"
# Confirm vulnerability_fix_commit URL repo matches vulnerable_package
```

---
Related: See `../../eval/results/baseline_20260910_093811/alfred-workflow-nodejs.json` for failed PoC attempts.
