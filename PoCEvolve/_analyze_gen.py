import json

with open('PoCEvolve/logs/vfcs.generated.single_cve_dataset.txt.jsonl') as f:
    for line in f:
        if not line.strip():
            continue
        obj = json.loads(line)

        print("=== SOURCE INFO ===")
        print(f"CVE IDs: {obj.get('ids')}")
        print(f"Package: {obj.get('vulnerable_package')}")
        print(f"Version: {obj.get('vulnerable_version')}")
        print(f"Vuln Type: {obj.get('vulnerability_type')}")
        print(f"Commit msg: {obj.get('commit_message')}")

        ad = obj.get('advisory_descriptions', [])
        if ad:
            print(f"Advisory (truncated): {str(ad[0])[:300]}...")

        gen = obj.get('generated', {})
        print(f"\n=== LLM Generation Usage ===")
        print(json.dumps(gen.get('usage', {}), indent=2))

        ge = obj.get('generated_exploits', [])
        print(f"\n=== Generated Exploits ({len(ge)} attempt(s)) ===")
        for i, exp in enumerate(ge):
            print(f"\n--- Attempt {i+1} ---")
            sys_prompt = str(exp.get('systemPrompt', ''))
            user_prompt = str(exp.get('userPrompt', ''))
            resp = exp.get('response', '')

            print(f"System prompt ({len(sys_prompt)} chars): first 200 = {sys_prompt[:200]}")
            print(f"User prompt ({len(user_prompt)} chars)")
            # show key parts of user prompt
            print(f"User prompt first 600 chars: {user_prompt[:600]}")

            if resp and '```javascript' in resp:
                start = resp.index('```javascript') + 13
                end = resp.index('```', start) if '```' in resp[13:] else -1
                code = resp[start:end].strip() if end > 0 else resp[start:]
            elif resp and '```' in resp:
                parts = resp.split('```')
                code = parts[1] if len(parts) > 1 else ''
            else:
                code = resp[:500]

            print(f"Response code ({len(code)} chars): {code[:600]}")
            print(f"Full response length: {len(resp)}")
            print(f"Has backticks in response: {'```' in resp}")

        sbt = obj.get('secbench_test', '')
        if sbt:
            print(f"\n=== SecBench Test ({len(sbt)} chars) ===")
            print(sbt[:500])
