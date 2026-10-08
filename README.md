# InputShield — Consensus Prompt-Injection Firewall for GenLayer

InputShield is a standalone **GenLayer Intelligent Contract security primitive** that classifies untrusted text or public web content before another contract, agent, or application relies on it.

It is intentionally different from an oracle, escrow, visual verifier, or generic “AI decides X” demo. Its purpose is to make a reusable security decision over adversarial natural-language input:

- **ALLOW** — no meaningful prompt-injection signal and sufficient confidence;
- **REVIEW** — suspicious or low-confidence content that must not be auto-trusted;
- **BLOCK** — high-impact agent-control / secret / tool / wallet / transaction requests, or severe injection risk.

## Why this matters

GenLayer Intelligent Contracts can read live webpages and use LLMs, but public content is not inherently trustworthy. A webpage can contain instructions such as “ignore previous instructions”, impersonate system/developer messages, request tool execution, or try to extract credentials.

InputShield creates a small reusable boundary that downstream builders can query before using that content in a more powerful workflow.

## Why GenLayer is central

A deterministic smart contract cannot reliably classify semantic prompt-injection attempts in arbitrary natural language. InputShield uses:

- `gl.nondet.web.render` to read public HTTPS content;
- `gl.nondet.exec_prompt(..., response_format="json")` for a bounded security classification;
- `gl.vm.run_nondet_unsafe` so validators independently re-run the classification;
- deterministic enforcement logic that maps accepted structured signals into **ALLOW / REVIEW / BLOCK**.

The validator never trusts the leader's formatting alone. It independently classifies the same input and verifies the security-critical fields. URL scans additionally require exact equality of the rendered evidence hash between leader and validators.

## Equivalence design

Raw LLM scores are allowed limited drift, but **drift can never cross an enforcement boundary**.

The contract deterministically derives the final action from:

- `suspicious`
- `high_impact`
- `risk_score`
- `confidence`

A validator accepts only when:

1. its independently derived final action matches the leader's;
2. `suspicious` matches;
3. `high_impact` matches;
4. risk-score drift is at most 15 points;
5. confidence drift is at most 20 points.

This explicitly prevents the classic threshold bug where, for example, one node scores 69 (**REVIEW**) and another 71 (**BLOCK**) yet numeric tolerance incorrectly treats them as equivalent.

## Evidence binding and freshness

Every stored scan includes an SHA-256 evidence hash plus deterministic transaction timestamps. ALLOW records expire after one hour; after expiry, `is_allowed` returns false and both `get_action` and `get_effective_action` return REVIEW. URL retrieval failures also resolve fail-closed to REVIEW rather than silently becoming trusted.

Untrusted evidence is JSON-encoded before insertion into the security prompt so fake delimiter text inside the payload cannot escape the evidence boundary.

## Fail-closed policy

- High-impact requests are always **BLOCK**.
- Confidence below 60 can never produce **ALLOW**.
- Risk score 70+ is **BLOCK**.
- Suspicious content or score 30+ is **REVIEW**.
- Malformed/missing structured model fields fail closed rather than becoming safe.

Free-form rationale is stored for auditability but is **not** used for enforcement.

## Public methods

### `scan_text(scan_id, source_label, untrusted_text)`
Classifies deterministic text supplied to the contract.

### `scan_url(scan_id, source_url)`
Fetches a public HTTPS page inside the non-deterministic block and classifies its text.

### `get_scan(scan_id)`
Returns the stored security record.

### `get_action(scan_id)`
Returns `ALLOW`, `REVIEW`, or `BLOCK`.

### `is_allowed(scan_id)`
Convenience view for downstream gating.

### `get_policy_version()`
Returns the immutable policy identifier `inputshield-v1`.

## Threat model

InputShield looks specifically for natural-language attempts to control an AI/agent, including:

- instruction hierarchy override;
- system/developer/validator/tool impersonation;
- tool execution requests;
- wallet signing / value-transfer / state-mutation requests;
- credentials, API keys, private keys, seed phrases, tokens, hidden prompts, or secret extraction;
- encoded or obfuscated instructions.

It is **not** a malware scanner, URL reputation service, antivirus product, phishing blacklist, or general content-moderation contract.

See [SECURITY.md](SECURITY.md) for scope and limitations.

## Live Studionet proof

Verified on commit `126305282f53c3d629a7d4679095ee0845f41804`.

- Contract: `0x2450bd6D294C9DE72ec2CA6f924C15fca7f9A116`
- Explorer: https://explorer-studio.genlayer.com/address/0x2450bd6D294C9DE72ec2CA6f924C15fca7f9A116
- Benign scan tx: https://explorer-studio.genlayer.com/tx/0x462040fdefeb25d265090259a8d69119887c015f834786b27bdf2230d37574fd
- Benign result: `ALLOW`, risk score `0`, confidence `98`
- Injection scan tx: https://explorer-studio.genlayer.com/tx/0xb25a1694301389f4374591c98eaaca81447eb5665da29413e74577176260a07a
- Injection result: `BLOCK`, high-impact `1`, risk score `100`
- CI: https://github.com/maho0638/inputshield-genlayer/actions/runs/37730228366
- Studionet proof: https://github.com/maho0638/inputshield-genlayer/actions/runs/37730228386
- Direct tests: **19 / 19 PASS**
- GenVM lint: **PASS**

## Verification

Direct tests cover:

- safe / review / blocked outcomes;
- fail-closed malformed output;
- HTTPS and input bounds;
- duplicate IDs;
- public web scanning;
- risk-score threshold crossing;
- confidence threshold crossing;
- high-impact disagreement;
- acceptable numeric drift that preserves the same final action.

A separate workflow deploys the contract to Studionet and exercises both a benign page and an explicit prompt-injection fixture.

### Local

```bash
pip install -r requirements.txt
pytest tests/direct -v
genvm-lint check contracts/input_shield.py
```

### Live Studionet

```bash
gltest tests/integration/test_inputshield_studionet.py -v -s --network studionet
```

## Repository layout

```text
contracts/input_shield.py
tests/direct/test_input_shield.py
tests/integration/test_inputshield_studionet.py
fixtures/benign.txt
fixtures/prompt_injection.txt
SECURITY.md
SUBMISSION_DRAFT.md
.github/workflows/ci.yml
.github/workflows/inputshield-studionet.yml
```

## Policy version

Current: **inputshield-v1**

The policy identifier is stored with every scan so downstream users can distinguish future policy upgrades.
