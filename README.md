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

The validator never trusts the leader's formatting alone. It independently classifies the same input and verifies the security-critical fields.

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

Verified on commit `c0183412e94e0d133e41ce3b045864d0ddb3640d`.

- Contract: `0xc2d1A30CDA9ad1688a3739dB72C60cEe55FDBb87`
- Explorer: https://explorer-studio.genlayer.com/address/0xc2d1A30CDA9ad1688a3739dB72C60cEe55FDBb87
- Benign scan tx: https://explorer-studio.genlayer.com/tx/0xb476004ed7ee5ad6ad9e881b9fb5bc0088d9f60784eab29b9dab4de05a401dc2
- Benign result: `ALLOW`, risk score `0`, confidence `98`
- Injection scan tx: https://explorer-studio.genlayer.com/tx/0x2c4397c533377bebad67ecf6d091c6d68cbbdc5dd80c0577251a61e4a59d98d8
- Injection result: `BLOCK`, high-impact `1`, risk score `95`
- CI: https://github.com/maho0638/inputshield-genlayer/actions/runs/37694677972
- Studionet proof: https://github.com/maho0638/inputshield-genlayer/actions/runs/37694678128
- Direct tests: **14 / 14 PASS**
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
