# InputShield Security Model

## Purpose

InputShield is a defense-in-depth primitive for GenLayer builders who need to decide whether untrusted text or public web content is safe to pass into a more capable LLM/agent workflow.

The consensus-critical output is one of:

- `ALLOW`
- `REVIEW`
- `BLOCK`

## Protected failure modes

The policy targets prompt-injection and agent-control attempts such as:

1. instruction hierarchy override;
2. system/developer/validator/tool impersonation;
3. tool execution or browsing commands;
4. wallet signing, transfer, or contract-mutation requests;
5. secret/credential/private-key/seed-phrase extraction;
6. encoded or obfuscated control instructions.

## Consensus invariants

InputShield does not accept a leader result just because it is valid JSON.

Each validator independently performs the same classification and the contract requires agreement on the security-critical boolean signals and on the **derived enforcement action**.

Scores may drift only while remaining inside the same action bucket. A 69/71 split cannot pass merely because the values are numerically close if one means REVIEW and the other means BLOCK.

## Fail-closed behavior

- `high_impact = true` => BLOCK.
- malformed/missing booleans default to risky values;
- malformed/missing score defaults to 100;
- confidence below 60 cannot result in ALLOW;
- unknown or low-confidence evidence therefore cannot silently become trusted.

## Audit-only fields

`rationale` is human-readable context. It is not used to trigger a downstream security decision and validators do not require wording equality.

## Known limitations

InputShield is not a proof that content is harmless.

- A sufficiently novel injection may evade all participating models.
- Public pages can change between validator requests.
- The URL method classifies at most the first 30,000 rendered text characters.
- The contract does not provide malware, phishing-domain, binary-file, or network-reputation analysis.
- Builders should combine InputShield with least-privilege tool design, output constraints, allowlisted actions, and human review for high-value operations.

For critical value transfer, InputShield should be treated as one gate, not the sole authorization mechanism.
