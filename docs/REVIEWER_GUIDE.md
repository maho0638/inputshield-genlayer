# Reviewer Guide

## What to review first

1. `contracts/input_shield.py`
   - `_derive_action` is the deterministic security policy.
   - `_validator_accepts` is the equivalence rule.
   - `scan_text` and `scan_url` expose the reusable primitive.

2. `tests/direct/test_input_shield.py`
   - look specifically at the threshold-crossing tests;
   - a 69 -> 71 risk-score change must fail validation;
   - a 61 -> 59 confidence change must fail if it changes ALLOW -> REVIEW;
   - numeric drift is accepted only when the final action remains unchanged;
   - tampered leader action fields are rejected;
   - evidence hashes and one-hour expiry metadata are stored;
   - source-unavailable results fail closed to REVIEW.

3. `tests/integration/test_inputshield_studionet.py`
   - deploys the contract;
   - scans one benign public fixture;
   - scans one explicit prompt-injection fixture;
   - verifies ALLOW vs BLOCK on live Studionet.

## Why this is a GenLayer primitive

The security question is semantic, not mechanically decidable from bytes. The contract uses GenLayer's non-deterministic web/LLM capabilities, but the final security action is constrained by deterministic policy and independent validator re-execution.

## Expected live result

- benign fixture => `ALLOW`
- adversarial fixture => `BLOCK`
- adversarial fixture => `high_impact = 1`
- policy version => `inputshield-v1`

## Reuse pattern

A downstream product can scan a source, read `get_action(scan_id)`, and only continue an automated workflow when it returns `ALLOW`. `REVIEW` can route to a human or additional verification; `BLOCK` should stop the automated path.
