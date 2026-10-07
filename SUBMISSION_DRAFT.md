# Portal Submission Draft

## Category

Developer -> Intelligent Contracts

## Title

InputShield — Consensus Prompt-Injection Firewall for GenLayer

## Notes / description

InputShield is a reusable GenLayer Intelligent Contract security primitive for screening untrusted text and public web content before downstream contracts or agents rely on it. It detects prompt-injection and agent-control attempts such as instruction overrides, role impersonation, secret extraction, tool execution, wallet signing, value transfer, and contract-mutation requests.

GenLayer is central to the design: public webpages and semantic injection attempts are non-deterministic, so the contract uses live web rendering, structured LLM classification, and independent validator re-execution. Validators do not merely check JSON shape. They independently classify the same evidence and must agree on the final deterministic enforcement action: ALLOW, REVIEW, or BLOCK.

The equivalence rule explicitly prevents threshold-crossing bugs: numeric score drift is allowed only when it preserves the same final enforcement outcome. High-impact requests fail closed, low-confidence results can never become ALLOW, and malformed structured outputs default to risky values.

Direct tests cover safe, suspicious, blocked, malformed, boundary-crossing, and validator-disagreement cases. A live Studionet workflow deploys InputShield and verifies both a benign page and an explicit prompt-injection page.

## Evidence checklist

Replace placeholders after live proof completes.

- GitHub Repository:
  https://github.com/maho0638/inputshield-genlayer
- Contract source:
  https://github.com/maho0638/inputshield-genlayer/blob/main/contracts/input_shield.py
- Direct tests:
  https://github.com/maho0638/inputshield-genlayer/blob/main/tests/direct/test_input_shield.py
- Reviewer guide:
  https://github.com/maho0638/inputshield-genlayer/blob/main/docs/REVIEWER_GUIDE.md
- CI run: TBD
- Studionet proof run: TBD
- Explorer contract: TBD
- Benign transaction: TBD
- Blocked injection transaction: TBD

## Status

NOT READY until:
- PR CI passes;
- main CI passes;
- Studionet deployment finalizes;
- benign fixture is ALLOW;
- malicious fixture is BLOCK;
- live contract and transaction links are recorded.
