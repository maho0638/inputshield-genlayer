# Portal Submission Draft

## Category

Developer -> Intelligent Contracts

## Title

InputShield — Consensus Prompt-Injection Firewall for GenLayer

## Notes / description

InputShield is a reusable GenLayer Intelligent Contract security primitive that screens untrusted text and public web content before downstream contracts or agents rely on it. It detects prompt-injection and agent-control attempts such as instruction overrides, role impersonation, secret extraction, tool execution, wallet signing, value transfer, and contract-mutation requests. Validators independently re-run the security classification and must agree on the deterministic ALLOW / REVIEW / BLOCK outcome. Numeric drift is accepted only when it preserves the same final action, preventing threshold-crossing consensus bugs. High-impact and malformed outputs fail closed. Scans are bound to SHA-256 evidence hashes, ALLOW results expire after one hour, URL retrieval failures fail closed to REVIEW, and untrusted content is JSON-encoded before prompt insertion to prevent delimiter breakout. Verification: 17/17 direct tests PASS, GenVM lint PASS, and live Studionet proof PASS. Live benign content resolved ALLOW (score 0, confidence 99); explicit injection resolved BLOCK (high-impact 1, score 99).

## Evidence

- GitHub Repository:
  https://github.com/maho0638/inputshield-genlayer
- Immutable contract source:
  https://github.com/maho0638/inputshield-genlayer/blob/aee50fcdb19f4e24af5c23fbcea1f14de313b1a6/contracts/input_shield.py
- Immutable direct tests:
  https://github.com/maho0638/inputshield-genlayer/blob/aee50fcdb19f4e24af5c23fbcea1f14de313b1a6/tests/direct/test_input_shield.py
- Reviewer guide:
  https://github.com/maho0638/inputshield-genlayer/blob/aee50fcdb19f4e24af5c23fbcea1f14de313b1a6/docs/REVIEWER_GUIDE.md
- CI run:
  https://github.com/maho0638/inputshield-genlayer/actions/runs/37728828887
- Studionet proof run:
  https://github.com/maho0638/inputshield-genlayer/actions/runs/37728828915
- Explorer contract:
  https://explorer-studio.genlayer.com/address/0xEe0c544Dc9a1657740bAaeD9705c920ad0A62e93
- Benign ALLOW transaction:
  https://explorer-studio.genlayer.com/tx/0x850a8f1b6170aa112546e8bc5755784bea8494a604ae73f2c007300d8675adfe
- Injection BLOCK transaction:
  https://explorer-studio.genlayer.com/tx/0xa8154f152e06059d06601f439990253df7f59a5704f733e71d41b6af555be22d

## Status

READY FOR PORTAL SUBMISSION

Verified release:
- source commit: `aee50fcdb19f4e24af5c23fbcea1f14de313b1a6`
- 17/17 direct tests PASS
- GenVM lint PASS
- Studionet live proof PASS
- benign => ALLOW
- explicit injection => BLOCK
- evidence hash binding => PASS
- stale ALLOW expiry => implemented
- retrieval failure => REVIEW
