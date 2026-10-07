# Portal Submission Draft

## Category

Developer -> Intelligent Contracts

## Title

InputShield — Consensus Prompt-Injection Firewall for GenLayer

## Notes / description

InputShield is a reusable GenLayer Intelligent Contract security primitive that screens untrusted text and public web content before downstream contracts or agents rely on it. It detects prompt-injection and agent-control attempts such as instruction overrides, role impersonation, secret extraction, tool execution, wallet signing, value transfer, and contract-mutation requests. Validators independently re-run the security classification and must agree on the deterministic ALLOW / REVIEW / BLOCK outcome. Numeric drift is accepted only when it preserves the same final action, preventing threshold-crossing consensus bugs. High-impact and malformed outputs fail closed. Verification: 14/14 direct tests PASS, GenVM lint PASS, and live Studionet proof PASS. Live benign content resolved ALLOW (score 0, confidence 98); explicit injection resolved BLOCK (high-impact 1, score 95).

## Evidence

- GitHub Repository:
  https://github.com/maho0638/inputshield-genlayer
- Immutable contract source:
  https://github.com/maho0638/inputshield-genlayer/blob/c0183412e94e0d133e41ce3b045864d0ddb3640d/contracts/input_shield.py
- Immutable direct tests:
  https://github.com/maho0638/inputshield-genlayer/blob/c0183412e94e0d133e41ce3b045864d0ddb3640d/tests/direct/test_input_shield.py
- Reviewer guide:
  https://github.com/maho0638/inputshield-genlayer/blob/c0183412e94e0d133e41ce3b045864d0ddb3640d/docs/REVIEWER_GUIDE.md
- CI run:
  https://github.com/maho0638/inputshield-genlayer/actions/runs/37694677972
- Studionet proof run:
  https://github.com/maho0638/inputshield-genlayer/actions/runs/37694678128
- Explorer contract:
  https://explorer-studio.genlayer.com/address/0xc2d1A30CDA9ad1688a3739dB72C60cEe55FDBb87
- Benign ALLOW transaction:
  https://explorer-studio.genlayer.com/tx/0xb476004ed7ee5ad6ad9e881b9fb5bc0088d9f60784eab29b9dab4de05a401dc2
- Injection BLOCK transaction:
  https://explorer-studio.genlayer.com/tx/0x2c4397c533377bebad67ecf6d091c6d68cbbdc5dd80c0577251a61e4a59d98d8

## Status

READY FOR PORTAL SUBMISSION

Verified release:
- source commit: `c0183412e94e0d133e41ce3b045864d0ddb3640d`
- 14/14 direct tests PASS
- GenVM lint PASS
- Studionet live proof PASS
- benign => ALLOW
- explicit injection => BLOCK
