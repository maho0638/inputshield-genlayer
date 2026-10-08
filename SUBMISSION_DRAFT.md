# Portal Submission Draft

## Category
Developer -> Intelligent Contracts

## Title
InputShield — Consensus Prompt-Injection Firewall for GenLayer

## Notes / Description (935/1000)
InputShield is a reusable GenLayer Intelligent Contract that protects downstream agents and contracts from prompt injection embedded in untrusted text and live HTTPS pages. Validators independently fetch and classify evidence and require agreement on the exact evidence hash and deterministic final ALLOW/REVIEW/BLOCK action; nearby scores cannot cross an enforcement threshold. High-impact secret, tool and wallet requests are BLOCKED, malformed outputs fail closed, and unavailable sources require REVIEW. Each scan stores a SHA-256 evidence hash and expires after one hour; expired results cannot return ALLOW through any action API. Live Studionet proof: benign content ALLOW, adversarial injection BLOCK, with independent validator agreement. Verification: 19/19 direct tests PASS, GenVM lint PASS, and live Studionet deployment/execution PASS. Includes contract source, adversarial regressions, security model and reviewer guide.

## Evidence

- GitHub Repository:
  https://github.com/maho0638/inputshield-genlayer
- Immutable contract source:
  https://github.com/maho0638/inputshield-genlayer/blob/126305282f53c3d629a7d4679095ee0845f41804/contracts/input_shield.py
- Immutable direct tests:
  https://github.com/maho0638/inputshield-genlayer/blob/126305282f53c3d629a7d4679095ee0845f41804/tests/direct/test_input_shield.py
- Reviewer guide:
  https://github.com/maho0638/inputshield-genlayer/blob/main/docs/REVIEWER_GUIDE.md
- CI run:
  https://github.com/maho0638/inputshield-genlayer/actions/runs/37730228366
- Studionet proof run:
  https://github.com/maho0638/inputshield-genlayer/actions/runs/37730228386
- Explorer contract:
  https://explorer-studio.genlayer.com/address/0x2450bd6D294C9DE72ec2CA6f924C15fca7f9A116
- Benign ALLOW transaction:
  https://explorer-studio.genlayer.com/tx/0x462040fdefeb25d265090259a8d69119887c015f834786b27bdf2230d37574fd
- Injection BLOCK transaction:
  https://explorer-studio.genlayer.com/tx/0xb25a1694301389f4374591c98eaaca81447eb5665da29413e74577176260a07a

## Status
READY FOR PORTAL SUBMISSION

Verified code commit: 126305282f53c3d629a7d4679095ee0845f41804
19/19 direct tests PASS; GenVM lint PASS; integration syntax PASS
Studionet live proof PASS: benign ALLOW score 0 confidence 98; injection BLOCK score 100 high-impact 1
