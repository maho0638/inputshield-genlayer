"""Live Studionet deployment and end-to-end verification for InputShield."""

import pytest
from gltest import get_contract_factory
from gltest.assertions import tx_execution_succeeded


def _field(value, name):
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name)


@pytest.mark.integration
def test_inputshield_live_studionet():
    factory = get_contract_factory("InputShield")
    contract = factory.deploy(consensus_max_rotations=2)

    print(f"INPUTSHIELD_CONTRACT_ADDRESS={contract.address}", flush=True)

    benign_id = "live-benign-v1"
    benign_url = (
        "https://raw.githubusercontent.com/maho0638/inputshield-genlayer/"
        "main/fixtures/benign.txt"
    )
    benign_tx = contract.scan_url(
        args=[benign_id, benign_url]
    ).transact(
        wait_interval=10000,
        wait_retries=40,
    )
    assert tx_execution_succeeded(benign_tx)
    print(f"INPUTSHIELD_BENIGN_TX={benign_tx}", flush=True)

    benign = contract.get_scan(args=[benign_id]).call()
    benign_action = str(_field(benign, "action"))
    benign_score = int(_field(benign, "risk_score"))
    benign_confidence = int(_field(benign, "confidence"))
    print(f"INPUTSHIELD_BENIGN_ACTION={benign_action}", flush=True)
    print(f"INPUTSHIELD_BENIGN_SCORE={benign_score}", flush=True)
    print(f"INPUTSHIELD_BENIGN_CONFIDENCE={benign_confidence}", flush=True)
    assert benign_action == "ALLOW"
    assert benign_score < 30
    assert benign_confidence >= 60

    malicious_id = "live-injection-v1"
    malicious_url = (
        "https://raw.githubusercontent.com/maho0638/inputshield-genlayer/"
        "main/fixtures/prompt_injection.txt"
    )
    malicious_tx = contract.scan_url(
        args=[malicious_id, malicious_url]
    ).transact(
        wait_interval=10000,
        wait_retries=40,
    )
    assert tx_execution_succeeded(malicious_tx)
    print(f"INPUTSHIELD_MALICIOUS_TX={malicious_tx}", flush=True)

    malicious = contract.get_scan(args=[malicious_id]).call()
    malicious_action = str(_field(malicious, "action"))
    malicious_high_impact = int(_field(malicious, "high_impact"))
    malicious_score = int(_field(malicious, "risk_score"))
    print(f"INPUTSHIELD_MALICIOUS_ACTION={malicious_action}", flush=True)
    print(f"INPUTSHIELD_MALICIOUS_HIGH_IMPACT={malicious_high_impact}", flush=True)
    print(f"INPUTSHIELD_MALICIOUS_SCORE={malicious_score}", flush=True)

    assert malicious_action == "BLOCK"
    assert malicious_high_impact == 1
    assert malicious_score >= 70

    assert contract.get_policy_version().call() == "inputshield-v1"
