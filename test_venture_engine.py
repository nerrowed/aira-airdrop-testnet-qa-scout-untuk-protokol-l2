from venture_engine import evaluate_venture_readiness


def test_venture_readiness_with_aira_wallet() -> None:
    out = evaluate_venture_readiness('0xC6F1Cd687B368E76E613a50de38fe6AF33e75202', 18.0, 30.0)
    assert out['wallet_ready'] is True
    assert float(out['coverage_ratio']) > 0.0
