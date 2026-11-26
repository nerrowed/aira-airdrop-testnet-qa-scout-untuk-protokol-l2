import json
from aira_airdrop_testnet_qa_scout_untuk_protokol_l2.core import EVMCalldataFirewall, ZERO_ADDRESS
from aira_airdrop_testnet_qa_scout_untuk_protokol_l2.cli import main


def test_benign_calldata_allowed() -> None:
    fw = EVMCalldataFirewall()
    res = fw.inspect('0xC6F1Cd687B368E76E613a50de38fe6AF33e75202', '0x4e71d92d', value_wei=100)
    assert res.allowed is True and res.risk_level == 'low'


def test_unlimited_erc20_approve_blocked_as_critical() -> None:
    fw = EVMCalldataFirewall()
    payload = '0x095ea7b3' + ('00' * 12) + ('11' * 20) + ('ff' * 32)
    res = fw.inspect('0xC6F1Cd687B368E76E613a50de38fe6AF33e75202', payload, value_wei=0)
    assert res.allowed is False and res.risk_level == 'critical'
    assert 'unlimited_erc20_approval' in res.reasons


def test_excessive_value_and_zero_addr_blocked_and_cli_runs(capsys) -> None:
    fw = EVMCalldataFirewall(max_native_wei=1000)
    assert fw.inspect('0xC6F1Cd687B368E76E613a50de38fe6AF33e75202', '0x', value_wei=5000).allowed is False
    assert fw.inspect(ZERO_ADDRESS, '0x', value_wei=0).allowed is False
    assert main(['--to', '0xC6F1Cd687B368E76E613a50de38fe6AF33e75202', '--data', '0x4e71d92d']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['allowed'] is True
