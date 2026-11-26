from __future__ import annotations

import argparse
import json
from aira_airdrop_testnet_qa_scout_untuk_protokol_l2.core import EVMCalldataFirewall


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='evm-firewall')
    parser.add_argument('--to', default='0xC6F1Cd687B368E76E613a50de38fe6AF33e75202')
    parser.add_argument('--data', default='0x4e71d92d')
    parser.add_argument('--value-wei', type=int, default=0)
    args = parser.parse_args(argv)
    res = EVMCalldataFirewall().inspect(args.to, args.data, value_wei=args.value_wei)
    print(json.dumps(res.to_dict(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
