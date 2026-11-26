"""EVM Calldata Firewall & Transaction Guard (aira_airdrop_testnet_qa_scout_untuk_protokol_l2)."""
from __future__ import annotations

from aira_airdrop_testnet_qa_scout_untuk_protokol_l2.core import CalldataInspection, DANGEROUS_SELECTORS, EVMCalldataFirewall

__version__ = "0.1.0"
__all__ = ["CalldataInspection", "DANGEROUS_SELECTORS", "EVMCalldataFirewall", "__version__"]
