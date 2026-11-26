"""Static EVM calldata inspector for autonomous wallet & AI agent transaction safety."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

DANGEROUS_SELECTORS: dict[str, str] = {
    "095ea7b3": "ERC-20/721 approve(address,uint256)",
    "a9059cbb": "ERC-20 transfer(address,uint256)",
    "23b872dd": "ERC-20/721 transferFrom(address,address,uint256)",
    "a22cb465": "ERC-721/1155 setApprovalForAll(address,bool)",
    "d505accf": "EIP-2612 permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
}


@dataclass(frozen=True)
class CalldataInspection:
    allowed: bool
    risk_level: str
    selector: str
    matched_rule: str
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EVMCalldataFirewall:
    """Inspects EVM calldata and native value limits before transaction signing."""

    def __init__(
        self,
        *,
        max_native_wei: int = 10_000_000_000_000_000,
        block_unlimited_approval: bool = True,
        block_spend_selectors: bool = True,
    ) -> None:
        self.max_native_wei = max(0, int(max_native_wei))
        self.block_unlimited_approval = bool(block_unlimited_approval)
        self.block_spend_selectors = bool(block_spend_selectors)

    def inspect(self, to_address: str, data_hex: str = "0x", value_wei: int = 0) -> CalldataInspection:
        reasons: list[str] = []
        risk = "low"
        matched = "benign_call"
        addr = str(to_address or "").strip()
        if not _ADDR_RE.match(addr):
            reasons.append("invalid_target_address")
            risk = "critical"
        elif addr.lower() == ZERO_ADDRESS:
            reasons.append("zero_address_burn_target")
            risk = "critical"
        if int(value_wei) < 0:
            reasons.append("negative_value_wei")
            risk = "critical"
        elif int(value_wei) > self.max_native_wei:
            reasons.append("native_value_exceeds_policy_cap")
            risk = "high"
        clean = str(data_hex or "0x").strip()
        if clean.startswith(("0x", "0X")):
            clean = clean[2:]
        selector = clean[:8].lower() if len(clean) >= 8 else ""
        if selector in DANGEROUS_SELECTORS:
            matched = DANGEROUS_SELECTORS[selector]
            if self.block_spend_selectors:
                reasons.append(f"blocked_spend_selector:{selector}")
                risk = "high"
            if selector == "095ea7b3" and len(clean) >= 136 and self.block_unlimited_approval:
                amount_int = int(clean[72:136], 16)
                if amount_int >= (1 << 255):
                    reasons.append("unlimited_erc20_approval")
                    risk = "critical"
        return CalldataInspection(
            allowed=(len(reasons) == 0),
            risk_level=risk,
            selector=selector,
            matched_rule=matched,
            reasons=reasons,
        )
