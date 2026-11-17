"""从 TronGrid 已确认交易中恢复 secp256k1 公钥（需该地址曾签名上链）。"""

from __future__ import annotations

import hashlib
from typing import Any

import requests
from coincurve import PublicKey

from tron_crypto import address_to_payload_hex
from tron_crypto import public_key_uncompressed_to_address
from verify_address import _trongrid_headers

TRONGRID = "https://api.trongrid.io"


def _owner_hex_from_tx(tx: dict[str, Any]) -> str:
    contracts = (tx.get("raw_data") or {}).get("contract") or []
    if not contracts:
        return ""
    value = (contracts[0].get("parameter") or {}).get("value") or {}
    raw = value.get("owner_address") or value.get("account_address") or ""
    return str(raw).lower()


def _recover_pubkey_from_tx(tx: dict[str, Any]) -> bytes | None:
    raw_hex = tx.get("raw_data_hex")
    sigs = tx.get("signature") or []
    if not raw_hex or not sigs:
        return None
    raw = bytes.fromhex(str(raw_hex))
    digest = hashlib.sha256(raw).digest()
    sig = bytes.fromhex(str(sigs[0]))
    try:
        pub = PublicKey.from_signature_and_message(sig, digest, hasher=None)
    except Exception:
        return None
    return pub.format(compressed=False)[1:]


def recover_public_key_from_chain(
    session: requests.Session,
    address: str,
    *,
    max_tx_scan: int = 40,
) -> dict[str, Any]:
    """
    返回 dict：ok, public_key_hex, tx_id, message, …
    """
    address = address.strip()
    if not address.startswith("T"):
        return {"ok": False, "message": "请输入主网 T 开头地址"}
    try:
        want_hex = address_to_payload_hex(address)
    except ValueError as e:
        return {"ok": False, "message": f"地址无效：{e}"}

    url = f"{TRONGRID}/v1/accounts/{address}/transactions"
    resp = session.get(
        url,
        params={
            "limit": min(max(max_tx_scan, 1), 200),
            "only_confirmed": "true",
            "order_by": "block_timestamp,desc",
        },
        headers=_trongrid_headers(),
        timeout=45,
    )
    if resp.status_code == 404:
        return {
            "ok": False,
            "message": "账户无交易或不存在；仅收币、从未签名的地址无法恢复公钥",
        }
    resp.raise_for_status()
    txs = resp.json().get("data") or []
    if not txs:
        return {
            "ok": False,
            "message": "未找到已确认交易；从未主动签名的地址链上没有公钥可恢复",
        }

    scanned = 0
    for tx in txs:
        scanned += 1
        pub = _recover_pubkey_from_tx(tx)
        if pub is None:
            continue
        derived = public_key_uncompressed_to_address(pub)
        owner = _owner_hex_from_tx(tx)
        if derived == address or owner == want_hex:
            return {
                "ok": True,
                "address": address,
                "public_key_hex": pub.hex(),
                "derived_address": derived,
                "tx_id": tx.get("txID") or "",
                "owner_in_tx_hex": owner,
                "scanned_txs": scanned,
                "message": "已从签名交易恢复公钥（非从地址反推）",
            }

    return {
        "ok": False,
        "message": f"已扫描 {scanned} 笔交易，未能恢复与该地址匹配的公钥",
        "scanned_txs": scanned,
    }
