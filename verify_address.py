"""链上验证：仅在候选命中后查询 USDT 余额。"""

from __future__ import annotations

import os
from typing import Any

import requests

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_DECIMALS = 1_000_000
TRONGRID = "https://api.trongrid.io"
TRONSCAN_TOKENS = "https://apilist.tronscanapi.com/api/account/tokens"


def _trongrid_headers() -> dict[str, str]:
    h: dict[str, str] = {"User-Agent": "tron-collider/1.0"}
    key = os.environ.get("TRONGRID_API_KEY") or os.environ.get("TRON_PRO_API_KEY")
    if key:
        h["TRON-PRO-API-KEY"] = key
    return h


def _tronscan_headers() -> dict[str, str]:
    h: dict[str, str] = {"User-Agent": "tron-collider/1.0"}
    scan = os.environ.get("TRONSCAN_API_KEY")
    if scan:
        h["TRON-PRO-API-KEY"] = scan
    return h


def fetch_usdt_balance_tronscan(session: requests.Session, address: str) -> float | None:
    params = {
        "address": address,
        "start": 0,
        "limit": 1,
        "token": USDT_CONTRACT,
        "show": 1,
        "hidden": 1,
    }
    resp = session.get(
        TRONSCAN_TOKENS, params=params, headers=_tronscan_headers(), timeout=30
    )
    if resp.status_code == 404:
        return 0.0
    resp.raise_for_status()
    data = resp.json()
    tokens = data.get("data") or data.get("tokens") or []
    if not tokens:
        return 0.0
    raw = int(tokens[0].get("balance") or tokens[0].get("quantity") or 0)
    return raw / USDT_DECIMALS


def fetch_account_exists_trongrid(session: requests.Session, address: str) -> dict[str, Any]:
    resp = session.post(
        f"{TRONGRID}/wallet/getaccount",
        json={"address": address, "visible": True},
        headers=_trongrid_headers(),
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _parse_trc20_balances(trc20_field: object) -> dict[str, float]:
    out: dict[str, float] = {}
    if not trc20_field:
        return out
    entries = trc20_field if isinstance(trc20_field, list) else [trc20_field]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for contract, raw in entry.items():
            try:
                val = int(raw)
            except (TypeError, ValueError):
                continue
            if val <= 0:
                continue
            if contract == USDT_CONTRACT:
                out["USDT"] = val / USDT_DECIMALS
            else:
                out[str(contract)] = float(val)
    return out


def fetch_balances_trongrid(
    session: requests.Session, address: str
) -> dict[str, Any]:
    resp = session.get(
        f"{TRONGRID}/v1/accounts/{address}",
        headers=_trongrid_headers(),
        timeout=30,
    )
    if resp.status_code == 404:
        return _empty_balance_result(address, activated=False)
    resp.raise_for_status()
    data = resp.json().get("data") or []
    if not data:
        return _empty_balance_result(address, activated=False)
    item = data[0]
    trx_sun = int(item.get("balance") or 0)
    trc20 = _parse_trc20_balances(item.get("trc20"))
    usdt = float(trc20.get("USDT") or 0.0)
    has_trc20 = usdt > 0 or any(v > 0 for v in trc20.values())
    return {
        "address": address,
        "activated": trx_sun > 0 or bool(item.get("create_time")) or has_trc20,
        "trx_sun": trx_sun,
        "trx": trx_sun / 1_000_000,
        "usdt_balance": usdt,
        "trc20": {k: v for k, v in trc20.items() if k != "USDT"},
    }


def _empty_balance_result(address: str, *, activated: bool) -> dict[str, Any]:
    return {
        "address": address,
        "activated": activated,
        "trx_sun": 0,
        "trx": 0.0,
        "usdt_balance": 0.0,
        "trc20": {},
    }


def fetch_balances_tronscan_hybrid(
    session: requests.Session, address: str
) -> dict[str, Any]:
    base = _empty_balance_result(address, activated=False)
    try:
        acct = fetch_account_exists_trongrid(session, address)
        if acct:
            base["activated"] = True
            trx_sun = int(acct.get("balance") or 0)
            base["trx_sun"] = trx_sun
            base["trx"] = trx_sun / 1_000_000
    except requests.RequestException:
        pass
    try:
        usdt = fetch_usdt_balance_tronscan(session, address)
        if usdt is not None and usdt > 0:
            base["usdt_balance"] = usdt
    except requests.RequestException:
        pass
    return base


def has_positive_balance(
    balances: dict[str, Any],
    *,
    asset: str = "any",
) -> bool:
    trx_sun = int(balances.get("trx_sun") or 0)
    usdt = float(balances.get("usdt_balance") or 0.0)
    trc20 = balances.get("trc20") or {}
    if asset == "trx":
        return trx_sun > 0
    if asset == "usdt":
        return usdt > 0
    if trx_sun > 0 or usdt > 0:
        return True
    return any(float(v) > 0 for v in trc20.values())


def fetch_account_balances(
    session: requests.Session,
    address: str,
    *,
    backend: str = "trongrid",
) -> dict[str, Any]:
    if backend == "tronscan":
        return fetch_balances_tronscan_hybrid(session, address)
    return fetch_balances_trongrid(session, address)


def verify_candidate(
    session: requests.Session,
    address: str,
    *,
    backend: str = "tronscan",
) -> dict[str, Any]:
    if backend == "trongrid":
        acct = fetch_account_exists_trongrid(session, address)
        return {
            "address": address,
            "activated": bool(acct),
            "account": acct,
        }
    usdt = fetch_usdt_balance_tronscan(session, address)
    return {
        "address": address,
        "usdt_balance": usdt,
        "confirmed_in_target_set": usdt is not None and usdt > 0,
    }
