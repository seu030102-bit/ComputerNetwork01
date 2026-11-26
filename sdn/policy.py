"""경보 → 차단 대상 결정 (OS-Ken 불필요, 단위 테스트용).

data-format.md: SDN 차단은 endpoint의 mac/ip/sw/port 네 값만 본다.
- MAC이 있으면 eth_src 기준 drop (포트가 있으면 in_port도 같이 매칭)
- MAC이 없고 sw/port만 있으면(mac_flood, dhcp_starve) in_port 기준 drop
"""

from __future__ import annotations

from common.records import endpoint, make, now

# OpenFlow 우선순위: table-miss=0, L2 학습=1, 차단은 그보다 높음
DROP_PRIORITY = 100
DEDUP_SEC = 10.0

# Mininet s1 → datapath id (LanTopo 기본)
SW_TO_DPID = {"s1": 1}


def dpid_for(sw: str | None) -> int | None:
    if not sw:
        return None
    if sw in SW_TO_DPID:
        return SW_TO_DPID[sw]
    # "s1" / "1" / 숫자 문자열
    if sw.isdigit():
        return int(sw)
    return None


def block_spec(alert: dict) -> dict | None:
    """경보에서 OpenFlow drop에 쓸 명세를 뽑는다. 차단 불가면 None.

    반환 예:
      {"dpid": 1, "mac": "00:..:04", "port": 4, "match": "mac+port",
       "reason": "alert rule-000001 arp_spoof → drop eth_src=..,in_port=4"}
    """
    if alert.get("type") != "alert":
        return None
    atk = alert.get("attacker") or {}
    mac = atk.get("mac")
    port = atk.get("port")
    sw = atk.get("sw")
    dpid = dpid_for(sw) or 1  # sw 모르면 실험망 기본 s1

    if mac:
        kind = "mac+port" if port is not None else "mac"
        bits = [f"eth_src={mac}"]
        if port is not None:
            bits.append(f"in_port={port}")
        reason = (
            f"alert {alert.get('alert_id')} {alert.get('attack')} → drop "
            + ",".join(bits)
        )
        return {
            "dpid": dpid,
            "mac": mac.lower(),
            "port": port,
            "match": kind,
            "reason": reason,
            "target": endpoint(mac=mac, ip=atk.get("ip"), sw=sw or "s1", port=port),
        }

    if port is not None:
        reason = (
            f"alert {alert.get('alert_id')} {alert.get('attack')} → drop "
            f"in_port={port} (MAC 미상, 포트 차단)"
        )
        return {
            "dpid": dpid,
            "mac": None,
            "port": int(port),
            "match": "port",
            "reason": reason,
            "target": endpoint(mac=None, ip=atk.get("ip"), sw=sw or "s1", port=int(port)),
        }

    return None


def make_block_action(
    alert: dict,
    spec: dict,
    *,
    ok: bool,
    install_ms: float,
    ts: float | None = None,
    expires_ts: float | None = None,
) -> dict:
    return make(
        "action",
        ts=now() if ts is None else ts,
        action="block",
        target=spec["target"],
        alert_id=alert.get("alert_id"),
        reason=spec["reason"],
        expires_ts=expires_ts,
        ok=ok,
        install_ms=float(install_ms),
    )


def dedup_key(spec: dict) -> tuple:
    return (spec.get("dpid"), spec.get("mac"), spec.get("port"), spec.get("match"))


class BlockDeduper:
    """같은 대상 차단은 DEDUP_SEC 안에 한 번만 기록/설치."""

    def __init__(self, window: float = DEDUP_SEC):
        self.window = window
        self._last: dict[tuple, float] = {}

    def allow(self, spec: dict, ts: float) -> bool:
        key = dedup_key(spec)
        prev = self._last.get(key)
        if prev is not None and ts - prev < self.window:
            return False
        self._last[key] = ts
        return True
