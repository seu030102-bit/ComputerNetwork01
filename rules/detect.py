"""규칙 기반 탐지기 (P4).

실험 폴더의 features_1s.jsonl / features_5s.jsonl 을 읽어 공격을 판정하고
alerts_rule.jsonl 을 만듭니다. 형식은 docs/data-format.md 2.4.

    python3 rules/detect.py data/runs/<run_id>

규칙:
  R1 arp_conflict    : feat_host.arp_ip_conflicts > 0
  R2 arp_unsolicited : feat_host.arp_rep_unsolicited ≥ 임계치 (5초창)
  R3 mac_flood       : feat_seg.new_src_macs ≥ 임계치 (1초창), DHCP 신호 없을 때
  R4 dhcp_rogue      : 정상 dhcp_servers가 아닌 MAC이 dhcp_offer/ack 전송
  R5 dhcp_starve     : feat_seg.dhcp_discover 또는 dhcp_chaddrs 급증 (1초창)
  R6 port_scan       : feat_host.dst_ports ≥ 임계치
  R7 syn_flood       : feat_host.tcp_syn 높고 dst_ports 낮음

같은 (공격자, 공격)은 10초에 한 번만 경보(data-format 2.4).
임계치는 w11_lab 데이터(정상 대비)로 잡았습니다.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import make, read, write  # noqa: E402

# 임계치 (w11_lab: 정상 dst_ports≤24, tcp_syn≤16 / 공격은 훨씬 큼)
ARP_UNSOLICITED_MIN = 5
MAC_FLOOD_NEW_MACS = 15
DHCP_STARVE_DISCOVER = 15   # 1초창; 정상은 0, starve p90≈27
DHCP_STARVE_CHADDRS = 5     # 1초창; 정상 0, starve p90≈9
PORT_SCAN_DST_PORTS = 40    # 정상 max 24, 스캔은 수백~1000
PORT_SCAN_MIN_SYN = 15      # SYN flood 피해자(dst_ports↑·tcp_syn↓) 오탐 완화
SYN_FLOOD_TCP_SYN = 25      # 정상 max 16, flood 공격자 p50≈32
SYN_FLOOD_MAX_PORTS = 5     # 소수 포트로 SYN 폭주 (스캔과 구분)
DEDUP_SEC = 10.0


class Deduper:
    def __init__(self, window: float = DEDUP_SEC):
        self.window = window
        self.last: dict[tuple, float] = {}

    def allow(self, key: tuple, ts: float) -> bool:
        prev = self.last.get(key)
        if prev is not None and ts - prev < self.window:
            return False
        self.last[key] = ts
        return True


def _load_meta(run_dir: Path) -> dict:
    f = run_dir / "meta.json"
    if not f.exists():
        return {}
    return json.loads(f.read_text(encoding="utf-8"))


def detect(run_dir: Path) -> None:
    feats = []
    for w in (1, 5):
        f = run_dir / f"features_{w}s.jsonl"
        if f.exists():
            feats += list(read(f))
    if not feats:
        sys.exit(f"특징 파일 없음: {run_dir} (먼저 capture/extract.py 실행)")
    feats.sort(key=lambda r: r["ts"])

    meta = _load_meta(run_dir)
    legit_dhcp = {m.lower() for m in (meta.get("dhcp_servers") or [])}

    dedup = Deduper()
    n = 0
    out = run_dir / "alerts_rule.jsonl"
    with open(out, "w", encoding="utf-8") as fh:
        for r in feats:
            alert = None
            if r["type"] == "feat_host":
                alert = _host_alert(r, legit_dhcp, dedup)
            elif r["type"] == "feat_seg":
                alert = _seg_alert(r, dedup)
            if alert:
                write(fh, alert)
                n += 1
    print(f"[detect] {out.name}: 경보 {n}개")


def _host_alert(r: dict, legit_dhcp: set[str], dedup: Deduper):
    host = r["host"]
    mac = (host.get("mac") or "").lower()

    # R1: ARP 충돌
    if r.get("arp_ip_conflicts", 0) > 0:
        if dedup.allow(("arp_spoof", mac), r["ts"]):
            return _mk(r, host, "arp_conflict", attack="arp_spoof", score=1.0,
                       summary=f"{mac}가 다른 호스트의 IP를 사칭(ARP 충돌)",
                       evidence={"arp_ip_conflicts": r["arp_ip_conflicts"],
                                 "arp_rep_unsolicited": r.get("arp_rep_unsolicited", 0)})

    # R2: 미요청 ARP 응답 다발 (5초 창)
    if (r.get("win") == 5
            and r.get("arp_rep_unsolicited", 0) >= ARP_UNSOLICITED_MIN):
        if dedup.allow(("arp_spoof", mac), r["ts"]):
            return _mk(r, host, "arp_unsolicited", attack="arp_spoof", score=0.8,
                       summary=f"{mac}가 요청 없는 ARP 응답을 "
                               f"{r['arp_rep_unsolicited']}회 전송",
                       evidence={"arp_rep_unsolicited": r["arp_rep_unsolicited"]})

    # R4: 가짜 DHCP 서버 (정상 목록에 없는 MAC이 OFFER/ACK)
    offers = int(r.get("dhcp_offer") or 0) + int(r.get("dhcp_ack") or 0)
    if offers > 0 and mac and mac not in legit_dhcp:
        if dedup.allow(("dhcp_rogue", mac), r["ts"]):
            return _mk(r, host, "dhcp_rogue", attack="dhcp_rogue", score=1.0,
                       summary=f"{mac}가 정상 DHCP 목록 밖에서 "
                               f"OFFER/ACK {offers}회 전송",
                       evidence={"dhcp_offer": r.get("dhcp_offer", 0),
                                 "dhcp_ack": r.get("dhcp_ack", 0),
                                 "legit_dhcp_servers": sorted(legit_dhcp)})

    dst_ports = int(r.get("dst_ports") or 0)
    tcp_syn = int(r.get("tcp_syn") or 0)

    # R6: 포트 스캔 (목적지 포트 폭증 + SYN도 어느 정도)
    if dst_ports >= PORT_SCAN_DST_PORTS and tcp_syn >= PORT_SCAN_MIN_SYN:
        if dedup.allow(("port_scan", mac), r["ts"]):
            return _mk(r, host, "port_scan", attack="port_scan", score=1.0,
                       summary=f"{mac}가 목적지 포트 {dst_ports}개로 스캔",
                       evidence={"dst_ports": dst_ports, "tcp_syn": tcp_syn,
                                 "tcp_rst_in": r.get("tcp_rst_in", 0)})

    # R7: SYN flood (SYN 많음 + 포트 소수 → 스캔과 구분)
    if tcp_syn >= SYN_FLOOD_TCP_SYN and dst_ports <= SYN_FLOOD_MAX_PORTS:
        if dedup.allow(("syn_flood", mac), r["ts"]):
            return _mk(r, host, "syn_flood", attack="syn_flood", score=1.0,
                       summary=f"{mac}가 SYN {tcp_syn}개 "
                               f"(포트 {dst_ports}개) 전송",
                       evidence={"tcp_syn": tcp_syn, "dst_ports": dst_ports,
                                 "dst_ips": r.get("dst_ips", 0)})

    return None


def _seg_alert(r: dict, dedup: Deduper):
    seg = {"mac": None, "ip": None, "sw": r.get("sw"), "port": r.get("port")}
    discover = int(r.get("dhcp_discover") or 0)
    chaddrs = int(r.get("dhcp_chaddrs") or 0)
    new_macs = int(r.get("new_src_macs") or 0)

    # R5: DHCP 고갈 (가짜 chaddr DISCOVER 폭주) — MAC 플러딩보다 먼저
    if (r.get("win") == 1
            and (discover >= DHCP_STARVE_DISCOVER
                 or chaddrs >= DHCP_STARVE_CHADDRS)):
        key = ("dhcp_starve", r.get("sw"), r.get("port"))
        if dedup.allow(key, r["ts"]):
            return _mk(r, seg, "dhcp_starve", attack="dhcp_starve", score=1.0,
                       summary=f"구간(sw={r.get('sw')},port={r.get('port')})에서 "
                               f"DHCP DISCOVER {discover}/chaddr {chaddrs} 급증",
                       evidence={"dhcp_discover": discover,
                                 "dhcp_chaddrs": chaddrs,
                                 "new_src_macs": new_macs})

    # R3: MAC 플러딩 (DHCP 고갈 신호가 없을 때만)
    if r.get("win") == 1 and new_macs >= MAC_FLOOD_NEW_MACS:
        key = ("mac_flood", r.get("sw"), r.get("port"))
        if dedup.allow(key, r["ts"]):
            return _mk(r, seg, "mac_flood", attack="mac_flood", score=1.0,
                       summary=f"구간(sw={r.get('sw')},port={r.get('port')})에서 "
                               f"새 MAC {new_macs}개 급증(MAC 플러딩)",
                       evidence={"new_src_macs": new_macs,
                                 "src_macs": r.get("src_macs", 0)})

    return None


_SEQ = [0]


def _mk(feat, attacker, source, *, attack, score, summary, evidence):
    _SEQ[0] += 1
    # 오프라인: 경보 시각 = 근거 특징 창이 끝난 시각
    return make("alert", ts=feat["ts"], alert_id=f"rule-{_SEQ[0]:06d}",
                detector="rule", source=source, attack=attack, score=score,
                attacker=attacker, victim=None, feature_ts=feat["ts"],
                win=feat["win"], summary=summary, evidence=evidence)


def main() -> None:
    p = argparse.ArgumentParser(description="규칙 기반 탐지기 (P4)")
    p.add_argument("run_dir")
    a = p.parse_args()
    detect(Path(a.run_dir))


if __name__ == "__main__":
    main()
