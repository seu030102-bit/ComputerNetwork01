"""정상 트래픽에 섞은 공격 (w12, ★ 회피) — 격리 실험용.

공격자가 보통 클라이언트처럼 웹/DNS/동영상/파일 요청을 계속 보내는 동시에,
그 사이에 저속 공격 패킷을 끼워 넣습니다. 호스트별 패킷 수·종류만 보는
탐지기가 "공격자 호스트도 정상 사용자처럼 보인다"는 이유로 공격을 놓치는지
확인하는 것이 목적입니다.

이 스크립트는 패킷을 "보내기만" 합니다. --base로 숨길 공격을 고릅니다
(기본 port_scan). 각 공격은 이미 있는 느린(회피) 설정을 그대로 재사용합니다.
배경 트래픽은 env/traffic/normal.py의 client()를 그대로 씁니다.

run.py가 Mininet 공격자 호스트 안에서 실행합니다. 직접 실행은 labguard가 막습니다.

    python env/attacks/mixed_attack.py --iface h4-eth0 --target-ip 10.0.0.1 \
        --http-port 8000 --base port_scan --duration 60
"""

from __future__ import annotations

import threading

from env.attacks.labguard import require_lab


def _decoy_traffic(duration: float, http_port: int, seed: int) -> None:
    """공격자 호스트가 보통 클라이언트처럼 보이게 하는 배경 트래픽."""
    from env.traffic.normal import client

    client(duration, http_port, seed)


def _base_arp_spoof(iface: str, target_ip: str, duration: float) -> None:
    from env.attacks.arp_spoof import run

    # 느린(회피) 설정: 초당 0.2개
    run(iface, spoof_ip="10.0.0.254", victim_ip=target_ip, rate=0.2,
        duration=duration, gratuitous=False)


def _base_syn_flood(iface: str, target_ip: str, duration: float) -> None:
    from env.attacks.syn_flood import run

    # 느린(회피) 설정: 초당 5개
    run(iface, target_ip=target_ip, target_port=80, rate=5, duration=duration)


def _base_port_scan(iface: str, target_ip: str, duration: float) -> None:
    from env.attacks.port_scan import run_scapy

    # 느린(회피) 설정: 포트 순서를 섞고 패킷 사이를 띄움
    run_scapy(iface, target_ip, ports="1-200", duration=duration, evasive=True)


BASES = {
    "arp_spoof": _base_arp_spoof,
    "syn_flood": _base_syn_flood,
    "port_scan": _base_port_scan,
}


def run(iface: str, target_ip: str, http_port: int, base: str,
        duration: float, seed: int) -> None:
    decoy = threading.Thread(
        target=_decoy_traffic, args=(duration, http_port, seed), daemon=True)
    decoy.start()
    BASES[base](iface, target_ip, duration)
    decoy.join(timeout=5)
    print(f"mixed_attack 끝: base={base}, target={target_ip} "
          f"(정상 트래픽과 동시 실행, 배경 종료 대기 최대 5초)")


def main() -> None:
    require_lab()
    import argparse
    p = argparse.ArgumentParser(description="정상 트래픽에 섞은 공격 (격리 실험용)")
    p.add_argument("--iface", required=True)
    p.add_argument("--target-ip", required=True)
    p.add_argument("--http-port", type=int, default=8000)
    p.add_argument("--base", choices=sorted(BASES), default="port_scan",
                   help="배경 트래픽 뒤에 숨길 공격")
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--seed", type=int, default=99, help="배경 트래픽 난수 시드")
    a = p.parse_args()
    if a.base not in BASES:
        raise SystemExit(f"없는 base: {a.base}. 가능: {sorted(BASES)}")
    run(a.iface, a.target_ip, a.http_port, a.base, a.duration, a.seed)


if __name__ == "__main__":
    main()
