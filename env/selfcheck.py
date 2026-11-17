"""실험 환경 자체 점검 (P1).

새 VM/WSL을 세팅한 사람이 "환경이 제대로 됐나"를 30초 안에 확인하는 용도입니다.
Mininet 실험망을 잠깐 띄워서 아래를 차례로 확인하고 OK/FAIL을 출력합니다.

  1. 필수 프로그램 설치 여부
  2. 호스트 간 ping (h1 -> gw, h1 -> h2)
  3. DNS (게이트웨이 dnsmasq가 *.lab.test 에 응답)
  4. DHCP (dhcp 서버가 주소를 제안하는지)

실행 (project/ 폴더에서, root 필요):
    sudo python3 env/selfcheck.py
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

REQUIRED = ["mn", "ovs-vsctl", "dnsmasq", "nmap", "hping3", "iperf3",
            "tcpdump", "nslookup", "wget"]

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def main() -> int:
    if os.geteuid() != 0:
        sys.exit("root 권한이 필요합니다: sudo python3 env/selfcheck.py")

    missing = [c for c in REQUIRED if shutil.which(c) is None]
    check("필수 프로그램", not missing, "없음: " + ", ".join(missing) if missing else "")
    try:
        import scapy  # noqa: F401
        check("scapy", True, scapy.__version__)
    except ImportError:
        check("scapy", False, "sudo apt install python3-scapy")
    if missing:
        return 1

    from mininet.clean import cleanup
    from mininet.net import Mininet
    from mininet.node import OVSController

    from env.hosts import one
    from env.run import DHCP_POOL, configure_network
    from env.topo import LanTopo

    cleanup()
    net = Mininet(topo=LanTopo(), controller=OVSController, autoSetMacs=False)
    net.start()
    procs: list = []
    try:
        configure_network(net, procs)
        net.waitConnected(timeout=15)
        time.sleep(1.5)  # dnsmasq 기동 대기

        gw = one("gateway")
        h1, h2 = net.get("h1"), net.get("h2")

        out = h1.cmd(f"ping -c 2 -W 1 {gw.ip}")
        check("ping h1 -> gw", " 0% packet loss" in out)
        out = h1.cmd("ping -c 2 -W 1 10.0.0.2")
        check("ping h1 -> h2", " 0% packet loss" in out)

        out = h1.cmd(f"nslookup www.lab.test {gw.ip}")
        check("DNS (*.lab.test)", gw.ip in out.split("Name:")[-1] if "Name:" in out else False)

        # DHCP: h1에서 DISCOVER 방송 -> OFFER 받는지 (nmap 스크립트)
        out = h1.cmd("nmap --script broadcast-dhcp-discover -e h1-eth0 2>&1")
        offered = f"Server Identifier: {one('dhcp_server').ip}" in out
        in_pool = DHCP_POOL[0].rsplit(".", 1)[0] in out and "IP Offered" in out
        check("DHCP 서버 OFFER", offered and in_pool,
              "" if offered and in_pool else out.strip()[-200:])
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        net.stop()

    bad = [r for r in results if not r[1]]
    print("\n전부 통과" if not bad else f"\n실패 {len(bad)}건")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
