"""nmap 포트 스캔 (w11) — 격리 실험용.

공격자가 피해자의 여러 포트(또는 서브넷 전체)로 TCP SYN을 보내 열린 서비스를
찾습니다. 탐지기가 "짧은 시간에 한 호스트가 여러 포트/호스트로 접속 시도"
패턴을 잡는지 보는 것이 목적입니다.

기본은 nmap(-sS, SYN 스캔)을 씁니다. nmap이 없으면 scapy로 대체합니다
(--no-nmap). "--evasive" 옵션은 nmap의 느린 타이밍 템플릿(-T1)과 포트를
흩뿌려 보내는 옵션으로 탐지를 회피하려는 공격을 흉내냅니다.

run.py가 Mininet 공격자 호스트 안에서 실행합니다. 직접 실행은 labguard가 막습니다.

    python env/attacks/port_scan.py --iface h4-eth0 --target-ip 10.0.0.1 \
        --ports 1-1000 --duration 30
"""

from __future__ import annotations

import shutil
import subprocess
import time

from env.attacks.labguard import require_lab


def run_nmap(target_ip: str, ports: str, duration: float, evasive: bool) -> None:
    timing = ["-T1"] if evasive else ["-T4"]
    cmd = ["nmap", "-sS", "-Pn", "-n", "-p", ports, *timing, target_ip]
    print(f"[port_scan] 실행: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=duration, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass


def run_scapy(iface: str, target_ip: str, ports: str, duration: float,
              evasive: bool) -> None:
    from scapy.all import IP, TCP, sr1  # noqa: F401
    lo, _, hi = ports.partition("-")
    lo, hi = int(lo), int(hi) if hi else int(lo)
    port_list = list(range(lo, hi + 1))
    if evasive:
        import random
        random.shuffle(port_list)
    end = time.time() + duration
    sent = 0
    for port in port_list:
        if time.time() > end:
            break
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        sr1(pkt, timeout=0.3, verbose=False, iface=iface)
        sent += 1
        if evasive:
            time.sleep(0.3)
    print(f"port_scan(scapy) 끝: {sent}개 포트 탐색 (target={target_ip})")


def main() -> None:
    require_lab()
    import argparse
    p = argparse.ArgumentParser(description="nmap 포트 스캔 (격리 실험용)")
    p.add_argument("--iface", required=True)
    p.add_argument("--target-ip", required=True)
    p.add_argument("--ports", default="1-1000")
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument("--no-nmap", action="store_true", help="scapy로 대체 실행")
    p.add_argument("--evasive", action="store_true", help="느리게/순서를 흩어서 스캔")
    a = p.parse_args()

    if not a.no_nmap and shutil.which("nmap"):
        run_nmap(a.target_ip, a.ports, a.duration, a.evasive)
    else:
        run_scapy(a.iface, a.target_ip, a.ports, a.duration, a.evasive)


if __name__ == "__main__":
    main()
