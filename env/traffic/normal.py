"""정상 트래픽 발생기 — Mininet 호스트 안에서 역할별로 실행.

run.py가 각 호스트에서 이 스크립트를 띄웁니다.

  - gateway/dhcp 서버: iperf3 서버, 간단한 HTTP 서버를 띄워 둠
  - client: 주기적으로 ping(ARP 유발), HTTP 내려받기(TCP), DNS 조회,
    동영상 스트리밍(iperf3 UDP 버스트), 파일 전송(iperf3 TCP 버스트)을 섞어서 보냄

탐지기의 오탐을 확인하려면 "정상인데 공격처럼 보이는" 트래픽도 필요합니다.
그래서 클라이언트는 여러 목적지로 고르게 접속합니다(한 곳만 때리지 않음).
w11: 트래픽 종류를 web/video/dns/file로 다양화 (단순 ping·http·dns에서 확장).
"""

from __future__ import annotations

import argparse
import random
import subprocess
import time

from env.hosts import GATEWAY_IP, by_role


def _run(cmd: str, timeout: float | None = None) -> None:
    try:
        subprocess.run(cmd, shell=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass


def server(duration: float, http_port: int) -> None:
    """서버 역할(gateway): iperf3 서버 + HTTP 서버를 duration 동안 띄움.

    iperf3 서버는 `-1`(단발) 없이 띄워서, 여러 클라이언트가 번갈아
    video(UDP)/file(TCP) 전송을 반복해도 계속 응답합니다.
    """
    procs = [
        subprocess.Popen(["iperf3", "-s"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL),
        subprocess.Popen(["python3", "-m", "http.server", str(http_port)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    try:
        time.sleep(duration)
    finally:
        for p in procs:
            p.terminate()


def client(duration: float, http_port: int, seed: int) -> None:
    """클라이언트 역할: web / video / dns / file 트래픽을 섞어서 반복."""
    rnd = random.Random(seed)
    # 접속할 정상 상대 목록 (자기 자신 제외)
    peers = [h.ip for h in by_role("client") + by_role("gateway")]
    end = time.time() + duration
    while time.time() < end:
        kind = rnd.choice(["ping", "web", "dns", "video", "file"])
        if kind == "ping":
            dst = rnd.choice(peers)
            _run(f"ping -c {rnd.randint(1, 3)} -W 1 {dst}", timeout=5)
        elif kind == "web":
            _run(f"wget -q -O /dev/null http://{GATEWAY_IP}:{http_port}/", timeout=5)
        elif kind == "dns":  # 게이트웨이의 dnsmasq에 조회
            name = rnd.choice(["a", "b", "c", "www"]) + ".lab.test"
            _run(f"nslookup {name} {GATEWAY_IP}", timeout=5)
        elif kind == "video":  # 동영상 스트리밍 흉내: 지속적인 UDP 버스트 (대역폭 제한 필수)
            _run(f"iperf3 -c {GATEWAY_IP} -u -b 1M -t 2", timeout=5)
        else:  # file: 파일 전송 흉내: 짧은 TCP 버스트
            # Mininet 가상 링크는 기본 대역폭 제한이 없어, -b(목표 속도) 없이
            # iperf3 TCP를 돌리면 링크를 포화시켜 캡처가 수 GB로 폭주한다.
            # 5Mbps로 1초 버스트 → 약 625KB 정도로 제한.
            _run(f"iperf3 -c {GATEWAY_IP} -b 5M -t 1", timeout=5)
        time.sleep(rnd.uniform(0.3, 1.5))


def main() -> None:
    p = argparse.ArgumentParser(description="정상 트래픽 발생기")
    p.add_argument("--role", required=True, choices=["server", "client"])
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--http-port", type=int, default=8000)
    p.add_argument("--seed", type=int, default=0)
    a = p.parse_args()
    if a.role == "server":
        server(a.duration, a.http_port)
    else:
        client(a.duration, a.http_port, a.seed)


if __name__ == "__main__":
    main()
