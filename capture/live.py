"""실시간 스트리밍 캡처 → 특징 → 탐지기 전달 (P2, 12주차).

실험이 돌아가는 동안 캡처 포트(mon0)에서 패킷을 바로 읽어, 1초·5초 창이 끝날 때마다
특징 기록을 features_1s.jsonl / features_5s.jsonl 끝에 한 줄씩 붙입니다(data-format §5).
특징 계산은 오프라인 extract.py와 같은 코드(capture/features.py)입니다.

    # 터미널 1: 실시간 캡처 + 규칙 탐지 (실험보다 먼저 띄워 둠)
    sudo PYTHONPATH=$PWD python3 capture/live.py --auto --rules

    # 터미널 2: 실험 (run.py가 mon0과 실험 폴더를 만들면 live.py가 알아서 붙음)
    sudo python3 env/run.py arp_spoof

    # SDN 차단까지: 컨트롤러 inbox로도 경보를 보냄 (sdn/README.md 라이브 절차)
    sudo PYTHONPATH=$PWD python3 capture/live.py --auto --rules --inbox data/sdn/inbox.jsonl

옵션
  --auto           mon0이 생기길 기다렸다가, 그 뒤에 생긴 가장 새 실험 폴더에 기록.
                   mon0이 사라지면(실험 끝) 남은 창을 내보내고 종료.
  --run-dir DIR    기록할 폴더를 직접 지정 (--auto 대신)
  --iface IF       캡처할 인터페이스 (기본 mon0)
  --rules          특징이 나오는 즉시 P4 규칙(rules/detect.py)으로 판정 →
                   <실험 폴더>/alerts_rule.jsonl 에 경보 추가 (대시보드가 바로 읽음)
  --inbox FILE     경보를 SDN 컨트롤러 inbox에도 추가 (공격자 자동 차단)
  --lag SEC        창이 끝난 뒤 늦게 오는 패킷을 기다리는 시간 (기본 0.3초)

다른 탐지기(P3 AI 등)는 capture/follow.py 로 특징 파일을 실시간으로 읽으면 됩니다.
특징 기록의 extra.lag_ms = 창이 끝난 뒤 기록이 파일에 쓰이기까지 걸린 시간(ms).
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture.features import WINDOWS, FeatureAggregator, hosts_from_env  # noqa: E402
from common.records import write  # noqa: E402

RCVBUF = 64 * 1024 * 1024   # 캡처 소켓 수신 버퍼 64MB
SO_RCVBUFFORCE = 33         # root면 rmem_max 제한을 넘어 버퍼 설정 가능 (Linux)
SOL_PACKET, PACKET_STATISTICS = 263, 6


def iface_exists(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}").exists()


def wait_for_iface(iface: str, stop: threading.Event) -> bool:
    shown = False
    while not stop.is_set():
        if iface_exists(iface):
            return True
        if not shown:
            print(f"[live] {iface} 기다리는 중 … (다른 터미널에서 sudo python3 env/run.py <시나리오>)",
                  flush=True)
            shown = True
        stop.wait(0.1)
    return False


def newest_run_dir(runs_dir: Path, since: float, timeout: float = 15.0) -> Path | None:
    """since 이후에 생긴 가장 새 실험 폴더."""
    end = time.time() + timeout
    while time.time() < end:
        cands = [d for d in runs_dir.glob("*/") if d.stat().st_mtime >= since - 2]
        if cands:
            return max(cands, key=lambda d: d.name)
        time.sleep(0.2)
    return None


class RuleBridge:
    """특징 기록을 받는 즉시 P4 규칙 탐지기 함수로 판정해 경보를 씀."""

    def __init__(self, run_dir: Path, inbox: Path | None):
        from env.hosts import by_role
        from rules.detect import Deduper, _host_alert, _seg_alert
        self._host, self._seg = _host_alert, _seg_alert
        self.dedup = Deduper()
        self.legit_dhcp = {h.mac for h in by_role("dhcp_server")}
        self.out = open(run_dir / "alerts_rule.jsonl", "a", encoding="utf-8")
        self.inbox = None
        if inbox is not None:
            inbox.parent.mkdir(parents=True, exist_ok=True)
            self.inbox = open(inbox, "a", encoding="utf-8")
        self.count = 0

    def feed(self, rec: dict) -> None:
        if rec["type"] == "feat_host":
            alert = self._host(rec, self.legit_dhcp, self.dedup)
        else:
            alert = self._seg(rec, self.dedup)
        if not alert:
            return
        alert["ts"] = time.time()       # 실시간: 경보 시각 = 판정을 마친 시각 (data-format 2.4)
        write(self.out, alert)
        if self.inbox is not None:
            write(self.inbox, alert)
        self.count += 1
        print(f"[live] 🚨 경보 {alert['attack']}: {alert['summary']} "
              f"(창 끝 후 {(alert['ts'] - rec['ts']) * 1000:.0f}ms)", flush=True)

    def close(self) -> None:
        self.out.close()
        if self.inbox is not None:
            self.inbox.close()


class LiveCapture:
    def __init__(self, iface: str, run_dir: Path, lag: float, bridge: RuleBridge | None):
        mac2port, mac2ip = hosts_from_env()
        self.agg = FeatureAggregator(mac2port, mac2ip)
        self.iface, self.run_dir, self.lag, self.bridge = iface, run_dir, lag, bridge
        self.lock = threading.Lock()
        self.files = {w: open(run_dir / f"features_{w}s.jsonl", "w", encoding="utf-8")
                      for w in WINDOWS}
        self.records = 0
        self.lags: list[float] = []

    def on_packet(self, pkt) -> None:
        with self.lock:
            self.agg.add(pkt)

    def emit(self, upto_ts: float | None) -> None:
        with self.lock:
            out = self.agg.flush(upto_ts)
        now = time.time()
        for w in WINDOWS:
            hosts, segs = out[w]
            for rec in hosts + segs:
                lag_ms = round((now - rec["ts"]) * 1000, 1)
                rec["extra"]["lag_ms"] = lag_ms
                write(self.files[w], rec)
                self.records += 1
                if upto_ts is not None:      # 마지막 정리분은 지연 통계에서 뺌
                    self.lags.append(lag_ms)
                if self.bridge is not None:
                    self.bridge.feed(rec)

    def _open_socket(self):
        """수신 버퍼를 크게 잡은 캡처 소켓. 순간적으로 몰리는 패킷을 커널이 버리지 않게."""
        import logging
        import socket

        from scapy.all import conf
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # 종료 시 'Network is down' 경고 숨김
        sock = conf.L2listen(iface=self.iface)
        try:
            sock.ins.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, RCVBUF)
        except OSError:
            sock.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
        self.sock = sock
        return sock

    def kernel_stats(self) -> tuple[int, int] | None:
        """(커널이 넘겨준 패킷, 버퍼가 차서 버린 패킷) — 마지막 조회 이후 누적."""
        import struct
        try:
            raw = self.sock.ins.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        except Exception:
            return None
        got, drops = struct.unpack("II", raw)
        self.k_packets += got
        self.k_drops += drops
        return self.k_packets, self.k_drops

    def run(self, stop: threading.Event, stop_when_iface_gone: bool) -> None:
        from scapy.all import AsyncSniffer
        self.k_packets = self.k_drops = 0
        sniffer = AsyncSniffer(opened_socket=self._open_socket(), prn=self.on_packet,
                               store=False)
        sniffer.start()
        print(f"[live] 캡처 시작: {self.iface} → {self.run_dir}", flush=True)
        last_stat = time.time()
        try:
            while not stop.is_set():
                stop.wait(0.1)
                self.emit(time.time() - self.lag)
                self.kernel_stats()
                if stop_when_iface_gone and not iface_exists(self.iface):
                    print(f"[live] {self.iface} 사라짐 → 실험 종료로 보고 마무리", flush=True)
                    break
                if time.time() - last_stat >= 5:
                    last_stat = time.time()
                    print(f"[live] 패킷 {self.agg.packets} · 특징 {self.records}줄"
                          + (f" · 경보 {self.bridge.count}" if self.bridge else ""), flush=True)
        finally:
            try:
                sniffer.stop()
            except Exception:   # 인터페이스가 먼저 사라지면 stop()이 실패할 수 있음
                pass
            self.emit(None)     # 남은 창 전부
            for fh in self.files.values():
                fh.close()

    def summary(self) -> str:
        lags = sorted(self.lags)
        lag_txt = "없음"
        if lags:
            p95 = lags[min(len(lags) - 1, int(len(lags) * 0.95))]
            lag_txt = f"중앙값 {lags[len(lags) // 2]:.0f}ms, 95% {p95:.0f}ms, 최대 {lags[-1]:.0f}ms"
        return (f"패킷 {self.agg.packets}개, 커널 버퍼에서 버려진 패킷 {self.k_drops}개, "
                f"늦게 와서 버린 패킷 {self.agg.late}개, "
                f"특징 {self.records}줄, 기록 지연 {lag_txt}")


def _give_back_to_user(paths: list[Path]) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid:
        return
    for p in paths:
        try:
            os.chown(p, int(uid), int(gid or uid))
        except OSError:
            pass


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="실시간 캡처 → 특징 → 탐지기 (P2)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--auto", action="store_true", help="mon0과 새 실험 폴더를 기다렸다가 붙음")
    g.add_argument("--run-dir", help="기록할 실험 폴더")
    p.add_argument("--iface", default="mon0")
    p.add_argument("--runs-dir", default=str(ROOT / "data" / "runs"))
    p.add_argument("--rules", action="store_true", help="P4 규칙으로 실시간 판정")
    p.add_argument("--inbox", default=None, help="경보를 SDN inbox에도 추가")
    p.add_argument("--lag", type=float, default=0.3)
    a = p.parse_args()
    if a.inbox and not a.rules:
        p.error("--inbox 는 --rules 와 함께 쓰세요")
    if os.geteuid() != 0:
        sys.exit("root 권한이 필요합니다: sudo PYTHONPATH=$PWD python3 capture/live.py ...")

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    started = time.time()
    if not wait_for_iface(a.iface, stop):
        return 1
    if a.auto:
        run_dir = newest_run_dir(Path(a.runs_dir), started)
        if run_dir is None:
            sys.exit(f"[live] {a.runs_dir} 에 새 실험 폴더가 안 생김")
    else:
        run_dir = Path(a.run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)

    bridge = RuleBridge(run_dir, Path(a.inbox) if a.inbox else None) if a.rules else None
    cap = LiveCapture(a.iface, run_dir, a.lag, bridge)
    try:
        cap.run(stop, stop_when_iface_gone=True)
    finally:
        if bridge is not None:
            bridge.close()
        _give_back_to_user([run_dir / f"features_{w}s.jsonl" for w in WINDOWS]
                           + [run_dir / "alerts_rule.jsonl"]
                           + ([Path(a.inbox)] if a.inbox else []))
    print(f"[live] 끝: {cap.summary()}" + (f", 경보 {bridge.count}개" if bridge else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
