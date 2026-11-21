"""실험망 데이터 일괄 수집기 (P2, 11주차).

공격 시나리오를 여러 번 반복 실행하고, 정상 트래픽만 흐르는 실험을 원하는 시간만큼 돌린 뒤,
실험마다 특징을 추출하고, 끝나면 라벨 검증(verify.py)과 라벨 데이터셋(label.py)까지 만듭니다.

    # 계획만 보기 (root·Mininet 불필요)
    python3 capture/collect.py --dry-run

    # 기본: 공격 6종 × 3회 + 정상 30분(10분 × 3), 약 1시간
    sudo python3 capture/collect.py

    # 공격별 5회, 회피 공격(*_slow)도 포함, 정상 40분
    sudo python3 capture/collect.py --repeat 5 --with-evasive --normal-min 40

    # 일부만 / 정상만
    sudo python3 capture/collect.py --scenarios arp_spoof syn_flood --repeat 2 --normal-min 0
    sudo python3 capture/collect.py --scenarios --normal-min 30

공격 실험은 env/run.py(P1)를 그대로 호출합니다. 정상 실험은 run.py에 정상 전용 시나리오가
없어서 이 파일이 run.py의 망 구성·캡처 함수를 그대로 가져다 공격만 빼고 실행합니다.
정상 실험의 labels.jsonl 은 빈 파일입니다(= 모든 시간이 normal, data-format 2.1).

중간에 멈춰도(Ctrl+C) 이미 끝난 실험은 data/runs 에 남습니다.
진행 기록: data/collect_log.jsonl (실험마다 한 줄: 시나리오, 폴더, 성공 여부, 걸린 시간)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 11주차 기본 수집 대상 (scenarios.py 이름). *_slow 는 --with-evasive 로 추가
BASE_SCENARIOS = ["arp_spoof", "mac_flood", "dhcp_starve", "dhcp_rogue",
                  "port_scan", "syn_flood"]
NORMAL = "normal"
PY = sys.executable or "python3"


def available_scenarios() -> dict:
    from env.scenarios import SCENARIOS
    return SCENARIOS


def plan(scenarios: list[str], repeat: int, normal_min: float, chunk_min: float,
         interleave: bool) -> list[tuple[str, float | None]]:
    """실행 순서 목록: (시나리오, 정상이면 길이(초) / 공격이면 None)."""
    attacks: list[tuple[str, float | None]] = []
    if interleave:   # 1회차 전부 → 2회차 전부 … (중간에 멈춰도 공격 종류가 고르게 남음)
        for _ in range(repeat):
            attacks += [(s, None) for s in scenarios]
    else:
        for s in scenarios:
            attacks += [(s, None)] * repeat
    normals = []
    left = normal_min * 60
    while left > 1:
        d = min(chunk_min * 60, left)
        normals.append((NORMAL, d))
        left -= d
    return attacks + normals


def estimate_sec(item: tuple[str, float | None], scns: dict) -> float:
    name, dur = item
    if dur is not None:
        return dur + 15
    return scns[name].duration + 15 if name in scns else 60


# ---------------------------------------------------------------- 실험 1회

def _new_dir(outdir: Path, before: set[str]) -> Path | None:
    new = sorted(set(p.name for p in outdir.glob("*/")) - before)
    return outdir / new[-1] if new else None


def run_attack(name: str, outdir: Path, controller: str) -> tuple[Path | None, bool, str]:
    outdir.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in outdir.glob("*/")}
    cmd = [PY, str(ROOT / "env" / "run.py"), name, "--outdir", str(outdir),
           "--controller", controller]
    r = subprocess.run(cmd, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
    d = _new_dir(outdir, before)
    ok = r.returncode == 0 and d is not None and (d / "meta.json").exists()
    return d, ok, f"run.py 종료코드 {r.returncode}"


def run_normal(outdir: Path, seconds: float) -> tuple[Path | None, bool, str]:
    outdir.mkdir(parents=True, exist_ok=True)
    run_dir = outdir / (datetime.now().strftime("%Y%m%d-%H%M%S-") + NORMAL)
    run_dir.mkdir(parents=True)
    # Mininet 정리를 실험마다 확실히 하려고 별도 프로세스로 실행
    cmd = [PY, str(Path(__file__).resolve()), "_normal_once", str(run_dir), str(seconds)]
    r = subprocess.run(cmd, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)})
    ok = r.returncode == 0 and (run_dir / "meta.json").exists()
    return run_dir, ok, f"정상 실험 종료코드 {r.returncode}"


def _normal_once(run_dir: Path, seconds: float) -> None:
    """정상 트래픽만 흐르는 실험 1회 (root, 내부용). env/run.py 의 함수를 재사용."""
    from mininet.clean import cleanup
    from mininet.net import Mininet
    from mininet.node import OVSController

    from env import run as envrun
    from env.hosts import by_role, one
    from env.scenarios import Scenario
    from env.topo import LanTopo

    scn = Scenario(name=NORMAL, attack=NORMAL, attacker=one("attacker").name,
                   module="", args=[], warmup=0.0, attack_dur=0.0, cooldown=0.0)
    cleanup()
    net = Mininet(topo=LanTopo(), controller=OVSController, autoSetMacs=False)
    net.start()
    procs, cap = [], None
    start = time.time()
    try:
        envrun.configure_network(net, procs)
        net.waitConnected(timeout=15)
        cap = envrun.start_capture(net, run_dir / "capture.pcap")
        gw = net.get(one("gateway").name)
        procs.append(gw.popen(
            f"{envrun._child_env()}python3 -m env.traffic.normal --role server "
            f"--duration {seconds} --http-port {envrun.HTTP_PORT}", shell=True))
        for i, h in enumerate(by_role("client")):
            procs.append(net.get(h.name).popen(
                f"{envrun._child_env()}python3 -m env.traffic.normal --role client "
                f"--duration {seconds} --http-port {envrun.HTTP_PORT} --seed {100 + i}",
                shell=True))
        print(f"[collect] 정상 트래픽 {seconds / 60:.1f}분 수집 중 …", flush=True)
        time.sleep(seconds)
        (run_dir / "labels.jsonl").write_text("", encoding="utf-8")  # 공격 없음
        envrun.write_meta(run_dir, scn, start, time.time())
    finally:
        envrun.stop_capture(cap)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        net.stop()


def extract(run_dir: Path) -> bool:
    if not (run_dir / "capture.pcap").exists():
        print(f"[collect] capture.pcap 없음 → 특징 추출 건너뜀: {run_dir.name}")
        return False
    r = subprocess.run([PY, str(ROOT / "capture" / "extract.py"), str(run_dir)], cwd=ROOT,
                       env={**os.environ, "PYTHONPATH": str(ROOT)})
    return r.returncode == 0


def _log(path: Path, **rec) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _give_back_to_user(paths: list[Path]) -> None:
    """sudo로 만든 파일을 원래 사용자 소유로 (나중에 sudo 없이 분석할 수 있게)."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not hasattr(os, "chown"):
        return
    for base in paths:
        if not base.exists():
            continue
        for p in [base, *base.rglob("*")]:
            try:
                os.chown(p, int(uid), int(gid or uid))
            except OSError:
                pass


# ---------------------------------------------------------------- main

def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if len(sys.argv) == 4 and sys.argv[1] == "_normal_once":
        _normal_once(Path(sys.argv[2]), float(sys.argv[3]))
        return 0

    p = argparse.ArgumentParser(description="실험망 데이터 일괄 수집 (P2, 11주차)")
    p.add_argument("--scenarios", nargs="*", default=None,
                   help=f"공격 시나리오 (기본: {' '.join(BASE_SCENARIOS)}). "
                        "값 없이 쓰면 공격 없이 정상만")
    p.add_argument("--with-evasive", action="store_true", help="*_slow 회피 시나리오 추가")
    p.add_argument("--repeat", type=int, default=3, help="공격 시나리오당 반복 횟수")
    p.add_argument("--normal-min", type=float, default=30, help="정상 전용 실험 총 시간(분)")
    p.add_argument("--normal-chunk-min", type=float, default=10,
                   help="정상 실험 1회 길이(분). 길면 pcap 하나가 너무 커짐")
    p.add_argument("--no-interleave", action="store_true",
                   help="같은 시나리오를 연달아 실행 (기본은 회차별로 섞어 실행)")
    p.add_argument("--controller", choices=["ovs", "remote"], default="ovs")
    p.add_argument("--outdir", default=str(ROOT / "data" / "runs"))
    p.add_argument("--dry-run", action="store_true", help="실행 계획만 출력")
    a = p.parse_args()

    scns = available_scenarios()
    names = BASE_SCENARIOS if a.scenarios is None else a.scenarios
    if a.with_evasive:
        names = names + [n for n in scns if n.endswith("_slow") and n not in names]
    missing = [n for n in names if n not in scns]
    if missing:
        print(f"[collect] scenarios.py에 없는 시나리오는 건너뜀: {', '.join(missing)}")
        print("          (P1의 11주차 공격이 main에 합쳐졌는지 확인하세요)")
        names = [n for n in names if n in scns]

    todo = plan(names, a.repeat, a.normal_min, a.normal_chunk_min, not a.no_interleave)
    total = sum(estimate_sec(t, scns) for t in todo)
    print(f"[collect] 실험 {len(todo)}개, 예상 {total / 60:.0f}분")
    for i, (name, dur) in enumerate(todo, 1):
        what = f"정상 {dur / 60:.1f}분" if dur is not None else f"공격 {name}"
        print(f"  {i:3d}. {what}")
    if a.dry_run:
        return 0
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        sys.exit("root 권한이 필요합니다: sudo python3 capture/collect.py ...")

    outdir = Path(a.outdir)
    log = ROOT / "data" / "collect_log.jsonl"
    batch = datetime.now().strftime("%Y%m%d-%H%M%S")
    done: list[Path] = []
    failed = 0
    t_batch = time.time()
    try:
        for i, (name, dur) in enumerate(todo, 1):
            print(f"\n[collect] ({i}/{len(todo)}) {name} 시작", flush=True)
            t0 = time.time()
            if dur is None:
                d, ok, why = run_attack(name, outdir, a.controller)
            else:
                d, ok, why = run_normal(outdir, dur)
            feat_ok = ok and d is not None and extract(d)
            if d is not None:
                done.append(d)
            if not (ok and feat_ok):
                failed += 1
                print(f"[collect] ⚠ {name} 실패: {why}, 특징 추출 {'성공' if feat_ok else '실패'}")
            _log(log, batch=batch, scenario=name, run_dir=d.name if d else None,
                 ok=ok, features=feat_ok, sec=round(time.time() - t0, 1),
                 ts=time.time())
    except KeyboardInterrupt:
        print("\n[collect] 중단됨. 지금까지 끝난 실험으로 검증합니다.")
    finally:
        _give_back_to_user([outdir, log, ROOT / "data" / "dataset"])

    print(f"\n[collect] 실험 {len(done)}개 끝 (실패 {failed}), "
          f"{(time.time() - t_batch) / 60:.1f}분 걸림")
    # 전체 data/runs 기준으로 검증·데이터셋 갱신 (이전 배치도 함께 셈)
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    subprocess.run([PY, str(ROOT / "capture" / "verify.py"), "--all", "--runs-dir", str(outdir),
                    "--min-reps", str(a.repeat), "--normal-min", str(a.normal_min)],
                   cwd=ROOT, env=env)
    subprocess.run([PY, str(ROOT / "capture" / "label.py"), "--all", "--runs-dir", str(outdir)],
                   cwd=ROOT, env=env)
    _give_back_to_user([ROOT / "data" / "dataset"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
