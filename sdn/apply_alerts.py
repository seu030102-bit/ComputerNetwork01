"""실험 폴더의 경보를 SDN 차단으로 넘기거나, 오프라인으로 action을 기록합니다.

사용법:
  # 컨트롤러가 inbox를 감시 중일 때 (실시간 사후 차단)
  python3 sdn/apply_alerts.py data/runs/<run_id> --inbox data/sdn/inbox.jsonl

  # 스위치/컨트롤러 없이 action만 기록 (파이프라인·평가용)
  python3 sdn/apply_alerts.py data/runs/<run_id> --offline

  # 경보 1줄을 inbox에 직접
  python3 sdn/apply_alerts.py --inject-json '{"type":"alert",...}' --inbox ...
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import read, write  # noqa: E402
from sdn.policy import BlockDeduper, block_spec, make_block_action  # noqa: E402

ALERT_FILES = ("alerts_rule.jsonl", "alerts_ai.jsonl", "alerts.jsonl")


def load_alerts(run_dir: Path) -> list[dict]:
    seen_ids: set[str] = set()
    out: list[dict] = []
    for name in ALERT_FILES:
        path = run_dir / name
        if not path.exists():
            continue
        for rec in read(path):
            if rec.get("type") != "alert":
                continue
            aid = rec.get("alert_id")
            if aid in seen_ids:
                continue
            if aid:
                seen_ids.add(aid)
            out.append(rec)
    out.sort(key=lambda r: r.get("ts", 0))
    return out


def append_inbox(inbox: Path, alerts: list[dict]) -> int:
    inbox.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(inbox, "a", encoding="utf-8") as fh:
        for a in alerts:
            write(fh, a)
            n += 1
    return n


def record_offline(run_dir: Path, alerts: list[dict]) -> int:
    """컨트롤러 없이 차단 가능 경보에 대해 action을 기록 (ok=True, install_ms=0).

    실제 OpenFlow 설치는 하지 않습니다. 평가·대시보드가 actions.jsonl을
    읽을 수 있게 하는 오프라인 시제품용입니다. 라이브 검증은 inbox 경로를 쓰세요.
    """
    dedup = BlockDeduper()
    actions_path = run_dir / "actions.jsonl"
    n = 0
    with open(actions_path, "a", encoding="utf-8") as fh:
        for alert in alerts:
            spec = block_spec(alert)
            if spec is None:
                print(f"[apply] 건너뜀(대상 없음): {alert.get('alert_id')} "
                      f"{alert.get('attack')}", flush=True)
                continue
            ts = float(alert.get("ts") or time.time())
            if not dedup.allow(spec, ts):
                continue
            # 경보 직후로 살짝 밀어 대응시간이 0이 되지 않게
            act = make_block_action(
                alert, spec, ok=True, install_ms=0.0, ts=ts + 0.05)
            act["reason"] = spec["reason"] + " [offline]"
            write(fh, act)
            n += 1
    return n


def main() -> int:
    p = argparse.ArgumentParser(description="경보 → SDN 차단 inbox / offline action")
    p.add_argument("run_dir", nargs="?", help="data/runs/<run_id>")
    p.add_argument("--inbox", type=Path, default=None,
                   help="컨트롤러가 읽는 경보 inbox JSONL")
    p.add_argument("--offline", action="store_true",
                   help="스위치 없이 run_dir/actions.jsonl 에 block 기록")
    p.add_argument("--inject-json", default=None,
                   help="경보 JSON 한 줄을 inbox에 추가 (run_dir 없이)")
    p.add_argument("--wait", type=float, default=0.5,
                   help="inbox 전송 후 컨트롤러 처리 대기(초)")
    p.add_argument("--copy-actions", type=Path, default=None,
                   help="컨트롤러 actions 파일을 run_dir/actions.jsonl 로 복사")
    args = p.parse_args()

    if args.inject_json:
        if not args.inbox:
            print("--inject-json 에는 --inbox 가 필요합니다", file=sys.stderr)
            return 2
        rec = json.loads(args.inject_json)
        n = append_inbox(args.inbox, [rec])
        print(f"[apply] inbox에 {n}줄 추가 → {args.inbox}")
        return 0

    if not args.run_dir:
        p.print_help()
        return 2

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"실험 폴더 없음: {run_dir}", file=sys.stderr)
        return 1

    alerts = load_alerts(run_dir)
    if not alerts:
        print(f"[apply] 경보 없음: {run_dir}")
        return 0

    # 기본은 offline (컨트롤러·스위치 없이도 파이프라인/평가용 actions 생성)
    if args.inbox is None and not args.offline:
        args.offline = True

    if args.offline:
        n = record_offline(run_dir, alerts)
        print(f"[apply] offline actions {n}개 → {run_dir / 'actions.jsonl'}")

    if args.inbox is not None:
        n = append_inbox(args.inbox, alerts)
        print(f"[apply] 경보 {n}개 → inbox {args.inbox}")
        if args.wait > 0:
            time.sleep(args.wait)
        if args.copy_actions and args.copy_actions.exists():
            dst = run_dir / "actions.jsonl"
            dst.write_bytes(args.copy_actions.read_bytes())
            print(f"[apply] actions 복사 → {dst}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
