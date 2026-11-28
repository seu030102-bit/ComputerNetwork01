"""JSONL 파일 실시간 읽기 (`tail -f` 방식, data-format §5). 표준 라이브러리만 씀.

실시간 캡처(live.py)는 특징을 features_1s.jsonl / features_5s.jsonl 끝에 한 줄씩 붙입니다.
탐지기(P3 AI, P4 규칙)는 이 함수로 새 줄이 생길 때마다 기록을 받으면 됩니다.

    from capture.follow import follow_many

    for rec in follow_many([run_dir / "features_1s.jsonl",
                            run_dir / "features_5s.jsonl"], idle_timeout=30):
        ...   # rec 은 dict (feat_host / feat_seg)

명령줄로 흐름 확인:

    python3 capture/follow.py data/runs/<run_id>/features_1s.jsonl

처리하는 경우
  - 파일이 아직 없음 → 생길 때까지 기다림
  - 마지막 줄이 덜 쓰임(줄바꿈 없음) → 다음 주기에 다시 읽음
  - 파일이 비워짐(truncate)·다시 만들어짐 → 처음부터 다시 읽음
  - JSON이 깨진 줄 → 건너뛰고 경고만 출력
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Callable, Iterable, Iterator


class _Tail:
    def __init__(self, path: Path, from_start: bool):
        self.path = Path(path)
        self.offset = 0
        self.inode = None
        if not from_start and self.path.exists():
            st = self.path.stat()
            self.offset, self.inode = st.st_size, st.st_ino

    def poll(self) -> list[dict]:
        """새로 완성된 줄들을 기록으로 돌려줌."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []
        if self.inode is not None and st.st_ino != self.inode:
            self.offset = 0          # 파일이 새로 만들어짐
        if st.st_size < self.offset:
            self.offset = 0          # 비워짐(truncate)
        self.inode = st.st_ino
        if st.st_size == self.offset:
            return []
        out = []
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            data = fh.read()
        end = data.rfind(b"\n")
        if end < 0:
            return []                # 아직 한 줄도 완성 안 됨
        self.offset += end + 1
        for raw in data[:end].split(b"\n"):
            line = raw.decode("utf-8-sig", errors="replace").strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[follow] JSON 오류, 건너뜀: {self.path.name}: {line[:60]}",
                      file=sys.stderr)
        return out


def follow_many(paths: Iterable[Path], *, from_start: bool = True, poll: float = 0.1,
                idle_timeout: float | None = None,
                stop: Callable[[], bool] | None = None) -> Iterator[dict]:
    """여러 JSONL 파일의 새 줄을 도착 순서대로 내보냄.

    idle_timeout: 이 시간(초) 동안 새 줄이 없으면 끝냄 (None이면 계속)
    stop: 참을 돌려주면 남은 줄까지 읽고 끝냄 (예: 실험 종료 감지)
    """
    tails = [_Tail(Path(p), from_start) for p in paths]
    last_new = time.monotonic()
    while True:
        got = False
        for t in tails:
            for rec in t.poll():
                got = True
                yield rec
        if got:
            last_new = time.monotonic()
            continue
        if stop is not None and stop():
            for t in tails:                 # 멈추기 직전에 마지막으로 한 번 더
                yield from t.poll()
            return
        if idle_timeout is not None and time.monotonic() - last_new > idle_timeout:
            return
        time.sleep(poll)


def follow(path: Path, **kw) -> Iterator[dict]:
    """파일 하나 버전."""
    return follow_many([path], **kw)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    import argparse
    p = argparse.ArgumentParser(description="JSONL 실시간 읽기 (tail -f)")
    p.add_argument("files", nargs="+")
    p.add_argument("--new-only", action="store_true", help="이미 있는 줄은 건너뜀")
    p.add_argument("--idle-timeout", type=float, default=None)
    a = p.parse_args()
    try:
        for rec in follow_many([Path(f) for f in a.files], from_start=not a.new_only,
                               idle_timeout=a.idle_timeout):
            print(json.dumps(rec, ensure_ascii=False), flush=True)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
