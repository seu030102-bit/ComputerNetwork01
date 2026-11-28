"""pcap → 특징 기록(feat_host, feat_seg) 추출기 (P2, 오프라인).

실험 폴더 하나를 받아 capture.pcap을 읽고 features_1s.jsonl / features_5s.jsonl을 만듭니다.
형식은 docs/data-format.md 2.2, 2.3 을 따릅니다.

    python3 capture/extract.py data/runs/<run_id>

특징 계산은 capture/features.py(FeatureAggregator)에 있고, 실시간 캡처(live.py)도
같은 코드를 씁니다. 그래서 오프라인과 실시간 특징이 같은 정의로 나옵니다.

오프라인 한계: 미러 pcap은 '들어온 스위치 포트'를 담지 않습니다. 그래서 포트는
meta.json의 MAC→포트로 역산하고, meta에 없는 MAC(플러딩용 가짜 MAC 등)은
포트 null 구간으로 묶습니다(data-format 2.3의 null 허용).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture.features import WINDOWS, FeatureAggregator, hosts_from_meta  # noqa: E402
from common.records import write  # noqa: E402


def load_meta(run_dir: Path):
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    mac2port, mac2ip = hosts_from_meta(meta)
    return meta, mac2port, mac2ip


def extract(run_dir: Path) -> None:
    from scapy.all import PcapReader

    _, mac2port, mac2ip = load_meta(run_dir)
    pcap = run_dir / "capture.pcap"
    if not pcap.exists():
        sys.exit(f"capture.pcap 없음: {run_dir} (run.py를 --no-pcap 없이 실행했는지 확인)")

    agg = FeatureAggregator(mac2port, mac2ip)
    for pkt in PcapReader(str(pcap)):
        agg.add(pkt)
    out = agg.flush(None)  # 끝까지 다 읽었으니 모든 창을 내보냄

    for w in WINDOWS:
        hosts, segs = out[w]
        path = run_dir / f"features_{w}s.jsonl"
        with open(path, "w", encoding="utf-8") as fh:
            for rec in hosts + segs:   # feat_host 전부 → feat_seg 전부 (예전 순서 유지)
                write(fh, rec)
        print(f"[extract] {path.name} 작성")


def main() -> None:
    p = argparse.ArgumentParser(description="pcap → 특징 추출 (P2)")
    p.add_argument("run_dir")
    a = p.parse_args()
    extract(Path(a.run_dir))


if __name__ == "__main__":
    main()
