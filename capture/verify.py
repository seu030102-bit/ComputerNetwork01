"""라벨 검증 + 수집량 점검 (P2, 11주차).

P1이 남긴 labels.jsonl 이 **실제 캡처와 맞는지** 특징(features_1s.jsonl)으로 확인하고,
11주차 수집 목표(공격별 여러 번, 정상 30분 이상)를 채웠는지 표로 보여 줍니다.

    python3 capture/verify.py --all                    # data/runs 전체
    python3 capture/verify.py data/runs/<run_id> ...   # 지정한 실험만
    python3 capture/verify.py --all --min-reps 5 --normal-min 30 --out data/dataset/verify.md

실험마다 결과를 통과 / 경고 / 실패로 나눕니다.

실패 (라벨을 믿을 수 없음 → 그 실험은 다시 수집)
  - meta.json 이 없거나 읽을 수 없음
  - 공격 시나리오인데 labels.jsonl 이 없거나 비어 있음 / 정상 시나리오인데 label 이 있음
  - label 형식 오류, attack_id 중복, 공격 종류가 시나리오와 다름
  - 공격자 MAC 이 meta.json 의 attacker 호스트가 아님
  - 공격 구간이 실험 시작·끝 밖
  - 공격 구간 안에서 공격 흔적이 전혀 없음 (공격 스크립트가 실패했을 가능성)

경고 (쓸 수는 있지만 확인 필요)
  - 특징 파일이 없어 흔적 검사를 못 함 (extract.py 먼저)
  - 공격 흔적이 약함(임계치 미만), 시작이 늦음, 라벨 끝보다 일찍 끝남
  - 공격 흔적이 라벨 구간 밖에도 있음 (라벨 경계가 어긋났을 가능성)
  - 정상 시나리오에 공격처럼 보이는 흔적 (IP 충돌, 가짜 MAC, 다른 DHCP 서버)

표준 라이브러리만 씁니다. 종료 코드: 실패가 없으면 0, 있으면 1.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from capture.label import (FAKE_MAC_ATTACKS, find_runs, known_macs,  # noqa: E402
                           load_features, load_labels, load_meta, scenario_attack)
from common.records import validate  # noqa: E402

# 11주차 수집 대상 공격 (dns_spoof 는 확장 목표라 제외)
TARGET_ATTACKS = ["arp_spoof", "mac_flood", "dhcp_rogue", "dhcp_starve",
                  "port_scan", "syn_flood"]

TIME_SLACK = 1.0     # meta 시작·끝과 비교할 때 허용 오차(초)
START_LATE = 3.0     # 공격 흔적이 start_ts 보다 이만큼 늦게 시작하면 경고
END_EARLY = 3.0      # 흔적이 end_ts 보다 이만큼 일찍 끝나면 경고(정보)
OUTSIDE_GRACE = 2.0  # 라벨 구간 밖 흔적을 셀 때 앞뒤 여유(초)

# (공격, 회피여부) → 공격 구간 전체 합계 최소값. 이보다 작으면 "흔적 약함" 경고
STRONG = {
    "arp_spoof": (3, 1), "mac_flood": (50, 20), "dhcp_starve": (10, 3),
    "dhcp_rogue": (1, 1), "port_scan": (20, 2), "syn_flood": (50, 5),
    "dns_spoof": (1, 1),
}


@dataclass
class RunResult:
    run_id: str
    scenario: str
    attack: str
    fails: list[str] = field(default_factory=list)
    warns: list[str] = field(default_factory=list)
    duration: float = 0.0
    attack_sec: float = 0.0
    has_features: bool = False

    @property
    def status(self) -> str:
        return "실패" if self.fails else ("경고" if self.warns else "통과")


# ---------------------------------------------------------------- 공격 흔적

def signature(attack: str, rec: dict, attacker_mac: str, known: set[str]) -> int:
    """1초 특징 한 줄에서 그 공격의 흔적 양 (0이면 흔적 없음)."""
    t = rec.get("type")
    if t == "feat_host":
        mac = rec["host"]["mac"]
        if attack in FAKE_MAC_ATTACKS:
            if mac in known:
                return 0
            return rec["pkts"] if attack == "mac_flood" else rec["dhcp_discover"]
        if mac != attacker_mac:
            return 0
        return {
            "arp_spoof": rec["arp_rep"],
            "dhcp_rogue": rec["dhcp_offer"] + rec["dhcp_ack"],
            "port_scan": rec["tcp_syn"],
            "syn_flood": rec["tcp_syn"],
            "dns_spoof": rec["dns_resp"],
        }.get(attack, 0)
    if t == "feat_seg" and rec.get("port") is None and attack in FAKE_MAC_ATTACKS:
        return rec["new_src_macs"] if attack == "mac_flood" else rec["dhcp_discover"]
    return 0


def _host_or_seg(attack: str) -> str:
    # 가짜 MAC 공격은 구간(포트 null) 합계로 세야 MAC 하나하나로 흩어지지 않음
    return "feat_seg" if attack in FAKE_MAC_ATTACKS else "feat_host"


def check_trace(res: RunResult, lab: dict, feats: list[dict], known: set[str],
                all_labels: list[dict]) -> None:
    attack, amac = lab["attack"], lab["attacker"]["mac"]
    s, e = lab["start_ts"], lab["end_ts"]
    kind = _host_or_seg(attack)
    inside, outside = [], 0
    for rec in feats:
        if rec.get("type") != kind:
            continue
        amount = signature(attack, rec, amac, known)
        if amount <= 0:
            continue
        w_start, w_end = rec["ts"] - rec["win"], rec["ts"]
        if w_end >= s and w_start <= e + OUTSIDE_GRACE:
            inside.append((rec["ts"], amount))
        elif not any(l["attack"] == attack
                     and w_end >= l["start_ts"] - OUTSIDE_GRACE
                     and w_start <= l["end_ts"] + OUTSIDE_GRACE for l in all_labels):
            outside += 1
    tag = f"[{lab['attack_id']} {attack}]"
    if not inside:
        res.fails.append(f"{tag} 공격 구간 안에 공격 흔적이 없음 (공격 스크립트 실패?)")
        return
    total = sum(a for _, a in inside)
    need = STRONG.get(attack, (1, 1))[1 if lab.get("evasive") else 0]
    if total < need:
        res.warns.append(f"{tag} 흔적이 약함: 합계 {total} < 기준 {need}")
    if attack == "arp_spoof" and not any(
            r.get("type") == "feat_host" and r["host"]["mac"] == amac
            and r["arp_ip_conflicts"] > 0 and s - 1 <= r["ts"] <= e + OUTSIDE_GRACE
            for r in feats):
        res.warns.append(f"{tag} ARP 충돌(arp_ip_conflicts)이 한 번도 안 잡힘 "
                         "(워밍업 중 대응표 학습이 안 됐을 수 있음)")
    first = min(ts for ts, _ in inside) - 1.0   # 1초 창의 시작
    last = max(ts for ts, _ in inside)
    if first - s > START_LATE:
        res.warns.append(f"{tag} 흔적이 start_ts 보다 {first - s:.1f}초 늦게 시작")
    if e - last > END_EARLY:
        res.warns.append(f"{tag} 흔적이 end_ts 보다 {e - last:.1f}초 일찍 끝남 "
                         "(공격이 일찍 끝났으면 정상, 예: nmap 스캔 완료)")
    if outside:
        res.warns.append(f"{tag} 라벨 구간 밖에서 같은 흔적 {outside}초 "
                         "(라벨 경계 확인 필요)")


def check_normal_clean(res: RunResult, feats: list[dict], meta: dict,
                       known: set[str], labels: list[dict]) -> None:
    """정상 구간에 공격처럼 보이는 흔적이 있는지 (라벨 밖 구간만)."""
    def in_attack(ts):
        return any(l["start_ts"] - OUTSIDE_GRACE <= ts <= l["end_ts"] + OUTSIDE_GRACE
                   for l in labels)
    servers = set(meta.get("dhcp_servers") or [])
    conflicts = unknown = rogue = 0
    for r in feats:
        if in_attack(r["ts"]):
            continue
        if r.get("type") == "feat_host":
            if r["arp_ip_conflicts"] > 0:
                conflicts += 1
            if r["host"]["mac"] not in known:
                unknown += 1
            if r["dhcp_offer"] > 0 and r["host"]["mac"] not in servers:
                rogue += 1
    if conflicts:
        res.warns.append(f"정상 구간에 ARP 충돌 {conflicts}초 (규칙 오탐 원인 후보)")
    if unknown:
        res.warns.append(f"정상 구간에 meta에 없는 MAC {unknown}건")
    if rogue:
        res.warns.append(f"정상 구간에 등록 안 된 DHCP OFFER {rogue}초")


# ---------------------------------------------------------------- 실험 하나

def verify_run(run_dir: Path) -> RunResult:
    try:
        meta = load_meta(run_dir)
    except Exception as e:
        res = RunResult(run_dir.name, "?", "?")
        res.fails.append(f"meta.json 을 읽을 수 없음: {e}")
        return res
    attack = scenario_attack(meta)
    res = RunResult(meta.get("run_id", run_dir.name), meta.get("scenario", "?"), attack)
    res.duration = float(meta.get("end_ts", 0) - meta.get("start_ts", 0))
    known = known_macs(meta)
    attackers = {h["mac"] for h in meta.get("hosts", []) if h.get("role") == "attacker"}

    try:
        labels = load_labels(run_dir)
    except Exception as e:
        res.fails.append(f"labels.jsonl 을 읽을 수 없음: {e}")
        return res

    if attack == "normal":
        if labels:
            res.fails.append(f"정상 시나리오인데 label {len(labels)}개가 있음")
    elif not (run_dir / "labels.jsonl").exists():
        res.fails.append("labels.jsonl 없음 (공격 시나리오)")
    elif not labels:
        res.fails.append("labels.jsonl 이 비어 있음 (공격이 기록되지 않음)")

    ids = Counter(l.get("attack_id") for l in labels)
    for aid, n in ids.items():
        if n > 1:
            res.fails.append(f"attack_id {aid} 가 {n}번 중복")
    for lab in labels:
        tag = f"[{lab.get('attack_id')}]"
        errs = validate(lab)
        if errs:
            res.fails.append(f"{tag} 형식 오류: " + "; ".join(errs))
            continue
        if attack != "normal" and lab["attack"] != attack:
            res.fails.append(f"{tag} 공격 종류 {lab['attack']} ≠ 시나리오 {attack}")
        if lab["attacker"]["mac"] not in attackers:
            res.fails.append(f"{tag} 공격자 MAC {lab['attacker']['mac']} 이 "
                             "meta의 attacker 호스트가 아님")
        if (lab["start_ts"] < meta["start_ts"] - TIME_SLACK
                or lab["end_ts"] > meta["end_ts"] + TIME_SLACK):
            res.fails.append(f"{tag} 공격 구간이 실험 시작·끝 밖")
        if res.scenario.endswith("_slow") and not lab["evasive"]:
            res.warns.append(f"{tag} 느린(회피) 시나리오인데 evasive=false")
        res.attack_sec += lab["end_ts"] - lab["start_ts"]

    feats = load_features(run_dir, 1)
    res.has_features = bool(feats)
    if not feats:
        res.warns.append("features_1s.jsonl 없음 → 흔적 검사 생략 (extract.py 먼저)")
        return res
    good = [l for l in labels if not validate(l)]
    for lab in good:
        check_trace(res, lab, feats, known, good)
    check_normal_clean(res, feats, meta, known, good)
    return res


# ---------------------------------------------------------------- 요약

def summarize(results: list[RunResult], min_reps: int, normal_min: float) -> tuple[str, bool]:
    """마크다운 요약과 '11주차 목표 달성' 여부."""
    by_scn: dict[str, list[RunResult]] = defaultdict(list)
    for r in results:
        by_scn[r.scenario].append(r)

    lines = ["## 시나리오별 수집 현황", "",
             "| 시나리오 | 공격 | 실험 수 | 통과 | 경고 | 실패 | 공격 시간(초) |",
             "|---|---|---|---|---|---|---|"]
    for scn in sorted(by_scn):
        rs = by_scn[scn]
        st = Counter(r.status for r in rs)
        lines.append(f"| {scn} | {rs[0].attack} | {len(rs)} | {st['통과']} | {st['경고']} "
                     f"| {st['실패']} | {sum(r.attack_sec for r in rs):.0f} |")

    usable = [r for r in results if not r.fails]
    reps = Counter(r.attack for r in usable if r.attack != "normal")
    normal_sec = sum(r.duration for r in usable if r.attack == "normal")
    incidental = sum(r.duration - r.attack_sec for r in usable if r.attack != "normal")
    fails = sum(1 for r in results if r.fails)

    missing = [a for a in TARGET_ATTACKS if reps[a] < min_reps]
    ok_reps = not missing
    ok_labels = fails == 0 and bool(results)
    ok_normal = normal_sec >= normal_min * 60

    def mark(ok):
        return "✅" if ok else "❌"

    lines += ["", "## 11주차 체크리스트", "",
              f"- {mark(ok_reps)} 공격별 반복 수집 (공격마다 실패 없는 실험 {min_reps}회 이상): "
              + ", ".join(f"{a} {reps[a]}" for a in TARGET_ATTACKS),
              f"- {mark(ok_labels)} 라벨 검증: 실험 {len(results)}개 중 실패 {fails}개",
              f"- {mark(ok_normal)} 정상 {normal_min:.0f}분 이상: 정상 전용 실험 "
              f"{normal_sec / 60:.1f}분 (공격 실험의 워밍업·쿨다운 정상 구간 "
              f"{incidental / 60:.1f}분 별도)"]

    detail = [r for r in results if r.fails or r.warns]
    if detail:
        lines += ["", "## 실패·경고 상세", ""]
        for r in detail:
            lines.append(f"- **{r.run_id}** ({r.status})")
            lines += [f"  - 실패: {m}" for m in r.fails]
            lines += [f"  - 경고: {m}" for m in r.warns]
    return "\n".join(lines) + "\n", ok_reps and ok_labels and ok_normal


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="라벨 검증 + 수집량 점검 (P2)")
    p.add_argument("runs", nargs="*", help="실험 폴더들")
    p.add_argument("--all", action="store_true", help="--runs-dir 안의 실험 전체")
    p.add_argument("--runs-dir", default=str(ROOT / "data" / "runs"),
                   help="--all 이 볼 폴더 (기본 data/runs)")
    p.add_argument("--min-reps", type=int, default=3, help="공격별 최소 반복 횟수")
    p.add_argument("--normal-min", type=float, default=30, help="정상 최소 시간(분)")
    p.add_argument("--out", default=str(ROOT / "data" / "dataset" / "verify.md"))
    a = p.parse_args()
    run_dirs = [Path(r) for r in a.runs]
    if a.all:
        run_dirs += find_runs(Path(a.runs_dir))
    if not run_dirs:
        p.error("실험 폴더를 주거나 --all 을 쓰세요")

    results = [verify_run(d) for d in sorted(set(run_dirs))]
    for r in results:
        print(f"{r.status}  {r.run_id}")
        for m in r.fails:
            print(f"    실패: {m}")
        for m in r.warns:
            print(f"    경고: {m}")
    text, done = summarize(results, a.min_reps, a.normal_min)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("# 실험망 데이터 수집·라벨 검증 결과\n\n" + text, encoding="utf-8")
    print()
    print(text)
    print(f"[verify] 저장: {out}  ({'11주차 목표 달성' if done else '목표 미달'})")
    return 1 if any(r.fails for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
