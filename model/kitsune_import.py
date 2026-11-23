"""Kitsune pcap → 우리 실험 폴더(data/runs/<run_id>/) 변환 (P3).

Kitsune 원본에는 meta.json / labels.jsonl 이 없으므로 만들어 줍니다.
이후 `capture/extract.py`가 feat_host / feat_seg 를 뽑습니다. 표준 라이브러리만 씁니다.

    python3 model/kitsune_import.py --kind arp_mitm --pcap ~/kitsune_work/ARP_MitM_pcap.pcapng
    python3 model/kitsune_import.py --kind os_scan  --pcap ~/kitsune_work/OS_Scan_pcap.pcapng
    # SYN_DoS: 공격 전 정상 구간만 잘라서 정상 실험으로
    editcap -r SYN_DoS_pcap.pcap syn_normal.pcap 1-2682349
    python3 model/kitsune_import.py --kind syn_dos_normal --pcap ~/kitsune_work/syn_normal.pcap
    python3 capture/extract.py data/runs/<출력된 run_id>
    python3 common/records.py check data/runs/<출력된 run_id>

pcap은 pcapng여야 합니다(editcap 출력은 기본이 pcapng).

공격 구간(라벨)은 Kitsune의 패킷 라벨이 아니라 **pcap에서 직접 확인한 증거**로 정했습니다.
우리 규칙(label.py)대로 "공격자 MAC이 공격 구간에 보낸 창 = 공격"이 되도록 공격자의
실제 패킷 시각을 씁니다. 공격마다 확인한 내용은 아래 PROFILES의 주석에 있습니다.

Kitsune 9종 중 우리 탐지 대상과 맞는 것은 ARP MitM(arp_spoof), OS Scan(port_scan),
SYN DoS(syn_flood) 셋입니다. SYN DoS는 아래 이유로 공격 데이터로는 못 씁니다.

IP/MAC 정보는 pcap 분석으로 얻은 값이며 역할(role)은 추정입니다.
"""

from __future__ import annotations

import argparse
import json
import mmap
import os
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import make, write  # noqa: E402

# Kitsune ARP MitM / OS Scan 망 (192.168.2.0/24) 호스트: (이름, MAC, IP, 역할)
NET2 = [
    ("gw",  "00:a0:de:f1:88:6e", "192.168.2.1",  "gateway"),
    ("h13", "10:4f:a8:70:22:7e", "192.168.2.13", "client"),
    ("h15", "ac:9b:0a:fc:2a:73", "192.168.2.15", "client"),
    ("h2",  "48:7a:da:b2:0d:ff", "192.168.2.2",  "client"),
    ("h169", "18:db:f2:01:09:33", "169.254.174.17", "client"),
    ("h7",  "00:0c:29:6a:6c:64", "192.168.2.7",  "attacker"),   # 두 캡처의 같은 공격자 VM
]
ATTACKER2 = {"mac": "00:0c:29:6a:6c:64", "ip": "192.168.2.7"}

PROFILES = {
    # ARP MitM: 전체 pcap의 ARP 1,717개를 tshark로 뽑아 확인.
    #  - Kitsune 라벨은 130만 번째 패킷부터 '공격'이지만 공격자는 141만 번째에 처음 나타나고,
    #    IP 사칭 ARP 응답 46개(192.168.2.13을 사칭해 게이트웨이에 알림)에도 라벨 0이 붙어 있음.
    #  - 구간 = 공격자 첫·마지막 ARP 패킷. ARP 없는 공격자 창(46개)은 dataset.py가
    #    '흔적 없는 공격 창'으로 학습에서 뺌.
    "arp_mitm": {
        "attack": "arp_spoof", "hosts": NET2, "attacker": ATTACKER2, "target": "192.168.2.1",
        "windows": [(1502267773.448523, 1502268224.005925)],   # 패킷 1,419,511 ~ 2,351,872
        "topology": "Kitsune ARP MitM (실제 IoT/사무망 캡처, 스위치 포트 정보 없음)",
    },
    # OS Scan: 전체 SYN 65,544개가 모두 공격자(192.168.2.7)가 게이트웨이(192.168.2.1)로
    # 보낸 것. 포트 65,535개 전부를 24.5초에 훑고(nmap 포트 스캔), 약 200초 뒤 SYN 9개를
    # 0.7초 동안 더 보냄(OS 탐지 프로브). 공격자 패킷 65,564개 중 65,561개가 TCP.
    # Kitsune 라벨 구간(패킷 1,314,659~1,576,579)은 이를 감싸지만 더 넓음.
    "os_scan": {
        "attack": "port_scan", "hosts": NET2, "attacker": ATTACKER2, "target": "192.168.2.1",
        "windows": [(1502110884.940088, 1502110909.444604),   # 포트 스캔 (패킷 1,326,390~)
                    (1502111110.394766, 1502111111.384670)],  # OS 탐지 프로브 (~패킷 1,570,844)
        "topology": "Kitsune OS Scan (실제 IoT/사무망 캡처, 스위치 포트 정보 없음)",
    },
    # SYN DoS: 공격 SYN이 캡처에 없음(pcap 전체 SYN 369개). Kitsune가 공격(라벨 1)으로 표시한
    # 7,038개는 피해 카메라(192.168.3.11)가 위조 출발지들에 보낸 SYN-ACK와 자기 정상 트래픽.
    # 미러가 피해자 쪽만 본 것으로 보임 → 공격자 기준인 우리 syn_flood 라벨을 만들 수 없음.
    # 그래서 공격 전 구간(패킷 1~2,682,349, 51분)만 잘라 '실제 망 정상 데이터'로 씀.
    "syn_dos_normal": {
        "attack": None, "attacker": None, "target": None, "windows": [],
        "hosts": [
            ("gw",   "c8:00:84:2a:39:51", "192.168.3.1",  "gateway"),
            ("cam11", "ac:9b:0a:fc:2d:8e", "192.168.3.11", "client"),
            ("cam12", "10:4f:a8:7e:77:c5", "192.168.3.12", "client"),
            ("cam13", "ac:9b:0a:33:a4:82", "192.168.3.13", "client"),
            ("cam14", "10:4f:a8:70:22:7c", "192.168.3.14", "client"),
            ("h107", "ec:08:6b:0f:a4:30", "192.168.3.107", "client"),
            ("d1",   "48:7a:da:b2:0f:76", None, "client"),   # DHCP DISCOVER만 보냄
            ("d2",   "00:0c:29:da:09:84", None, "client"),   # DHCP DISCOVER만 보냄
        ],
        "topology": "Kitsune SYN DoS 캡처의 공격 전 구간 (실제 IoT 카메라망, 정상만)",
    },
}


def pcapng_time_range(path: str) -> tuple[float, float, int]:
    """pcapng의 첫·마지막 패킷 시각과 패킷 수 (본문은 건너뛰고 블록 머리만 읽음)."""
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        n, pos, endian, res = len(m), 0, "<", []
        first = last = None
        count = 0
        while pos + 12 <= n:
            btype, blen = struct.unpack_from(endian + "II", m, pos)
            if btype == 0x0A0D0D0A:
                endian = "<" if struct.unpack_from("<I", m, pos + 8)[0] == 0x1A2B3C4D else ">"
                btype, blen = struct.unpack_from(endian + "II", m, pos)
                res = []
            elif btype == 1:
                r, o = 1e-6, pos + 16
                while o + 4 <= pos + blen - 4:
                    code, ln = struct.unpack_from(endian + "HH", m, o)
                    if code == 0:
                        break
                    if code == 9:
                        v = m[o + 4]
                        r = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                    o += 4 + ((ln + 3) // 4) * 4
                res.append(r)
            elif btype == 6:
                ifid, th, tl = struct.unpack_from(endian + "III", m, pos + 8)
                ts = ((th << 32) | tl) * res[ifid]
                first = ts if first is None else first
                last = ts
                count += 1
            if blen < 12:
                break
            pos += blen
    return first, last, count


def main() -> None:
    p = argparse.ArgumentParser(description="Kitsune pcap → 실험 폴더")
    p.add_argument("--kind", choices=sorted(PROFILES), default="arp_mitm")
    p.add_argument("--pcap", required=True, help="Kitsune pcapng (또는 잘라낸 pcapng)")
    p.add_argument("--out-root", default=str(ROOT / "data" / "runs"))
    p.add_argument("--copy", action="store_true", help="symlink 대신 pcap을 복사")
    a = p.parse_args()
    prof = PROFILES[a.kind]

    pcap = os.path.abspath(a.pcap)
    t0, t1, n = pcapng_time_range(pcap)
    if not n:
        sys.exit("패킷을 읽지 못했습니다(pcapng가 아닐 수 있음).")
    # 크롭 pcap이면 공격 구간이 파일 밖일 수 있어 겹치는 부분만 사용
    windows = [(max(s, t0), min(e, t1)) for s, e in prof["windows"]]
    windows = [(s, e) for s, e in windows if s < e]

    scenario = prof["attack"] or "normal"
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(t0))
    run_id = f"{stamp}-{scenario}"
    run_dir = Path(a.out_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    def ep(mac, ip):
        return {"mac": mac, "ip": ip, "sw": None, "port": None}

    meta = {
        "v": 1, "run_id": run_id, "scenario": scenario,
        "start_ts": t0, "end_ts": t1,
        "topology": prof["topology"],
        "hosts": [{"name": nm, "role": role, "mac": mac, "ip": ip, "sw": None, "port": None}
                  for nm, mac, ip, role in prof["hosts"]],
        "dhcp_servers": [],
        "notes": "attack=%s source=kitsune kind=%s packets=%d" % (scenario, a.kind, n),
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    with open(run_dir / "labels.jsonl", "w", encoding="utf-8") as fh:
        tgt = next((h for h in prof["hosts"] if h[2] == prof["target"]), None)
        for i, (start, end) in enumerate(windows, 1):
            att = prof["attacker"]
            write(fh, make(
                "label", ts=end, attack_id=f"a{i:02d}", attack=prof["attack"],
                start_ts=start, end_ts=end,
                attacker=ep(att["mac"], att["ip"]),
                target=ep(tgt[1], tgt[2]) if tgt else None,
                evasive=False,
                params={"tool": "unknown", "source": "kitsune", "kind": a.kind,
                        "note": "pcap에서 확인한 공격자 패킷 시각; Kitsune 패킷 라벨과 다름"}))
    has_attack = bool(windows)
    start = windows[0][0] if windows else 0.0
    end = windows[-1][1] if windows else 0.0
    link = run_dir / "capture.pcap"
    if link.exists() or link.is_symlink():
        link.unlink()
    if a.copy:
        import shutil
        shutil.copyfile(pcap, link)
    else:
        link.symlink_to(pcap)
    print(f"[import] {run_dir}")
    dur = sum(e - s for s, e in windows)
    state = (f"{len(windows)}개, 합계 {dur:.1f}초" if has_attack
             else "없음(정상 실험)" if not prof["windows"] else "없음(크롭 밖)")
    print(f"  패킷 {n:,}개, {t1 - t0:.1f}초, 공격 구간 {state}")
    print(f"다음: python3 capture/extract.py {run_dir}")


if __name__ == "__main__":
    main()
