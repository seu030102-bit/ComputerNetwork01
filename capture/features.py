"""패킷 → 특징 기록(feat_host, feat_seg) 집계기 (P2). 오프라인·실시간 공용.

`extract.py`(pcap 파일)와 `live.py`(실시간 캡처)가 이 클래스 하나를 같이 씁니다.
그래서 같은 패킷이면 오프라인과 실시간 특징이 똑같이 나옵니다. 형식은 data-format 2.2, 2.3.

    agg = FeatureAggregator(mac2port, mac2ip)
    for pkt in packets:          # 시각 순서
        agg.add(pkt)
    out = agg.flush(upto_ts)     # 창 끝 ≤ upto_ts 인 창을 기록으로 (None이면 전부)
    out[1] -> (host 기록들, seg 기록들)   # 1초 창
    out[5] -> (host 기록들, seg 기록들)   # 5초 창

핵심 계산(data-format 2.2):
  - 패킷을 시각 순서로 보며 IP-MAC 대응표를 학습(처음 본 쌍 등록, DHCP ACK로 갱신).
  - ARP 응답/Gratuitous ARP가 주장한 IP가 대응표에 다른 MAC으로 있으면 충돌(arp_ip_conflicts).
  - 최근 5초 내 해당 IP에 대한 who-has 요청이 없었던 ARP 응답은 미요청 응답(arp_rep_unsolicited).

창은 첫 패킷 시각 t0 기준 [t0 + k·w, t0 + (k+1)·w) 이고, 기록의 ts는 창이 끝난 시각입니다.
이미 내보낸 창에 늦게 도착한 패킷은 버리고 `late`로 셉니다(실시간에서만 생김).
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.records import make  # noqa: E402

WINDOWS = (1, 5)
UNSOLICITED_WINDOW = 5.0  # 요청-응답을 짝지을 때 보는 시간(초)


class HostAgg:
    """한 (창, MAC)의 집계."""
    __slots__ = ("pkts", "bytes", "arp_req", "arp_rep", "arp_grat",
                 "arp_rep_unsolicited", "claims", "conflicts",
                 "dhcp_offer", "dhcp_ack", "dhcp_discover",
                 "tcp_syn", "tcp_synack_in", "tcp_rst_in", "icmp_unreach_in",
                 "dns_resp", "dst_ip_count", "dst_port_set", "ip")

    def __init__(self):
        for f in self.__slots__:
            setattr(self, f, 0)
        self.claims = set()
        self.conflicts = set()
        self.dst_ip_count = defaultdict(int)
        self.dst_port_set = set()
        self.ip = None


class SegAgg:
    __slots__ = ("pkts", "bytes", "src_macs", "new_src_macs", "dhcp_discover",
                 "dhcp_chaddrs", "dhcp_offer", "dhcp_servers", "arp_rep", "tcp_syn")

    def __init__(self):
        for f in self.__slots__:
            setattr(self, f, 0)
        self.src_macs = set()
        self.new_src_macs = set()
        self.dhcp_chaddrs = set()
        self.dhcp_servers = set()


def hosts_from_meta(meta: dict) -> tuple[dict, dict]:
    """meta.json → (MAC→(sw, port), MAC→IP)."""
    mac2port, mac2ip = {}, {}
    for h in meta["hosts"]:
        mac2port[h["mac"]] = (h["sw"], h["port"])
        mac2ip[h["mac"]] = h["ip"]
    return mac2port, mac2ip


def hosts_from_env() -> tuple[dict, dict]:
    """env/hosts.py(토폴로지 단일 기준) → 같은 표. 실시간에는 meta.json이 실험 끝에 생기므로 이걸 씀."""
    from env.hosts import HOSTS, SWITCH
    return ({h.mac: (SWITCH, h.port) for h in HOSTS}, {h.mac: h.ip for h in HOSTS})


class FeatureAggregator:
    def __init__(self, mac2port: dict, mac2ip: dict, windows=WINDOWS):
        from scapy.all import (ARP, BOOTP, DHCP, DNS, ICMP, IP, TCP, UDP,  # noqa: F401
                               Ether)
        self._L = dict(ARP=ARP, BOOTP=BOOTP, DHCP=DHCP, DNS=DNS, ICMP=ICMP, IP=IP,
                       TCP=TCP, UDP=UDP, Ether=Ether)
        self.mac2port, self.mac2ip = mac2port, mac2ip
        self.windows = tuple(windows)
        self.bindings: dict[str, str] = {}       # ip -> mac (학습된 대응표)
        self.recent_req: dict[str, float] = {}   # who-has 대상 ip -> 마지막 요청 시각
        self.seen_src_macs: set[str] = set()     # 지금까지 등장한 출발지 MAC(새 MAC 판정용)
        # 집계: win -> window_index -> key -> Agg
        self.host_agg = {w: defaultdict(lambda: defaultdict(HostAgg)) for w in self.windows}
        self.seg_agg = {w: defaultdict(lambda: defaultdict(SegAgg)) for w in self.windows}
        self.done = {w: -1 for w in self.windows}  # 이미 내보낸 마지막 창 번호
        self.t0: float | None = None
        self.packets = 0
        self.late = 0

    def _port_of(self, mac):
        return self.mac2port.get(mac, (None, None))

    def window_end(self, w: int, idx: int) -> float:
        return self.t0 + (idx + 1) * w

    # ------------------------------------------------------------ 패킷 하나

    def add(self, pkt) -> None:
        L = self._L
        ARP, BOOTP, DHCP, DNS = L["ARP"], L["BOOTP"], L["DHCP"], L["DNS"]
        ICMP, IP, TCP, UDP, Ether = L["ICMP"], L["IP"], L["TCP"], L["UDP"], L["Ether"]
        if not pkt.haslayer(Ether):
            return
        ts = float(pkt.time)
        if self.t0 is None:
            self.t0 = ts
        eth = pkt[Ether]
        smac, dmac = eth.src.lower(), eth.dst.lower()
        # 캡처 포트(mon0) 자신이 켜질 때 내보내는 IPv6 자동 설정 패킷은 실험 트래픽이 아님.
        # 실험망은 IPv4 전용이므로 meta에 없는 MAC의 IPv6 패킷은 버림.
        if eth.type == 0x86DD and smac not in self.mac2port:
            return
        idxs = {w: int((ts - self.t0) // w) for w in self.windows}
        if any(idxs[w] <= self.done[w] for w in self.windows):
            self.late += 1      # 이미 내보낸 창 → 버림 (실시간 지연 패킷)
            return
        self.packets += 1
        size = len(pkt)
        seen_new = smac not in self.seen_src_macs
        self.seen_src_macs.add(smac)
        sw, port = self._port_of(smac)

        # ARP 상태 갱신 (전역 시간순)
        is_unsolicited = conflict_ip = claim_ip = None
        arp_kind = None
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            psrc, pdst = arp.psrc, arp.pdst
            hwsrc = (arp.hwsrc or smac).lower()
            if arp.op == 1:          # who-has (요청)
                arp_kind = "req"
                self.recent_req[pdst] = ts
            elif arp.op == 2:        # is-at (응답)
                arp_kind = "rep"
                claim_ip = psrc
                last = self.recent_req.get(psrc)
                is_unsolicited = (last is None) or (ts - last > UNSOLICITED_WINDOW)
                bound = self.bindings.get(psrc)
                if bound is not None and bound != hwsrc:
                    conflict_ip = psrc
                else:
                    self.bindings.setdefault(psrc, hwsrc)
            if arp.op == 2 and psrc == pdst:
                arp_kind = "grat"    # gratuitous

        # DHCP 메시지 종류
        dhcp_kind = None
        if pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    dhcp_kind = {1: "discover", 2: "offer", 3: "request",
                                 5: "ack"}.get(opt[1])
            if dhcp_kind == "ack" and pkt.haslayer(BOOTP):   # DHCP ACK가 가장 신뢰
                yi = getattr(pkt[BOOTP], "yiaddr", None)
                if yi and yi != "0.0.0.0":
                    self.bindings[yi] = smac

        for w in self.windows:
            idx = idxs[w]
            h = self.host_agg[w][idx][smac]
            h.pkts += 1
            h.bytes += size
            if pkt.haslayer(IP):
                ipl = pkt[IP]
                if h.ip is None:
                    h.ip = ipl.src
                h.dst_ip_count[ipl.dst] += 1
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    if tcp.dport:
                        h.dst_port_set.add(int(tcp.dport))
                    flags = int(tcp.flags)
                    if flags & 0x02 and not flags & 0x10:
                        h.tcp_syn += 1
                elif pkt.haslayer(UDP):
                    if pkt[UDP].dport:
                        h.dst_port_set.add(int(pkt[UDP].dport))
                    if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                        h.dns_resp += 1
            if arp_kind == "req":
                h.arp_req += 1
            elif arp_kind in ("rep", "grat"):
                h.arp_rep += 1
                if arp_kind == "grat":
                    h.arp_grat += 1
                if is_unsolicited:
                    h.arp_rep_unsolicited += 1
                if claim_ip:
                    h.claims.add(claim_ip)
                if conflict_ip:
                    h.conflicts.add(conflict_ip)
            if dhcp_kind == "offer":
                h.dhcp_offer += 1
            elif dhcp_kind == "ack":
                h.dhcp_ack += 1
            elif dhcp_kind == "discover":
                h.dhcp_discover += 1

            # 받은 쪽(_in) 집계: 목적지 MAC 기준
            din = self.host_agg[w][idx].get(dmac)
            if din is not None or dmac in self.seen_src_macs:
                din = self.host_agg[w][idx][dmac]
                if pkt.haslayer(TCP):
                    f = int(pkt[TCP].flags)
                    if f & 0x12 == 0x12:
                        din.tcp_synack_in += 1
                    if f & 0x04:
                        din.tcp_rst_in += 1
                if pkt.haslayer(ICMP) and int(pkt[ICMP].type) == 3:
                    din.icmp_unreach_in += 1

            # 구간(포트) 집계 — MAC으로 포트 역산, 모르면 null 구간
            s = self.seg_agg[w][idx][(sw, port)]
            s.pkts += 1
            s.bytes += size
            s.src_macs.add(smac)
            if seen_new:
                s.new_src_macs.add(smac)
            if arp_kind in ("rep", "grat"):
                s.arp_rep += 1
            if pkt.haslayer(TCP) and int(pkt[TCP].flags) & 0x02 and not int(pkt[TCP].flags) & 0x10:
                s.tcp_syn += 1
            if dhcp_kind == "discover":
                s.dhcp_discover += 1
                ch = getattr(pkt[BOOTP], "chaddr", b"")[:6] if pkt.haslayer(BOOTP) else b""
                if ch:
                    s.dhcp_chaddrs.add(bytes(ch))
            elif dhcp_kind == "offer":
                s.dhcp_offer += 1
                s.dhcp_servers.add(smac)

    # ------------------------------------------------------------ 기록 내보내기

    def flush(self, upto_ts: float | None = None) -> dict[int, tuple[list, list]]:
        """창 끝 ≤ upto_ts 인 창을 기록으로 바꿔 돌려주고 메모리에서 지움. None이면 전부."""
        out: dict[int, tuple[list, list]] = {w: ([], []) for w in self.windows}
        if self.t0 is None:
            return out
        for w in self.windows:
            hosts, segs = out[w]
            ready = sorted(i for i in set(self.host_agg[w]) | set(self.seg_agg[w])
                           if upto_ts is None or self.window_end(w, i) <= upto_ts)
            for idx in ready:
                hosts += self._host_records(w, idx, self.host_agg[w].pop(idx, {}))
            for idx in ready:
                segs += self._seg_records(w, idx, self.seg_agg[w].pop(idx, {}))
            if upto_ts is not None:
                # 패킷이 없던 창도 '지나간 창'으로 표시 → 늦게 온 패킷이 옛 창을 다시 만들지 않게
                last = int((upto_ts - self.t0) // w) - 1
                self.done[w] = max(self.done[w], last, *(ready or [-1]))
            elif ready:
                self.done[w] = max(self.done[w], ready[-1])
        return out

    def _host_records(self, w, idx, aggs) -> list:
        win_end = self.window_end(w, idx)
        recs = []
        for mac, h in sorted(aggs.items()):
            if h.pkts == 0:
                continue  # 보낸 게 없으면 기록 안 함
            sw, port = self.mac2port.get(mac, (None, None))
            total = sum(h.dst_ip_count.values())
            top = max(h.dst_ip_count.values()) / total if total else 0.0
            recs.append(make(
                "feat_host", ts=win_end, win=w,
                host={"mac": mac, "ip": h.ip or self.mac2ip.get(mac), "sw": sw, "port": port},
                pkts=h.pkts, bytes=h.bytes, arp_req=h.arp_req,
                arp_rep=h.arp_rep, arp_grat=h.arp_grat,
                arp_rep_unsolicited=h.arp_rep_unsolicited,
                arp_ip_claims=len(h.claims), arp_ip_conflicts=len(h.conflicts),
                dhcp_offer=h.dhcp_offer, dhcp_ack=h.dhcp_ack,
                dhcp_discover=h.dhcp_discover, tcp_syn=h.tcp_syn,
                tcp_synack_in=h.tcp_synack_in, tcp_rst_in=h.tcp_rst_in,
                icmp_unreach_in=h.icmp_unreach_in,
                dst_ips=len(h.dst_ip_count), dst_ports=len(h.dst_port_set),
                top_dst_share=round(top, 4), dns_resp=h.dns_resp))
        return recs

    def _seg_records(self, w, idx, aggs) -> list:
        win_end = self.window_end(w, idx)
        recs = []
        for (sw, port), s in sorted(
                aggs.items(),
                key=lambda kv: (kv[0][0] or "", -1 if kv[0][1] is None else kv[0][1])):
            recs.append(make(
                "feat_seg", ts=win_end, win=w, sw=sw, port=port,
                pkts=s.pkts, bytes=s.bytes, src_macs=len(s.src_macs),
                new_src_macs=len(s.new_src_macs), dhcp_discover=s.dhcp_discover,
                dhcp_chaddrs=len(s.dhcp_chaddrs), dhcp_offer=s.dhcp_offer,
                dhcp_servers=len(s.dhcp_servers), arp_rep=s.arp_rep,
                tcp_syn=s.tcp_syn))
        return recs
