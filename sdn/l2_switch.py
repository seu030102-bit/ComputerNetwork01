"""OS-Ken L2 학습 스위치 + 경보 기반 사후 차단 (P4, OpenFlow 1.3).

표준 learning switch에 더해, 경보 파일(inbox)에 alert 한 줄이 추가되면
공격자 MAC/포트에 우선순위 높은 drop 흐름을 설치하고 actions.jsonl에 기록합니다.

실행:
    # 기본 경로: data/sdn/inbox.jsonl → data/sdn/actions.jsonl
    PYTHONPATH=<project> osken-manager sdn.l2_switch

    # 경로 지정
    SDN_INBOX=/tmp/inbox.jsonl SDN_ACTIONS=/tmp/actions.jsonl \\
        PYTHONPATH=<project> osken-manager sdn.l2_switch

경보 넣기:
    python3 sdn/apply_alerts.py data/runs/<run_id> --inbox data/sdn/inbox.jsonl

다른 터미널에서 실험:
    sudo python3 env/run.py arp_spoof --controller remote
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                       set_ev_cls)
from os_ken.lib.packet import ethernet, packet
from os_ken.ofproto import ofproto_v1_3

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.records import write  # noqa: E402
from sdn.policy import (  # noqa: E402
    DROP_PRIORITY, BlockDeduper, block_spec, make_block_action,
)


def _default_inbox() -> Path:
    return Path(os.environ.get("SDN_INBOX", str(ROOT / "data" / "sdn" / "inbox.jsonl")))


def _default_actions() -> Path:
    return Path(os.environ.get("SDN_ACTIONS", str(ROOT / "data" / "sdn" / "actions.jsonl")))


class L2Switch(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}       # dpid -> {mac: port}
        self.datapaths = {}         # dpid -> datapath
        self._blocked = set()       # (dpid, mac|None, port|None)
        self._dedup = BlockDeduper()
        self._inbox = _default_inbox()
        self._actions_path = _default_actions()
        self._actions_fh = None
        self._stop = threading.Event()
        self._watcher = threading.Thread(target=self._watch_inbox, daemon=True)
        self._watcher.start()
        self.logger.info("inbox=%s actions=%s", self._inbox, self._actions_path)

    # ── OpenFlow 기본 ──────────────────────────────────────────

    def add_flow(self, dp, priority, match, actions, buffer_id=None, hard_timeout=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kw = dict(datapath=dp, priority=priority, match=match, instructions=inst,
                  hard_timeout=hard_timeout)
        if buffer_id is not None:
            kw["buffer_id"] = buffer_id
        dp.send_msg(parser.OFPFlowMod(**kw))

    def add_drop_flow(self, dp, match, hard_timeout=0):
        """actions 빈 목록 = drop. 학습 규칙(priority 1)보다 높은 우선순위."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # OFPIT_CLEAR_ACTIONS 또는 빈 APPLY_ACTIONS → 패킷 폐기
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [])]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=DROP_PRIORITY, match=match,
            instructions=inst, hard_timeout=hard_timeout,
            command=ofp.OFPFC_ADD))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.logger.info("switch %s 연결됨", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src, dst = eth.src, eth.dst

        # 이미 차단된 MAC/포트에서 온 PacketIn은 버리고 drop 재확인
        if self._is_blocked(dp.id, src, in_port):
            return

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][src] = in_port

        out_port = self.mac_to_port[dp.id].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(dp, 1, match, actions,
                          buffer_id=msg.buffer_id if msg.buffer_id != ofp.OFP_NO_BUFFER else None)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                return

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

    def _is_blocked(self, dpid, mac, in_port) -> bool:
        mac = (mac or "").lower()
        if (dpid, mac, None) in self._blocked:
            return True
        if (dpid, None, in_port) in self._blocked:
            return True
        if (dpid, mac, in_port) in self._blocked:
            return True
        return False

    # ── 차단 ───────────────────────────────────────────────────

    def block_from_alert(self, alert: dict) -> dict | None:
        """경보 1건을 처리해 drop을 설치하고 action 기록을 돌려준다(실패·스킵은 None 가능)."""
        spec = block_spec(alert)
        if spec is None:
            self.logger.warning("차단 불가(대상 MAC/포트 없음): %s",
                                alert.get("alert_id"))
            return None

        ts = float(alert.get("ts") or time.time())
        if not self._dedup.allow(spec, ts):
            self.logger.info("중복 차단 건너뜀: %s", spec["reason"])
            return None

        dpid = spec["dpid"]
        dp = self.datapaths.get(dpid)
        t0 = time.time()
        ok = False
        err = None
        if dp is None:
            err = f"switch dpid={dpid} 미연결"
        else:
            try:
                self._install_drop(dp, spec)
                key = (dpid, spec.get("mac"), spec.get("port")
                       if spec["match"] == "port" else (
                           spec.get("port") if spec["match"] == "mac+port" else None))
                if spec["match"] == "mac":
                    key = (dpid, spec["mac"], None)
                elif spec["match"] == "port":
                    key = (dpid, None, spec["port"])
                else:
                    key = (dpid, spec["mac"], spec["port"])
                self._blocked.add(key)
                ok = True
            except Exception as exc:  # noqa: BLE001 — 컨트롤러 로그 후 action에 남김
                err = str(exc)
                self.logger.exception("drop 설치 실패")

        install_ms = (time.time() - t0) * 1000.0
        reason = spec["reason"] if ok else f"{spec['reason']} ({err})"
        spec = {**spec, "reason": reason}
        action = make_block_action(alert, spec, ok=ok, install_ms=install_ms)
        self._write_action(action)
        self.logger.info("block ok=%s %s (%.1fms)", ok, reason, install_ms)
        return action

    def _install_drop(self, dp, spec: dict) -> None:
        parser = dp.ofproto_parser
        kw = {}
        if spec.get("mac"):
            kw["eth_src"] = spec["mac"]
        if spec.get("port") is not None and spec["match"] in ("port", "mac+port"):
            kw["in_port"] = int(spec["port"])
        match = parser.OFPMatch(**kw)
        self.add_drop_flow(dp, match)

    def _write_action(self, action: dict) -> None:
        self._actions_path.parent.mkdir(parents=True, exist_ok=True)
        if self._actions_fh is None:
            self._actions_fh = open(self._actions_path, "a", encoding="utf-8")
        write(self._actions_fh, action)

    # ── inbox tail ─────────────────────────────────────────────

    def _watch_inbox(self) -> None:
        """data-format §5: 파일 끝에 붙는 alert JSONL을 tail -f 방식으로 읽음."""
        path = self._inbox
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        offset = path.stat().st_size  # 기존 내용은 건너뛰고 새 줄만
        while not self._stop.is_set():
            try:
                size = path.stat().st_size
                if size < offset:
                    offset = 0  # truncate 됨
                if size > offset:
                    with open(path, encoding="utf-8") as fh:
                        fh.seek(offset)
                        # for line in fh 는 순회 중 tell()이 OSError → readline 사용
                        while True:
                            line = fh.readline()
                            if not line or not line.endswith("\n"):
                                break  # EOF 또는 아직 덜 쓰인 마지막 줄은 다음 주기에 다시 읽음
                            offset = fh.tell()
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                rec = json.loads(line)
                            except json.JSONDecodeError:
                                self.logger.warning("inbox JSON 오류: %s", line[:80])
                                continue
                            if rec.get("type") == "alert":
                                self.block_from_alert(rec)
            except FileNotFoundError:
                path.touch(exist_ok=True)
            except Exception:  # noqa: BLE001
                self.logger.exception("inbox 감시 오류")
            self._stop.wait(0.2)
