"""시나리오 정의 — 어떤 공격을, 누가, 어떤 설정으로.

run.py가 이 정의를 읽어서 (1) 공격 스크립트를 공격자 호스트에서 실행하고
(2) data-format.md의 label 기록을 만듭니다. label의 attacker/target/evasive/params가
여기서 나옵니다.

10주차 목표는 arp_spoof 와 mac_flood 입니다. 나머지 공격은 11주차에 채웁니다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from env.hosts import GATEWAY_IP, by_name


@dataclass
class Scenario:
    name: str
    attack: str                      # data-format.md의 공격 종류
    attacker: str                    # 호스트 이름
    module: str                      # python -m 로 실행할 공격 모듈
    args: list[str]                  # 공격 스크립트 인자 (iface는 run.py가 채움)
    target: str | None = None        # 피해자 호스트 이름 (없으면 None)
    evasive: bool = False
    params: dict = field(default_factory=dict)
    warmup: float = 10.0             # 공격 전 정상 트래픽만 흐르는 시간(초)
    attack_dur: float = 30.0         # 공격 지속 시간(초)
    cooldown: float = 5.0            # 공격 후 정상 트래픽 시간(초)

    @property
    def duration(self) -> float:
        return self.warmup + self.attack_dur + self.cooldown


SCENARIOS: dict[str, Scenario] = {
    # ARP 스푸핑: h4가 게이트웨이(10.0.0.254)를 사칭, 피해자 h1
    "arp_spoof": Scenario(
        name="arp_spoof", attack="arp_spoof", attacker="h4", target="h1",
        module="env.attacks.arp_spoof",
        args=["--spoof-ip", GATEWAY_IP, "--victim-ip", "10.0.0.1", "--rate", "2"],
        params={"tool": "scapy", "rate_pps": 2, "spoofed_ip": GATEWAY_IP},
    ),
    # 느린 ARP 스푸핑(회피): 초당 0.2개로 아주 천천히 — 규칙 임계치를 피하려는 공격
    "arp_spoof_slow": Scenario(
        name="arp_spoof_slow", attack="arp_spoof", attacker="h4", target="h1",
        module="env.attacks.arp_spoof",
        args=["--spoof-ip", GATEWAY_IP, "--victim-ip", "10.0.0.1", "--rate", "0.2"],
        evasive=True, attack_dur=60.0,
        params={"tool": "scapy", "rate_pps": 0.2, "spoofed_ip": GATEWAY_IP, "evasion": "low-rate"},
    ),
    # MAC 플러딩: h4가 가짜 출발지 MAC을 대량 전송 (대상 없음)
    "mac_flood": Scenario(
        name="mac_flood", attack="mac_flood", attacker="h4", target=None,
        module="env.attacks.mac_flood",
        args=["--rate", "500"], attack_dur=20.0,
        params={"tool": "scapy", "rate_fps": 500},
    ),
    # DHCP 고갈: h4가 가짜 MAC으로 DISCOVER를 대량 전송해 dhcp 서버의 풀을 소진
    # (모듈 파일명은 dhcp_exhaust, data-format.md의 attack 값은 dhcp_starve)
    "dhcp_starve": Scenario(
        name="dhcp_starve", attack="dhcp_starve", attacker="h4", target="dhcp",
        module="env.attacks.dhcp_exhaust",
        args=["--rate", "20"], attack_dur=30.0,
        params={"tool": "scapy", "rate_pps": 20},
    ),
    # 가짜 DHCP 서버: h4가 정상 서버(dhcp)를 사칭해 OFFER/ACK로 자신을 게이트웨이로 안내
    "dhcp_rogue": Scenario(
        name="dhcp_rogue", attack="dhcp_rogue", attacker="h4", target="h1",
        module="env.attacks.dhcp_rogue",
        args=["--server-ip", "10.0.0.4", "--offer-ip", "10.0.0.200"],
        attack_dur=30.0,
        params={"tool": "scapy", "spoofed_server_ip": "10.0.0.4", "offer_ip": "10.0.0.200"},
    ),
    # nmap 포트 스캔: h4가 h1의 1~1000번 포트를 SYN 스캔
    "port_scan": Scenario(
        name="port_scan", attack="port_scan", attacker="h4", target="h1",
        module="env.attacks.port_scan",
        args=["--target-ip", "10.0.0.1", "--ports", "1-1000"], attack_dur=30.0,
        params={"tool": "nmap", "ports": "1-1000"},
    ),
    # 느린 포트 스캔(회피): -T1 타이밍, 포트 순서 섞음
    "port_scan_slow": Scenario(
        name="port_scan_slow", attack="port_scan", attacker="h4", target="h1",
        module="env.attacks.port_scan",
        args=["--target-ip", "10.0.0.1", "--ports", "1-200", "--evasive"],
        evasive=True, attack_dur=60.0,
        params={"tool": "nmap", "ports": "1-200", "evasion": "slow-timing"},
    ),
    # SYN flood: h4가 가짜 출발지 IP로 h1의 80포트에 SYN을 대량 전송
    "syn_flood": Scenario(
        name="syn_flood", attack="syn_flood", attacker="h4", target="h1",
        module="env.attacks.syn_flood",
        args=["--target-ip", "10.0.0.1", "--target-port", "80", "--rate", "200"],
        attack_dur=20.0,
        params={"tool": "scapy", "rate_pps": 200, "target_port": 80},
    ),
    # 저속 SYN flood(회피): 초당 5개로 아주 천천히
    "syn_flood_slow": Scenario(
        name="syn_flood_slow", attack="syn_flood", attacker="h4", target="h1",
        module="env.attacks.syn_flood",
        args=["--target-ip", "10.0.0.1", "--target-port", "80", "--rate", "5"],
        evasive=True, attack_dur=60.0,
        params={"tool": "scapy", "rate_pps": 5, "target_port": 80, "evasion": "low-rate"},
    ),
    # 정상 트래픽에 섞은 공격(회피): h4가 보통 클라이언트처럼 웹/DNS/동영상/파일
    # 트래픽을 보내면서 그 사이에 느린 port_scan을 끼워 넣음
    "mixed_attack": Scenario(
        name="mixed_attack", attack="port_scan", attacker="h4", target="h1",
        module="env.attacks.mixed_attack",
        args=["--target-ip", "10.0.0.1", "--http-port", "8000",
              "--base", "port_scan", "--seed", "7"],
        evasive=True, attack_dur=60.0,
        params={"tool": "scapy", "base": "port_scan", "ports": "1-200",
                "evasion": "blended-with-normal"},
    ),
    # 정상 트래픽에 섞은 느린 ARP 스푸핑(회피)
    "mixed_arp_spoof": Scenario(
        name="mixed_arp_spoof", attack="arp_spoof", attacker="h4", target="h1",
        module="env.attacks.mixed_attack",
        args=["--target-ip", "10.0.0.1", "--http-port", "8000",
              "--base", "arp_spoof", "--seed", "7"],
        evasive=True, attack_dur=60.0,
        params={"tool": "scapy", "base": "arp_spoof", "rate_pps": 0.2,
                "spoofed_ip": GATEWAY_IP, "evasion": "blended-with-normal"},
    ),
    # 정상 트래픽에 섞은 저속 SYN flood(회피)
    "mixed_syn_flood": Scenario(
        name="mixed_syn_flood", attack="syn_flood", attacker="h4", target="h1",
        module="env.attacks.mixed_attack",
        args=["--target-ip", "10.0.0.1", "--http-port", "8000",
              "--base", "syn_flood", "--seed", "7"],
        evasive=True, attack_dur=60.0,
        params={"tool": "scapy", "base": "syn_flood", "rate_pps": 5,
                "target_port": 80, "evasion": "blended-with-normal"},
    ),
}


def get(name: str) -> Scenario:
    if name not in SCENARIOS:
        raise KeyError(f"없는 시나리오: {name}. 가능: {sorted(SCENARIOS)}")
    return SCENARIOS[name]
