#!/usr/bin/env bash
# 통합 테스트 (P1, 12주차)
#
# run_demo.sh로 여러 시나리오를 돌려 "공격 -> 캡처 -> 특징 추출 -> 규칙 탐지
# -> 평가 -> 형식 검사" 전체 파이프라인이 끝까지 도는지 확인한다.
#
# 회피 시나리오(arp_spoof_slow 등)는 탐지가 안 될 수도 있는 게 연구
# 질문이므로, 경보 개수는 참고용으로만 보여주고 통과/실패 판정에는
# 쓰지 않는다. 판정 기준은 "파이프라인이 오류 없이 끝까지 돌고,
# 기록 형식이 데이터 형식(docs/data-format.md)에 맞는가"이다.
#
# 사용법:
#   sudo ./integration_test.sh                 # 빠른 확인(2개 시나리오)
#   sudo ./integration_test.sh --all           # 전체 시나리오
#   sudo ./integration_test.sh arp_spoof mac_flood   # 지정한 시나리오만

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ "$(id -u)" -ne 0 ]; then
  echo "root 권한이 필요합니다: sudo ./integration_test.sh" >&2
  exit 1
fi

ALL_SCENARIOS=(arp_spoof arp_spoof_slow mac_flood dhcp_starve dhcp_rogue \
               port_scan port_scan_slow syn_flood syn_flood_slow mixed_attack \
               mixed_arp_spoof mixed_syn_flood)

if [ "${1:-}" = "--all" ]; then
  SCENARIOS=("${ALL_SCENARIOS[@]}")
elif [ "$#" -ge 1 ]; then
  SCENARIOS=("$@")
else
  SCENARIOS=(arp_spoof arp_spoof_slow)
fi

export PYTHONPATH="$PWD"
PASS=0
FAIL=0
declare -a ROWS

for s in "${SCENARIOS[@]}"; do
  echo "== $s =="
  if ./run_demo.sh "$s" --quiet --no-model; then
    RUN_DIR=$(ls -dt data/runs/*/ 2>/dev/null | head -1)
    RUN_DIR="${RUN_DIR%/}"
    N=0
    [ -f "$RUN_DIR/alerts_rule.jsonl" ] && N=$(wc -l < "$RUN_DIR/alerts_rule.jsonl")
    echo "  OK  (규칙 경보 ${N}개, $RUN_DIR)"
    PASS=$((PASS + 1))
    ROWS+=("| $s | OK | ${N} | $RUN_DIR |")
  else
    echo "  FAIL (run_demo.sh 오류, 위 로그 참고)"
    FAIL=$((FAIL + 1))
    ROWS+=("| $s | FAIL | - | - |")
  fi
done

echo
echo "| 시나리오 | 결과 | 규칙 경보 수 | 폴더 |"
echo "|---|---|---|---|"
for r in "${ROWS[@]}"; do echo "$r"; done
echo
echo "통과 ${PASS} / 실패 ${FAIL} (총 ${#SCENARIOS[@]})"

[ "$FAIL" -eq 0 ]
