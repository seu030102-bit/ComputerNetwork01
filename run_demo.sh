#!/usr/bin/env bash
# 데모 실행기 (P1, 12주차)
#
# 공격 하나를 Mininet에서 재현하고, 캡처 -> 특징 추출 -> 규칙 탐지 ->
# (있으면) AI 추론 -> 성능 평가 -> 형식 검사까지 한 번에 잇는다.
#
# README 12주차 완료 기준: "ARP 스푸핑을 실행하면 대시보드에 경보가 뜨고
# 공격자가 차단됨". SDN 차단(P4)은 탐지 후 actions.jsonl 기록까지 이 스크립트가
# 잇는다(오프라인 action). 대시보드 실시간 연결(P5)과 실험 중 라이브 drop은
# sdn/README.md 의 라이브 절차를 따른다.
#
# 사용법:
#   sudo ./run_demo.sh [시나리오] [옵션]
#
# 옵션:
#   --controller=remote   OS-Ken(osken-manager sdn.l2_switch)을 자동으로 띄워 붙임
#   --no-model             AI 추론(model/infer.py) 생략
#   --quiet                진행 메시지 생략, 마지막 요약만 출력
#
# 예:
#   sudo ./run_demo.sh arp_spoof
#   sudo ./run_demo.sh mixed_attack --controller=remote

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

SCENARIO="arp_spoof"
CONTROLLER="ovs"
RUN_MODEL=1
QUIET=0

for a in "$@"; do
  case "$a" in
    --controller=remote) CONTROLLER="remote" ;;
    --controller=ovs) CONTROLLER="ovs" ;;
    --no-model) RUN_MODEL=0 ;;
    --quiet) QUIET=1 ;;
    --*) echo "모르는 옵션: $a" >&2; exit 2 ;;
    *) SCENARIO="$a" ;;
  esac
done

log() { [ "$QUIET" -eq 1 ] || echo "$@"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "root 권한이 필요합니다: sudo ./run_demo.sh $SCENARIO" >&2
  exit 1
fi

export PYTHONPATH="$PWD"

OSKEN_PID=""
cleanup() {
  if [ -n "$OSKEN_PID" ]; then
    kill "$OSKEN_PID" 2>/dev/null || true
    wait "$OSKEN_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [ "$CONTROLLER" = "remote" ]; then
  if ! command -v osken-manager >/dev/null 2>&1; then
    echo "osken-manager 없음. --controller=remote 는 OS-Ken 설치 후 쓰세요." >&2
    exit 1
  fi
  mkdir -p data/sdn
  : > /tmp/run_demo_sdn_inbox.jsonl
  : > /tmp/run_demo_sdn_actions.jsonl
  log "[demo] OS-Ken 컨트롤러 시작 (sdn.l2_switch)"
  SDN_INBOX=/tmp/run_demo_sdn_inbox.jsonl \
  SDN_ACTIONS=/tmp/run_demo_sdn_actions.jsonl \
    osken-manager sdn.l2_switch >/tmp/run_demo_osken.log 2>&1 &
  OSKEN_PID=$!
  sleep 2
  if ! kill -0 "$OSKEN_PID" 2>/dev/null; then
    echo "OS-Ken 시작 실패. 로그: /tmp/run_demo_osken.log" >&2
    exit 1
  fi
fi

log "[demo] 1/6 실험 실행: $SCENARIO (controller=$CONTROLLER)"
if [ "$CONTROLLER" = "remote" ]; then
  python3 env/run.py "$SCENARIO" --controller remote
else
  python3 env/run.py "$SCENARIO"
fi
RUN_RC=$?
if [ "$RUN_RC" -ne 0 ]; then
  echo "[demo] 실험 실행 실패 (exit $RUN_RC)" >&2
  exit "$RUN_RC"
fi

RUN_DIR=$(ls -dt data/runs/*/ 2>/dev/null | head -1)
if [ -z "$RUN_DIR" ]; then
  echo "[demo] data/runs/ 에 결과 폴더가 없습니다." >&2
  exit 1
fi
RUN_DIR="${RUN_DIR%/}"
log "[demo] 실험 폴더: $RUN_DIR"

log "[demo] 2/6 특징 추출"
python3 capture/extract.py "$RUN_DIR" || { echo "[demo] 특징 추출 실패" >&2; exit 1; }

log "[demo] 3/7 규칙 탐지"
python3 rules/detect.py "$RUN_DIR" || { echo "[demo] 규칙 탐지 실패" >&2; exit 1; }

if [ "$RUN_MODEL" -eq 1 ] && [ -f model/rf.joblib ] && [ -f model/infer.py ]; then
  log "[demo] 4/7 AI 추론"
  python3 model/infer.py "$RUN_DIR" || log "[demo] AI 추론 건너뜀(오류, 계속 진행)"
else
  log "[demo] 4/7 AI 추론 건너뜀(모델 없음 또는 --no-model)"
fi

log "[demo] 5/7 SDN 차단 action 기록"
if [ -f sdn/apply_alerts.py ]; then
  # 실험 종료 후라 스위치는 보통 끊김 → offline action으로 평가 파이프라인 완결
  # (실험 중 라이브 drop은 sdn/README.md 절차)
  python3 sdn/apply_alerts.py "$RUN_DIR" --offline || log "[demo] SDN action 기록 실패(계속)"
  if [ "$CONTROLLER" = "remote" ]; then
    python3 sdn/apply_alerts.py "$RUN_DIR" \
      --inbox /tmp/run_demo_sdn_inbox.jsonl --wait 0.3 2>/dev/null || true
  fi
else
  log "[demo] 5/7 SDN 건너뜀(sdn/apply_alerts.py 없음)"
fi

log "[demo] 6/7 성능 평가"
if [ -f eval/report.py ]; then
  python3 eval/report.py "$RUN_DIR" --week demo 2>/dev/null || python3 eval/evaluate.py "$RUN_DIR"
else
  python3 eval/evaluate.py "$RUN_DIR"
fi

log "[demo] 7/7 형식 검사"
python3 common/records.py check "$RUN_DIR"
CHECK_RC=$?

echo
echo "[demo] 완료: $RUN_DIR"
for f in alerts_rule.jsonl alerts_ai.jsonl actions.jsonl; do
  if [ -f "$RUN_DIR/$f" ]; then
    N=$(wc -l < "$RUN_DIR/$f")
    echo "[demo]   $f: ${N}줄"
  fi
done
echo "[demo] 대시보드로 보려면: ~/.venvs/dash/bin/streamlit run dashboard/app.py  ($RUN_DIR 선택)"
echo "[demo] 라이브 drop 검증: sdn/README.md 참고"

exit "$CHECK_RC"
