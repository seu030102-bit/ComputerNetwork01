"""Streamlit 대시보드 (P5, 12주차).

경보 자동 갱신: 경보·행동 파일을 주기적으로 감시해 새 경보를 실시간 표시합니다.

실행 (대시보드 전용 venv에서):
    ~/.venvs/dash/bin/streamlit run dashboard/app.py
"""

from __future__ import annotations

import time
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.load import (  # noqa: E402
    action_rows, alert_rows, file_sizes, is_live, list_runs, summarize,
)

_REFRESH_DEFAULT = 5


def _run_label(run_dir: Path, live: bool) -> str:
    return f"🔴 {run_dir.name}" if live else run_dir.name


def main() -> None:
    st.set_page_config(page_title="LAN 공격 탐지 대시보드", page_icon="🛡️",
                       layout="wide")
    st.title("🛡️ LAN 공격 탐지 대시보드")

    # --- 사이드바 ---
    with st.sidebar:
        st.header("설정")
        auto_refresh = st.checkbox("실시간 자동 갱신", value=True)
        refresh_interval = (
            st.slider("갱신 주기 (초)", min_value=2, max_value=30,
                      value=_REFRESH_DEFAULT, step=1)
            if auto_refresh else _REFRESH_DEFAULT
        )
        st.divider()

        runs = list_runs()
        if not runs:
            st.warning("data/runs 에 실험 결과가 없습니다. 먼저 env/run.py 를 실행하세요.")
            return

        live_set = {r for r in runs if is_live(r)}
        labels = [_run_label(r, r in live_set) for r in runs]
        label_to_run = dict(zip(labels, runs))

        # 처음 접속 시: 라이브 실험 있으면 그것을, 없으면 최신 실험 선택
        if "run_label" not in st.session_state or st.session_state.run_label not in labels:
            live_labels = [lb for lb in labels if lb.startswith("🔴")]
            st.session_state.run_label = live_labels[0] if live_labels else labels[0]

        st.session_state.run_label = st.selectbox(
            "실험 선택", labels,
            index=labels.index(st.session_state.run_label),
        )

    run_dir = label_to_run[st.session_state.run_label]
    is_running = run_dir in live_set

    # 실험이 바뀌면 이전 파일 크기 초기화
    if st.session_state.get("prev_run") != run_dir.name:
        st.session_state.prev_run = run_dir.name
        st.session_state.prev_sizes = {}

    prev_sizes = st.session_state.get("prev_sizes", {})
    curr_sizes = file_sizes(run_dir)
    has_new = curr_sizes != prev_sizes
    st.session_state.prev_sizes = curr_sizes

    # --- 헤더 뱃지 ---
    col_title, col_badge = st.columns([7, 1])
    with col_title:
        st.subheader(f"실험: `{run_dir.name}`")
    with col_badge:
        if is_running:
            st.success("🔴 LIVE")
        elif has_new:
            st.info("🔄 갱신됨")

    # --- 요약 메트릭 ---
    s = summarize(run_dir)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("시나리오", s["scenario"])
    c2.metric("공격", ", ".join(s["attacks"]) or "-")
    c3.metric("경보 수", s["n_alerts"])
    c4.metric("차단 수", s["n_actions"])

    # --- 탐지기별 집계 ---
    st.subheader("탐지기별 경보 수")
    if s["by_detector"]:
        st.bar_chart(s["by_detector"])
    else:
        st.info("아직 경보가 없습니다.")

    # --- 경보 목록 ---
    st.subheader("경보 목록")
    rows = alert_rows(run_dir)
    if rows:
        st.dataframe(rows, use_container_width=True)
    else:
        st.info("경보 없음 (정상이거나 탐지기를 아직 안 돌림).")

    # --- SDN 차단 목록 ---
    st.subheader("SDN 차단 목록")
    arows = action_rows(run_dir)
    if arows:
        st.dataframe(arows, use_container_width=True)
    else:
        st.info("차단 기록 없음.")

    # --- 호스트 구성 ---
    with st.expander("호스트 구성"):
        st.dataframe(s["hosts"], use_container_width=True)

    # --- 자동 갱신 ---
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()
