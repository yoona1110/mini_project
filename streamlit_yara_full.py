
import streamlit as st
import yara
import os
import tempfile
import pandas as pd
import time

# 🔍 문자열 설명 매핑
STRING_EXPLANATIONS = {
    "$r1": "사용자 환경의 레지스트리 접근 (HKEY_CURRENT_USER)",
    "$r2": "레지스트리 편집기 비활성화",
    "$r3": "사용자 알림 비활성화 (ToastEnabled)",
    "$r4": "배경화면 변경으로 혼란 유도 (WallpaperStyle)",
    "$r5": "프로그램 설치 경로 변경",
    "$r6": "작업 관리자 비활성화",

    "$p1": "PowerShell 실행 정책 우회",
    "$p2": "외부 프로세스 실행",
    "$p3": "악성 스크립트 호출 (ps1)",
    "$p4": "Windows Defender 설정 변경",
    "$p5": "Bypass 정책 적용",
    "$p6": "예약 작업 비활성화",

    "$c1": "실행 중인 프로세스 수집 (tasklist)",
    "$c2": "네트워크 연결 수집 (netstat)",
    "$c3": "IP 설정 수집 (ipconfig)",
    "$c4": "사용자 계정 정보 수집 (whoami)",
    "$c5": "시스템 정보 수집 (systeminfo)"
}

def get_string_explanation(id_):
    return STRING_EXPLANATIONS.get(id_, "(알 수 없음)")

# 위험도 점수 계산
def calculate_score(ids):
    high_risk = {"$r2", "$p4", "$p6"}
    return sum(3 if i in high_risk else 1 for i in ids)

def evaluate_score_level(score):
    if score == 0:
        return "✅ 안전", "green"
    elif score <= 3:
        return "⚠️ 경고", "orange"
    else:
        return "🔥 심각", "red"

RULES_DIR = "yara_rules"
os.makedirs(RULES_DIR, exist_ok=True)

def load_yara_rules(selected_files):
    rules = {}
    for filename in selected_files:
        rule_path = os.path.join(RULES_DIR, filename)
        try:
            rules[filename] = yara.compile(filepath=rule_path)
        except yara.Error as e:
            st.error(f"YARA 룰 오류 ({filename}): {str(e)}")
    return rules

def main():
    st.set_page_config(layout="wide")
    st.title("🛡️ 악성코드 탐지 및 의미 기반 분석 시스템")
    st.markdown("📂 업로드한 파일을 선택한 YARA 룰로 탐지하고, 각 문자열의 의미 및 위험도를 분석합니다.")

    # 사이드바: YARA 룰 등록/관리
    st.sidebar.header("🧰 YARA 룰 도구")

    new_rule_name = st.sidebar.text_input("룰 파일 이름 (.yar 포함)", key="rule_name")
    new_rule_code = st.sidebar.text_area("YARA 룰 코드 입력", key="rule_code")

    if st.sidebar.button("💾 룰 저장"):
        if new_rule_name and new_rule_code:
            rule_path = os.path.join(RULES_DIR, new_rule_name)
            with open(rule_path, "w") as f:
                f.write(new_rule_code)
            st.sidebar.success(f"{new_rule_name} 저장 완료")
            st.session_state.rule_name = ""
            st.session_state.rule_code = ""

    with st.sidebar.expander("📤 YARA 룰 업로드", expanded=False):
        uploaded_yar = st.file_uploader("YARA 룰 파일 업로드 (.yar)", type=["yar"], key="upload_yar")
        if uploaded_yar is not None:
            save_path = os.path.join(RULES_DIR, uploaded_yar.name)
            with open(save_path, "wb") as f:
                f.write(uploaded_yar.read())
            st.success(f"'{uploaded_yar.name}' 업로드 완료!")

    with st.sidebar.expander("✏️ YARA 룰 수정", expanded=False):
        existing_rules = [f for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
        rule_to_edit = st.selectbox("수정할 룰 선택", options=existing_rules, key="edit_select")
        if rule_to_edit:
            with open(os.path.join(RULES_DIR, rule_to_edit), "r") as f:
                original_code = f.read()
            new_code = st.text_area("룰 내용 수정", value=original_code, height=200, key="edit_code")
            if st.button("📌 수정 저장"):
                with open(os.path.join(RULES_DIR, rule_to_edit), "w") as f:
                    f.write(new_code)
                st.success(f"{rule_to_edit} 수정 완료!")
                st.experimental_rerun()

    with st.sidebar.expander("🗑️ YARA 룰 삭제", expanded=False):
        rules_to_delete = st.multiselect("삭제할 룰 선택", options=existing_rules, key="delete_select")
        if st.button("❌ 선택한 룰 삭제"):
            for rule_file in rules_to_delete:
                os.remove(os.path.join(RULES_DIR, rule_file))
            st.success(f"{len(rules_to_delete)}개 룰 삭제 완료!")
            st.rerun()

    # 메인 탐지 영역
    uploaded_file = st.file_uploader("📥 분석할 악성코드 샘플 업로드", type=["exe", "pyc", "xlsm", "reg", "ps1", "bin"])
    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_path = tmp_file.name

        st.success(f"업로드 완료: `{uploaded_file.name}`")
        yara_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
        selected_rules = st.multiselect("✅ 사용할 YARA 룰 선택", yara_files, default=yara_files)

        if selected_rules and st.button("🚀 탐지 시작"):
            rules = load_yara_rules(selected_rules)
            results = []
            progress = st.progress(0, text="탐지 중...")

            for idx, (rule_file, rule_obj) in enumerate(rules.items()):
                try:
                    matches = rule_obj.match(tmp_path)
                    matched_ids = []
                    matched_info = []

                    for match in matches:
                        for s in match.strings:
                            identifier = s[1] if isinstance(s, tuple) else s.identifier
                            explanation = get_string_explanation(identifier)
                            matched_ids.append(identifier)
                            matched_info.append(f"{identifier}: {explanation}")

                    score = calculate_score(set(matched_ids))
                    level, color = evaluate_score_level(score)

                    results.append({
                        "룰": rule_file,
                        "탐지된 수": len(matched_ids),
                        "위험도": level,
                        "색상": color,
                        "설명": matched_info
                    })

                except Exception as e:
                    results.append({
                        "룰": rule_file,
                        "탐지된 수": "오류",
                        "위험도": f"❌ 오류 ({e})",
                        "색상": "gray",
                        "설명": []
                    })

                progress.progress((idx + 1) / len(rules))

            st.markdown("### 🧾 탐지 결과")
            df = pd.DataFrame([{
                "YARA 룰": r["룰"],
                "탐지 수": r["탐지된 수"],
                "위험도": r["위험도"]
            } for r in results])
            st.dataframe(df, use_container_width=True)

            for r in results:
                with st.expander(f"📄 {r['룰']} → {r['위험도']}"):
                    if isinstance(r["설명"], list) and r["설명"]:
                        for s in r["설명"]:
                            st.markdown(f"- {s}")
                    else:
                        st.info("탐지된 문자열 없음 또는 오류 발생")

if __name__ == "__main__":
    main()
