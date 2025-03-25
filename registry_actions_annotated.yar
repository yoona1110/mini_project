
rule Detect_Registry_Tweaks
{
    meta:
        description = "Detects malicious registry creation or modification"
        author = "Yoona_Project"
        version = "2.0"

    strings:
        // 사용자 환경 접근 (정상 행위도 존재하나, 조작 시 악성 행위 가능성 있음)
        $r1 = "HKEY_CURRENT_USER"

        // 레지스트리 편집기 비활성화 - 시스템 방어 회피
        $r2 = "DisableRegistryTools"

        // 사용자 알림 시스템 비활성화 - 침투 은폐
        $r3 = "ToastEnabled"

        // 바탕화면 설정 변경 - 시각적 혼란 또는 랜섬웨어 연출
        $r4 = "WallpaperStyle"

        // 프로그램 설치 경로 변경 조작 - 악성 실행 위치 은폐
        $r5 = "InstallPath"

        // 작업 관리자 비활성화 - 사용자 대응 방해
        $r6 = "DisableTaskMgr"

    condition:
        2 of ($*)
}
