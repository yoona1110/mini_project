
rule Detect_PowerShell_Usage
{
    meta:
        description = "Detects PowerShell-based malicious actions or evasions"
        author = "Yoona_Project"
        version = "2.0"

    strings:
        // PowerShell 실행 정책 우회 (Bypass, Unrestricted 등)
        $p1 = "ExecutionPolicy"

        // 외부 프로세스 실행 시도
        $p2 = "Start-Process"

        // 악성 PowerShell 스크립트 호출
        $p3 = "script1.ps1"

        // Defender 설정 변경 시도 (실시간 검사 끄기 등)
        $p4 = "Set-MpPreference"

        // 정책 우회 (최대한 실행되도록 우회)
        $p5 = "Bypass"

        // 예약 작업 비활성화 (백신 등 방해 제거 목적)
        $p6 = "Disable-ScheduledTask"

    condition:
        2 of ($*)
}
