
rule Detect_CMD_InfoCollection
{
    meta:
        description = "Detects common information gathering commands via cmd"
        author = "Yoona_Project"
        version = "2.0"

    strings:
        // 실행 중인 프로세스 정보 수집
        $c1 = "tasklist"

        // 네트워크 연결 정보 수집
        $c2 = "netstat"

        // 로컬 IP, DNS, 게이트웨이 정보 수집
        $c3 = "ipconfig"

        // 현재 로그인된 사용자 정보 확인
        $c4 = "whoami"

        // 시스템 운영체제 및 설치 정보 수집
        $c5 = "systeminfo"

    condition:
        2 of ($*)
}
