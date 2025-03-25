
rule Detect_PowerShell_Usage
{
    meta:
        description = "Detects PowerShell execution and evasion techniques"
        author = "Yoona_Project"
        version = "1.0"

    strings:
        $p1 = "ExecutionPolicy"
        $p2 = "Start-Process"
        $p3 = "script1.ps1"
        $p4 = "Set-MpPreference"
        $p5 = "Bypass"
        $p6 = "Disable-ScheduledTask"

    condition:
        2 of ($*)
}
