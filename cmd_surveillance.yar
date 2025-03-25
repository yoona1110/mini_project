
rule Detect_CMD_InfoCollection
{
    meta:
        description = "Detects suspicious command-line based surveillance activity"
        author = "Yoona_Project"
        version = "1.0"

    strings:
        $c1 = "tasklist"
        $c2 = "netstat"
        $c3 = "ipconfig"
        $c4 = "whoami"
        $c5 = "systeminfo"

    condition:
        2 of ($*)
}
