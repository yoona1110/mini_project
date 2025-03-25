
rule Detect_Registry_Tweaks
{
    meta:
        description = "Detects registry modification behavior"
        author = "Yoona_Project"
        version = "1.0"

    strings:
        $r1 = "HKEY_CURRENT_USER"
        $r2 = "DisableRegistryTools"
        $r3 = "WallpaperStyle"
        $r4 = "ToastEnabled"
        $r5 = "InstallPath"
        $r6 = "DisableTaskMgr"

    condition:
        2 of ($*)
}
