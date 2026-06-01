import "pe"

rule Suspicious_PowerShell_Command
{
    meta:
        author = "Malvex"
        severity = "medium"
    strings:
        $command = /powershell(\.exe)?[ \t]+[^\r\n]{0,96}(-enc(odedcommand)?|-nop|-w(indowstyle)?[ \t]+hidden|downloadstring|frombase64string)/ ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $command
}

rule Suspicious_Download_And_Execute
{
    meta:
        author = "Malvex"
        severity = "high"
    strings:
        $execute1 = "WinExec" ascii wide
        $execute2 = "cmd.exe /c" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (
            pe.imports("urlmon.dll", "URLDownloadToFileA") or
            pe.imports("urlmon.dll", "URLDownloadToFileW")
        ) and
        any of ($execute*)
}

rule Packed_Section_Name_Heuristic
{
    meta:
        author = "Malvex"
        severity = "low"
    condition:
        uint16(0) == 0x5A4D and
        for any section in pe.sections : (
            section.name == "UPX0" or section.name == "UPX1"
        )
}
