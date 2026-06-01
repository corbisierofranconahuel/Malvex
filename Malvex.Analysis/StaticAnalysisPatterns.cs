namespace Malvex.Analysis;

internal static class StaticAnalysisPatterns
{
    public static readonly string[] SuspiciousSectionNames =
    [
        "upx",
        "aspack",
        "petite",
        "mpress"
    ];

    public static readonly string[] HighRiskApis =
    [
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "SetWindowsHookEx",
        "InternetOpen",
        "HttpSendRequest",
        "URLDownloadToFile"
    ];

    public static readonly string[] ContextualApis =
    [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent"
    ];

    public static readonly string[] CommonMemoryApis =
    [
        "VirtualAlloc",
        "VirtualProtect",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress"
    ];

    public static readonly string[] SuspiciousPowerShellTerms =
    [
        "-enc",
        "-encodedcommand",
        "downloadstring",
        "iex(",
        "invoke-expression",
        "frombase64string",
        "-nop",
        "-w hidden"
    ];

    public static readonly string[] SuspiciousShellTerms =
    [
        "powershell",
        "reg add",
        "schtasks",
        "rundll32",
        "bitsadmin",
        "certutil",
        "mshta",
        "wscript",
        "cscript",
        "vssadmin",
        "bcdedit"
    ];

    public static readonly string[] PersistenceRegistryTerms =
    [
        "software\\microsoft\\windows\\currentversion\\run",
        "software\\microsoft\\windows\\currentversion\\runonce"
    ];

    public static readonly string[] IndirectExecutionTerms =
    [
        "schtasks /create",
        "sc create",
        "rundll32",
        "mshta",
        "wscript",
        "cscript"
    ];

    public static readonly string[] ImpactTerms =
    [
        "vssadmin delete shadows",
        "bcdedit /set",
        "wbadmin delete",
        "cipher /w:",
        "wevtutil cl"
    ];

    public static readonly string[] HighSignalStringTerms =
        SuspiciousPowerShellTerms
            .Concat(SuspiciousShellTerms)
            .Concat(PersistenceRegistryTerms)
            .Concat(IndirectExecutionTerms)
            .Concat(ImpactTerms)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static readonly string[] SuspiciousExportExactNames =
    [
        "ReflectiveLoader",
        "DllRegisterServer",
        "DllInstall",
        "ServiceMain"
    ];

    public static readonly string[] SuspiciousExportPrefixes =
    [
        "Reflective",
        "RunDLL"
    ];

    public static bool IsSensitiveExportName(string name)
    {
        return SuspiciousExportExactNames.Contains(name, StringComparer.OrdinalIgnoreCase) ||
               SuspiciousExportPrefixes.Any(prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }
}
