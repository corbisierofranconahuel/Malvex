namespace Malvex.Core.Models;

public sealed record PeAdvancedMetadata(
    string Imphash,
    RichHeaderInfo RichHeader,
    IReadOnlyList<ulong> TlsCallbackVas,
    int ResourceTableSize,
    IReadOnlyList<string> ResourceTypes,
    IReadOnlyList<PeResourceInfo> Resources,
    string? DebugPdbPath,
    string? FileDescription,
    string? CompanyName,
    string? ProductName,
    string? FileVersion,
    AuthenticodeInfo Authenticode)
{
    public static PeAdvancedMetadata Empty { get; } = new(
        string.Empty,
        RichHeaderInfo.Empty,
        [],
        0,
        [],
        [],
        null,
        null,
        null,
        null,
        null,
        new AuthenticodeInfo(AuthenticodeStatus.NotPresent, "No se detecto tabla Authenticode.", null, null));
}
