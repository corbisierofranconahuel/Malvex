namespace Malvex.Core.Models;

public sealed record ExportSymbol(
    string Name,
    int Ordinal,
    int AddressRva);
