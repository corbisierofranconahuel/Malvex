namespace Malvex.Core.Models;

public sealed record DisassemblyInstruction(
    int Index,
    long FileOffset,
    int Rva,
    string Bytes,
    string Mnemonic,
    string Operands);
