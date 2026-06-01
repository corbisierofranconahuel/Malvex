using Malvex.Core.Models;

namespace Malvex.Analysis;

public interface IDisassembler
{
    IReadOnlyList<DisassemblyInstruction> DisassembleEntryPoint(
        byte[] fileBytes,
        int entryPointRva,
        int entryPointOffset,
        bool is64Bit,
        ulong imageBase,
        int maxInstructions = 220);
}
