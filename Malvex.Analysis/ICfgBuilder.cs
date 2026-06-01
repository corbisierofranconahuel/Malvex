using Malvex.Core.Models;

namespace Malvex.Analysis;

public interface ICfgBuilder
{
    IReadOnlyList<CfgNode> Build(IReadOnlyList<DisassemblyInstruction> instructions);
}
