using Malvex.Core.Models;

namespace Malvex.Analysis;

public sealed class BasicCfgBuilder : ICfgBuilder
{
    private static readonly HashSet<string> Terminators = new(StringComparer.OrdinalIgnoreCase)
    {
        "ret",
        "retn",
        "retf",
        "int3",
        "hlt"
    };

    public IReadOnlyList<CfgNode> Build(IReadOnlyList<DisassemblyInstruction> instructions)
    {
        if (instructions.Count == 0)
        {
            return [];
        }

        var blocks = new List<(int Id, int Start, int End, List<int> Targets)>();
        var currentStartIndex = 0;
        var blockId = 0;

        for (var i = 0; i < instructions.Count; i++)
        {
            var ins = instructions[i];
            var mnemonic = ins.Mnemonic.ToLowerInvariant();
            var isJump = mnemonic.StartsWith('j');
            var isTerminator = Terminators.Contains(mnemonic) || mnemonic == "jmp";

            if (!isJump && !isTerminator)
            {
                continue;
            }

            var targets = new List<int>();
            var branchTarget = TryParseAbsoluteHex(ins.Operands);
            if (branchTarget.HasValue)
            {
                targets.Add(branchTarget.Value);
            }

            if (!string.Equals(mnemonic, "jmp", StringComparison.OrdinalIgnoreCase) && i + 1 < instructions.Count)
            {
                targets.Add(instructions[i + 1].Rva);
            }

            blocks.Add((blockId++, instructions[currentStartIndex].Rva, ins.Rva, targets));
            currentStartIndex = i + 1;
        }

        if (currentStartIndex < instructions.Count)
        {
            blocks.Add((
                blockId,
                instructions[currentStartIndex].Rva,
                instructions[^1].Rva,
                []));
        }

        var startToId = blocks.ToDictionary(b => b.Start, b => b.Id);
        var nodes = new List<CfgNode>(blocks.Count);

        foreach (var block in blocks)
        {
            var successors = block.Targets
                .Select(target => FindClosestNodeId(target, startToId))
                .Where(id => id.HasValue)
                .Select(id => id!.Value)
                .Distinct()
                .ToList();

            nodes.Add(new CfgNode(
                block.Id,
                block.Start,
                block.End,
                successors));
        }

        return nodes;
    }

    private static int? FindClosestNodeId(int rva, IReadOnlyDictionary<int, int> startToId)
    {
        if (startToId.TryGetValue(rva, out var exact))
        {
            return exact;
        }

        var candidates = startToId.Keys.Where(k => k <= rva).OrderByDescending(k => k).Take(1).ToList();
        if (candidates.Count == 0)
        {
            return null;
        }

        return startToId[candidates[0]];
    }

    private static int? TryParseAbsoluteHex(string operands)
    {
        if (string.IsNullOrWhiteSpace(operands))
        {
            return null;
        }

        var idx = operands.IndexOf("0x", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return null;
        }

        var hexChars = new string(operands
            .Substring(idx + 2)
            .TakeWhile(ch => Uri.IsHexDigit(ch))
            .ToArray());

        if (hexChars.Length == 0)
        {
            return null;
        }

        if (!long.TryParse(hexChars, System.Globalization.NumberStyles.HexNumber, null, out var value))
        {
            return null;
        }

        return value > int.MaxValue ? null : (int)value;
    }
}
