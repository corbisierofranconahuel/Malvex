using Iced.Intel;
using Malvex.Core.Models;

namespace Malvex.Analysis;

public sealed class IcedDisassembler : IDisassembler
{
    public IReadOnlyList<DisassemblyInstruction> DisassembleEntryPoint(
        byte[] fileBytes,
        int entryPointRva,
        int entryPointOffset,
        bool is64Bit,
        ulong imageBase,
        int maxInstructions = 220)
    {
        return DisassembleCodeWindow(fileBytes, entryPointRva, entryPointOffset, is64Bit, imageBase, 0, maxInstructions);
    }

    public IReadOnlyList<DisassemblyInstruction> DisassembleCodeWindow(
        byte[] codeBytes,
        int startRva,
        bool is64Bit,
        ulong imageBase,
        int fileOffsetBase,
        int maxInstructions = 120)
    {
        return DisassembleCodeWindow(codeBytes, startRva, 0, is64Bit, imageBase, fileOffsetBase, maxInstructions);
    }

    private static IReadOnlyList<DisassemblyInstruction> DisassembleCodeWindow(
        byte[] fileBytes,
        int entryPointRva,
        int entryPointOffset,
        bool is64Bit,
        ulong imageBase,
        int fileOffsetBase,
        int maxInstructions)
    {
        if (entryPointOffset < 0 || entryPointOffset >= fileBytes.Length)
        {
            return [];
        }

        var maxCodeSize = Math.Min(4096, fileBytes.Length - entryPointOffset);
        if (maxCodeSize <= 0)
        {
            return [];
        }

        var code = new byte[maxCodeSize];
        Array.Copy(fileBytes, entryPointOffset, code, 0, maxCodeSize);

        var bitness = is64Bit ? 64 : 32;
        var decoder = Decoder.Create(bitness, code);
        var startIp = imageBase + (uint)entryPointRva;
        decoder.IP = startIp;
        var formatter = new NasmFormatter();

        var output = new List<DisassemblyInstruction>(maxInstructions);
        var textBuilder = new StringOutput();
        var index = 0;

        while (output.Count < maxInstructions && decoder.IP - startIp < (ulong)maxCodeSize)
        {
            var instruction = decoder.Decode();
            if (instruction.Length <= 0)
            {
                break;
            }

            textBuilder.Reset();
            formatter.Format(instruction, textBuilder);
            var formatted = textBuilder.ToString();
            var split = formatted.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var mnemonic = split.Length > 0 ? split[0] : "db";
            var operands = split.Length > 1 ? split[1] : string.Empty;

            var relativeOffset = (long)(instruction.IP - startIp);
            var fileOffset = entryPointOffset + relativeOffset;
            if (fileOffset < 0 || fileOffset + instruction.Length > fileBytes.Length)
            {
                break;
            }

            var bytes = BitConverter
                .ToString(fileBytes, (int)fileOffset, instruction.Length)
                .Replace("-", " ");

            output.Add(new DisassemblyInstruction(
                index++,
                fileOffsetBase + fileOffset,
                entryPointRva + (int)relativeOffset,
                bytes,
                mnemonic,
                operands));
        }

        return output;
    }
}
