using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using Malvex.Core.Models;

namespace Malvex.Analysis;

public sealed class PeStaticAnalyzer : IPeStaticAnalyzer
{
    private const long MaxSupportedFileSizeBytes = 512L * 1024 * 1024;
    private const int MaxImportDescriptors = 4096;
    private const int MaxThunkEntries = 8192;
    private const int MaxExportEntries = 65_536;
    private const int MaxStringCandidates = 12_000;
    private const int MaxExtractedStringLength = 2048;
    private readonly IYaraScanner _yaraScanner;
    private readonly IDisassembler _disassembler;
    private readonly ICfgBuilder _cfgBuilder;

    public PeStaticAnalyzer()
        : this(new YaraCliScanner(), new IcedDisassembler(), new BasicCfgBuilder())
    {
    }

    public PeStaticAnalyzer(IYaraScanner yaraScanner, IDisassembler disassembler, ICfgBuilder cfgBuilder)
    {
        _yaraScanner = yaraScanner;
        _disassembler = disassembler;
        _cfgBuilder = cfgBuilder;
    }

    public PeAnalysisResult Analyze(string filePath, int maxStrings = 800)
    {
        var fileInfo = new FileInfo(filePath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("No se encontro el archivo seleccionado.", filePath);
        }

        if (fileInfo.Length > MaxSupportedFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"El archivo supera el limite de {MaxSupportedFileSizeBytes / 1024 / 1024} MB para analisis interactivo.");
        }

        var bytes = File.ReadAllBytes(filePath);
        var fileName = Path.GetFileName(filePath);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes));
        var strings = ExtractStrings(bytes, maxStrings);

        try
        {
            using var peStream = new MemoryStream(bytes, writable: false);
            using var peReader = new PEReader(peStream, PEStreamOptions.LeaveOpen);

            if (!peReader.HasMetadata && peReader.PEHeaders.PEHeader is null)
            {
                return BuildNonPeResult(filePath, fileName, bytes.LongLength, sha256, strings, "YARA no ejecutado: archivo no PE.");
            }

        var peHeaders = peReader.PEHeaders;
        var peHeader = peHeaders.PEHeader;
        if (peHeader is null)
        {
            return BuildNonPeResult(filePath, fileName, bytes.LongLength, sha256, strings, "YARA no ejecutado: cabecera PE ausente.");
        }

        var is64 = peHeader.Magic == PEMagic.PE32Plus;
        var arch = peHeaders.CoffHeader.Machine.ToString();
        var sections = BuildSections(peHeaders.SectionHeaders, bytes);
        var imports = ParseImports(bytes, peHeaders, is64);
        var exports = ParseExports(bytes, peHeaders);
        var yaraResult = _yaraScanner.Scan(filePath);

        var entryPointRva = peHeader.AddressOfEntryPoint;
        var entryPointOffset = RvaToOffset(entryPointRva, peHeaders.SectionHeaders);
        var imageBase = (ulong)Math.Max(0, peHeader.ImageBase);
        var coffTimestampUtc = ParseCoffTimestamp(peHeaders.CoffHeader.TimeDateStamp);
        var certificateTable = peHeader.CertificateTableDirectory;
        var certificateTableSize = Math.Max(0, certificateTable.Size);
        var overlaySize = CalculateOverlaySize(
            bytes.LongLength,
            peHeaders.SectionHeaders,
            certificateTable.RelativeVirtualAddress,
            certificateTableSize);
        var advancedMetadata = PeAdvancedMetadataExtractor.Extract(
            filePath,
            bytes,
            peReader,
            peHeaders,
            imports,
            is64,
            imageBase,
            certificateTableSize);
        var disassembly = _disassembler.DisassembleEntryPoint(bytes, entryPointRva, entryPointOffset, is64, imageBase);
        var cfg = _cfgBuilder.Build(disassembly);

        var findings = StaticAnalysisFindingsBuilder.Build(sections, imports, exports, strings, yaraResult, overlaySize, advancedMetadata);
        var risk = StaticAnalysisRiskScorer.Build(findings, yaraResult.Matches);
        var guidedSteps = StaticAnalysisGuidanceBuilder.BuildGuidedSteps(findings, yaraResult, sections, advancedMetadata, disassembly, cfg);
        var guidance = StaticAnalysisGuidanceBuilder.BuildAnalystGuidance(findings, imports, exports, sections, strings, yaraResult, risk, advancedMetadata, disassembly, cfg);

            return new PeAnalysisResult(
                filePath,
                fileName,
                bytes.LongLength,
                sha256,
                true,
                is64,
                arch,
                entryPointRva,
                imageBase,
                coffTimestampUtc,
                overlaySize,
                certificateTableSize,
                advancedMetadata,
                sections,
                imports,
                exports,
                strings,
                yaraResult.IsAvailable,
                yaraResult.Message,
                yaraResult.Matches,
                findings,
                risk,
                guidedSteps,
                disassembly,
                cfg,
                guidance);
        }
        catch (BadImageFormatException)
        {
            return BuildNonPeResult(filePath, fileName, bytes.LongLength, sha256, strings, "YARA no ejecutado: formato PE invalido o corrupto.");
        }
    }

    private static PeAnalysisResult BuildNonPeResult(
        string filePath,
        string fileName,
        long fileSize,
        string sha256,
        IReadOnlyList<string> strings,
        string yaraMessage)
    {
        var findings = new List<HeuristicFinding>
        {
            new(AnalysisSeverity.Warning, "Archivo no PE", "El archivo no tiene cabeceras PE validas.")
        };

        return new PeAnalysisResult(
            filePath,
            fileName,
            fileSize,
            sha256,
            false,
            false,
            "Unknown",
            0,
            0,
            null,
            0,
            0,
            PeAdvancedMetadata.Empty,
            [],
            [],
            [],
            strings,
            false,
            yaraMessage,
            [],
            findings,
            new RiskScore(20, RiskLevel.Low, ["Archivo no interpretable como PE"]),
            [new GuidedStep(1, "Verificar tipo de archivo", "Selecciona un .exe o .dll valido para analisis PE.")],
            [],
            [],
            new AnalystGuidance(
                "El archivo no pudo analizarse como PE.",
                "No hay metadata PE valida para generar hipotesis tecnicas.",
                [],
                [new AnalystChecklistItem("Validar formato binario", true, "No PE detectado.")],
                [new SuggestedAction(1, "Seleccionar otro archivo", "Malvex requiere .exe/.dll PE valido para analisis completo.")]));
    }

    private static IReadOnlyList<PeSectionInfo> BuildSections(IEnumerable<SectionHeader> sectionHeaders, byte[] bytes)
    {
        var result = new List<PeSectionInfo>();
        foreach (var section in sectionHeaders)
        {
            var rawPointer = section.PointerToRawData;
            var rawSize = section.SizeOfRawData;
            var safeSize = ClampSectionSize(bytes, rawPointer, rawSize);
            var entropy = safeSize > 0
                ? CalculateEntropy(bytes.AsSpan(rawPointer, safeSize))
                : 0d;

            result.Add(new PeSectionInfo(
                section.Name,
                section.VirtualAddress,
                section.VirtualSize,
                rawSize,
                rawPointer,
                Math.Round(entropy, 3),
                $"0x{(uint)section.SectionCharacteristics:X8}"));
        }

        return result;
    }

    private static DateTimeOffset? ParseCoffTimestamp(int timestamp)
    {
        if (timestamp <= 0)
        {
            return null;
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds((uint)timestamp);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static long CalculateOverlaySize(
        long fileSize,
        IEnumerable<SectionHeader> sectionHeaders,
        int certificateTableOffset,
        int certificateTableSize)
    {
        var lastSectionEnd = sectionHeaders
            .Select(section => (long)Math.Max(0, section.PointerToRawData) + Math.Max(0, section.SizeOfRawData))
            .DefaultIfEmpty(0)
            .Max();
        var overlaySize = Math.Max(0, fileSize - lastSectionEnd);

        if (overlaySize == 0 || certificateTableOffset < lastSectionEnd || certificateTableSize <= 0)
        {
            return overlaySize;
        }

        var certificateEnd = Math.Min(fileSize, (long)certificateTableOffset + certificateTableSize);
        var certificateBytesAfterSections = Math.Max(0, certificateEnd - Math.Max(lastSectionEnd, certificateTableOffset));
        return Math.Max(0, overlaySize - certificateBytesAfterSections);
    }

    private static IReadOnlyList<ImportLibrary> ParseImports(byte[] bytes, PEHeaders headers, bool is64)
    {
        var result = new List<ImportLibrary>();
        var importDirectory = headers.PEHeader?.ImportTableDirectory ?? default;
        if (importDirectory.RelativeVirtualAddress == 0 || importDirectory.Size == 0)
        {
            return result;
        }

        var descriptorOffset = RvaToOffset(importDirectory.RelativeVirtualAddress, headers.SectionHeaders);
        if (descriptorOffset < 0 || descriptorOffset >= bytes.Length)
        {
            return result;
        }

        const int descriptorSize = 20;
        var current = descriptorOffset;
        var descriptorLimit = (int)Math.Min(
            bytes.Length,
            (long)descriptorOffset + Math.Max(descriptorSize, importDirectory.Size));
        var descriptorCount = 0;
        while (current + descriptorSize <= descriptorLimit && descriptorCount++ < MaxImportDescriptors)
        {
            var originalFirstThunk = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(current, 4));
            var timeDateStamp = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(current + 4, 4));
            var forwarderChain = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(current + 8, 4));
            var nameRva = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(current + 12, 4));
            var firstThunk = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(current + 16, 4));

            if (originalFirstThunk == 0 && timeDateStamp == 0 && forwarderChain == 0 && nameRva == 0 && firstThunk == 0)
            {
                break;
            }

            var libName = ReadAsciiZ(bytes, RvaToOffset(nameRva, headers.SectionHeaders));
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var functions = thunkRva > 0
                ? ParseThunkNames(bytes, headers, thunkRva, is64)
                : [];

            result.Add(new ImportLibrary(libName, functions));
            current += descriptorSize;
        }

        return result;
    }

    private static IReadOnlyList<string> ParseThunkNames(byte[] bytes, PEHeaders headers, int thunkRva, bool is64)
    {
        var names = new List<string>();
        var entrySize = is64 ? 8 : 4;
        var thunkOffset = RvaToOffset(thunkRva, headers.SectionHeaders);
        if (thunkOffset < 0 || thunkOffset >= bytes.Length)
        {
            return names;
        }

        var position = thunkOffset;
        var entryCount = 0;
        while (position + entrySize <= bytes.Length && entryCount++ < MaxThunkEntries)
        {
            ulong raw = is64
                ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(position, 8))
                : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(position, 4));
            if (raw == 0)
            {
                break;
            }

            var isOrdinal = is64
                ? (raw & 0x8000000000000000UL) != 0
                : (raw & 0x80000000UL) != 0;

            if (isOrdinal)
            {
                var ordinal = (ushort)(raw & 0xFFFF);
                names.Add($"ordinal_{ordinal}");
            }
            else
            {
                var nameRva = (int)(raw & 0x7FFFFFFF);
                var nameOffset = RvaToOffset(nameRva, headers.SectionHeaders);
                if (nameOffset > 0 && nameOffset + 2 < bytes.Length)
                {
                    var functionName = ReadAsciiZ(bytes, nameOffset + 2);
                    if (!string.IsNullOrWhiteSpace(functionName))
                    {
                        names.Add(functionName);
                    }
                }
            }

            position += entrySize;
        }

        return names;
    }

    private static IReadOnlyList<ExportSymbol> ParseExports(byte[] bytes, PEHeaders headers)
    {
        var result = new List<ExportSymbol>();
        var exportDirectory = headers.PEHeader?.ExportTableDirectory ?? default;
        if (exportDirectory.RelativeVirtualAddress == 0 || exportDirectory.Size == 0)
        {
            return result;
        }

        var exportOffset = RvaToOffset(exportDirectory.RelativeVirtualAddress, headers.SectionHeaders);
        if (exportOffset < 0 || exportOffset + 40 > bytes.Length)
        {
            return result;
        }

        var ordinalBase = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(exportOffset + 16, 4));
        var numberOfFunctions = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(exportOffset + 20, 4));
        var numberOfNames = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(exportOffset + 24, 4));
        var addressOfFunctions = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(exportOffset + 28, 4));
        var addressOfNames = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(exportOffset + 32, 4));
        var addressOfNameOrdinals = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(exportOffset + 36, 4));

        if (numberOfFunctions <= 0)
        {
            return result;
        }

        var functionsOffset = RvaToOffset(addressOfFunctions, headers.SectionHeaders);
        var namesOffset = numberOfNames > 0 ? RvaToOffset(addressOfNames, headers.SectionHeaders) : -1;
        var ordinalsOffset = numberOfNames > 0 ? RvaToOffset(addressOfNameOrdinals, headers.SectionHeaders) : -1;
        if (functionsOffset < 0)
        {
            return result;
        }

        var effectiveNameCount = Math.Min(numberOfNames, MaxExportEntries);
        if (effectiveNameCount > 0 && (namesOffset < 0 || ordinalsOffset < 0))
        {
            effectiveNameCount = 0;
        }

        var namedOrdinals = new HashSet<int>();
        for (var i = 0; i < effectiveNameCount; i++)
        {
            var nameRvaPos = namesOffset + (i * 4);
            var ordinalPos = ordinalsOffset + (i * 2);
            if (nameRvaPos + 4 > bytes.Length || ordinalPos + 2 > bytes.Length)
            {
                break;
            }

            var nameRva = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(nameRvaPos, 4));
            var symbolName = ReadAsciiZ(bytes, RvaToOffset(nameRva, headers.SectionHeaders));
            var ordinalIndex = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(ordinalPos, 2));
            if (ordinalIndex >= numberOfFunctions)
            {
                continue;
            }

            var functionRvaPos = functionsOffset + (ordinalIndex * 4);
            if (functionRvaPos + 4 > bytes.Length)
            {
                continue;
            }

            var addressRva = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(functionRvaPos, 4));
            var realOrdinal = ordinalBase + ordinalIndex;
            result.Add(new ExportSymbol(string.IsNullOrWhiteSpace(symbolName) ? $"ordinal_{realOrdinal}" : symbolName, realOrdinal, addressRva));
            namedOrdinals.Add(realOrdinal);
        }

        for (var ordinal = 0; ordinal < Math.Min(numberOfFunctions, MaxExportEntries); ordinal++)
        {
            var realOrdinal = ordinalBase + ordinal;
            if (namedOrdinals.Contains(realOrdinal))
            {
                continue;
            }

            var functionRvaPos = functionsOffset + (ordinal * 4);
            if (functionRvaPos + 4 > bytes.Length)
            {
                break;
            }

            var addressRva = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(functionRvaPos, 4));
            if (addressRva == 0)
            {
                continue;
            }

            result.Add(new ExportSymbol($"ordinal_{realOrdinal}", realOrdinal, addressRva));
        }

        return result;
    }

    private static IReadOnlyList<string> ExtractStrings(byte[] bytes, int maxStrings)
    {
        var strings = new HashSet<string>(StringComparer.Ordinal);
        ExtractAsciiStrings(bytes, strings);
        ExtractUnicodeStrings(bytes, strings, 0);
        ExtractUnicodeStrings(bytes, strings, 1);

        return strings
            .OrderByDescending(GetStringPriority)
            .ThenByDescending(s => s.Length)
            .Take(maxStrings)
            .ToList();
    }

    private static void ExtractAsciiStrings(byte[] bytes, HashSet<string> strings, int minLength = 4)
    {
        var buffer = new StringBuilder();
        foreach (var value in bytes)
        {
            if (value is >= 32 and <= 126)
            {
                if (buffer.Length < MaxExtractedStringLength)
                {
                    buffer.Append((char)value);
                }
            }
            else
            {
                if (buffer.Length >= minLength)
                {
                    AddStringCandidate(strings, buffer);
                }

                buffer.Clear();
            }
        }

        if (buffer.Length >= minLength)
        {
            AddStringCandidate(strings, buffer);
        }
    }

    private static void ExtractUnicodeStrings(byte[] bytes, HashSet<string> strings, int startOffset, int minLength = 4)
    {
        var buffer = new StringBuilder();
        for (var i = startOffset; i + 1 < bytes.Length; i += 2)
        {
            var ch = BitConverter.ToChar(bytes, i);
            if (ch is >= ' ' and <= '~')
            {
                if (buffer.Length < MaxExtractedStringLength)
                {
                    buffer.Append(ch);
                }
            }
            else
            {
                if (buffer.Length >= minLength)
                {
                    AddStringCandidate(strings, buffer);
                }

                buffer.Clear();
            }
        }

        if (buffer.Length >= minLength)
        {
            AddStringCandidate(strings, buffer);
        }
    }

    private static void AddStringCandidate(HashSet<string> strings, StringBuilder buffer)
    {
        if (strings.Count >= MaxStringCandidates)
        {
            return;
        }

        var length = Math.Min(buffer.Length, MaxExtractedStringLength);
        strings.Add(buffer.ToString(0, length));
    }

    private static int GetStringPriority(string value)
    {
        if (StaticAnalysisPatterns.HighSignalStringTerms.Any(term =>
                value.Contains(term, StringComparison.OrdinalIgnoreCase)))
        {
            return 3;
        }

        if (value.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("https://", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        return 1;
    }

    private static int RvaToOffset(int rva, ImmutableArray<SectionHeader> sections)
    {
        foreach (var section in sections)
        {
            var sectionStart = section.VirtualAddress;
            var sectionEnd = sectionStart + Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (rva < sectionStart || rva >= sectionEnd)
            {
                continue;
            }

            return section.PointerToRawData + (rva - sectionStart);
        }

        return -1;
    }

    private static int ClampSectionSize(byte[] bytes, int rawPointer, int rawSize)
    {
        if (rawPointer < 0 || rawPointer >= bytes.Length)
        {
            return 0;
        }

        var maxSize = bytes.Length - rawPointer;
        return Math.Max(0, Math.Min(rawSize, maxSize));
    }

    private static double CalculateEntropy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            return 0;
        }

        Span<int> frequency = stackalloc int[256];
        foreach (var b in bytes)
        {
            frequency[b]++;
        }

        var entropy = 0d;
        foreach (var count in frequency)
        {
            if (count == 0)
            {
                continue;
            }

            var probability = (double)count / bytes.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static string ReadAsciiZ(byte[] bytes, int offset, int maxLength = 260)
    {
        if (offset < 0 || offset >= bytes.Length)
        {
            return string.Empty;
        }

        var length = 0;
        while (offset + length < bytes.Length && length < maxLength)
        {
            if (bytes[offset + length] == 0)
            {
                break;
            }

            length++;
        }

        return length == 0
            ? string.Empty
            : Encoding.ASCII.GetString(bytes, offset, length);
    }
}
