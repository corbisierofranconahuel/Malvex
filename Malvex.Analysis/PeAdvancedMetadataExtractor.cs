using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using Malvex.Core.Models;

namespace Malvex.Analysis;

internal static class PeAdvancedMetadataExtractor
{
    private const int MaxTlsCallbacks = 64;
    private const int MaxResourceTypes = 64;
    private const int MaxResourceEntries = 256;
    private const int MaxResourceDepth = 3;

    public static PeAdvancedMetadata Extract(
        string filePath,
        byte[] bytes,
        PEReader peReader,
        PEHeaders headers,
        IReadOnlyList<ImportLibrary> imports,
        bool is64,
        ulong imageBase,
        int certificateTableSize)
    {
        var versionInfo = ReadVersionInfo(filePath);
        var resourceDirectory = headers.PEHeader?.ResourceTableDirectory ?? default;
        var resources = ParseResources(bytes, headers, resourceDirectory.RelativeVirtualAddress);

        return new PeAdvancedMetadata(
            BuildImphash(imports),
            ParseRichHeader(bytes),
            ParseTlsCallbacks(bytes, headers, is64, imageBase),
            Math.Max(0, resourceDirectory.Size),
            resources
                .Select(resource => resource.Type)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaxResourceTypes)
                .ToList(),
            resources,
            ReadPdbPath(peReader),
            versionInfo.FileDescription,
            versionInfo.CompanyName,
            versionInfo.ProductName,
            versionInfo.FileVersion,
            AuthenticodeInspector.Inspect(filePath, certificateTableSize));
    }

    private static string BuildImphash(IReadOnlyList<ImportLibrary> imports)
    {
        var normalizedImports = imports
            .SelectMany(library => library.Functions.Select(function =>
                $"{NormalizeLibraryName(library.Name)}.{function.Trim().ToLowerInvariant()}"))
            .Where(value => !value.EndsWith(".", StringComparison.Ordinal))
            .ToList();

        if (normalizedImports.Count == 0)
        {
            return string.Empty;
        }

        return Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(string.Join(",", normalizedImports))))
            .ToLowerInvariant();
    }

    private static string NormalizeLibraryName(string name)
    {
        var normalized = Path.GetFileName(name).Trim().ToLowerInvariant();
        foreach (var extension in new[] { ".dll", ".ocx", ".sys" })
        {
            if (normalized.EndsWith(extension, StringComparison.Ordinal))
            {
                return normalized[..^extension.Length];
            }
        }

        return normalized;
    }

    private static IReadOnlyList<ulong> ParseTlsCallbacks(byte[] bytes, PEHeaders headers, bool is64, ulong imageBase)
    {
        var tlsDirectory = headers.PEHeader?.ThreadLocalStorageTableDirectory ?? default;
        var tlsOffset = RvaToOffset(tlsDirectory.RelativeVirtualAddress, headers.SectionHeaders);
        var callbackPointerOffset = is64 ? 24 : 12;
        var pointerSize = is64 ? 8 : 4;
        if (tlsDirectory.RelativeVirtualAddress <= 0 ||
            tlsOffset < 0 ||
            (long)tlsOffset + callbackPointerOffset + pointerSize > bytes.Length)
        {
            return [];
        }

        var callbackTableVa = ReadPointer(bytes, tlsOffset + callbackPointerOffset, is64);
        var callbackTableRva = VaToRva(callbackTableVa, imageBase);
        var callbackTableOffset = RvaToOffset(callbackTableRva, headers.SectionHeaders);
        if (callbackTableOffset < 0)
        {
            return [];
        }

        var callbacks = new List<ulong>();
        for (var index = 0; index < MaxTlsCallbacks; index++)
        {
            var entryOffset = (long)callbackTableOffset + (index * pointerSize);
            if (entryOffset < 0 || entryOffset + pointerSize > bytes.Length)
            {
                break;
            }

            var callbackVa = ReadPointer(bytes, (int)entryOffset, is64);
            if (callbackVa == 0)
            {
                break;
            }

            callbacks.Add(callbackVa);
        }

        return callbacks;
    }

    private static RichHeaderInfo ParseRichHeader(byte[] bytes)
    {
        var richOffset = FindAsciiMarker(bytes, "Rich"u8);
        if (richOffset < 0 || richOffset + 8 > bytes.Length)
        {
            return RichHeaderInfo.Empty;
        }

        var xorKey = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(richOffset + 4, 4));
        var dansValue = 0x536E6144u ^ xorKey;
        var dansOffset = -1;
        for (var offset = richOffset - 4; offset >= 0x40; offset -= 4)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4)) == dansValue)
            {
                dansOffset = offset;
                break;
            }
        }

        if (dansOffset < 0 || richOffset - dansOffset < 16)
        {
            return RichHeaderInfo.Empty;
        }

        var decrypted = new byte[richOffset - dansOffset];
        for (var offset = dansOffset; offset < richOffset; offset += 4)
        {
            var value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4)) ^ xorKey;
            BinaryPrimitives.WriteUInt32LittleEndian(decrypted.AsSpan(offset - dansOffset, 4), value);
        }

        var entryBytes = Math.Max(0, decrypted.Length - 16);
        var entryCount = entryBytes / 8;
        var hash = Convert.ToHexString(MD5.HashData(decrypted)).ToLowerInvariant();
        return new RichHeaderInfo(true, hash, entryCount, xorKey);
    }

    private static int FindAsciiMarker(byte[] bytes, ReadOnlySpan<byte> marker)
    {
        var searchLimit = Math.Min(bytes.Length - marker.Length, 1024);
        for (var offset = 0x40; offset <= searchLimit; offset++)
        {
            if (bytes.AsSpan(offset, marker.Length).SequenceEqual(marker))
            {
                return offset;
            }
        }

        return -1;
    }

    private static IReadOnlyList<PeResourceInfo> ParseResources(byte[] bytes, PEHeaders headers, int resourceRva)
    {
        var rootOffset = RvaToOffset(resourceRva, headers.SectionHeaders);
        if (resourceRva <= 0 || rootOffset < 0 || (long)rootOffset + 16 > bytes.Length)
        {
            return [];
        }

        var resources = new List<PeResourceInfo>();
        var visitedDirectories = new HashSet<int>();
        ParseResourceDirectory(bytes, rootOffset, rootOffset, 0, null, null, resources, visitedDirectories);
        return resources;
    }

    private static void ParseResourceDirectory(
        byte[] bytes,
        int rootOffset,
        int directoryOffset,
        int depth,
        string? type,
        string? name,
        List<PeResourceInfo> resources,
        HashSet<int> visitedDirectories)
    {
        if (depth >= MaxResourceDepth ||
            resources.Count >= MaxResourceEntries ||
            directoryOffset < 0 ||
            (long)directoryOffset + 16 > bytes.Length ||
            !visitedDirectories.Add(directoryOffset))
        {
            return;
        }

        var namedEntries = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(directoryOffset + 12, 2));
        var idEntries = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(directoryOffset + 14, 2));
        var entryCount = Math.Min(MaxResourceEntries, namedEntries + idEntries);
        for (var index = 0; index < entryCount && resources.Count < MaxResourceEntries; index++)
        {
            var entryOffset = (long)directoryOffset + 16 + (index * 8);
            if (entryOffset < 0 || entryOffset + 8 > bytes.Length)
            {
                break;
            }

            var nameValue = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)entryOffset, 4));
            var childValue = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)entryOffset + 4, 4));
            var label = ReadResourceLabel(bytes, rootOffset, nameValue, depth);
            var nextType = depth == 0 ? label : type;
            var nextName = depth == 1 ? label : name;
            var childRelativeOffset = (int)(childValue & 0x7FFFFFFF);
            var childOffset = AddOffset(rootOffset, childRelativeOffset);
            if (childOffset < 0)
            {
                continue;
            }

            if ((childValue & 0x80000000) != 0)
            {
                ParseResourceDirectory(bytes, rootOffset, childOffset, depth + 1, nextType, nextName, resources, visitedDirectories);
                continue;
            }

            if ((long)childOffset + 16 > bytes.Length)
            {
                continue;
            }

            var dataRva = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(childOffset, 4));
            var size = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(childOffset + 4, 4));
            resources.Add(new PeResourceInfo(
                nextType ?? "Tipo desconocido",
                nextName ?? "Sin nombre",
                depth >= 2 ? label : "Idioma no informado",
                Math.Max(0, dataRva),
                Math.Max(0, size)));
        }
    }

    private static string ReadResourceLabel(byte[] bytes, int rootOffset, uint value, int depth)
    {
        if ((value & 0x80000000) != 0)
        {
            return ReadResourceName(bytes, rootOffset, (int)(value & 0x7FFFFFFF));
        }

        var id = (int)value;
        return depth switch
        {
            0 => TranslateResourceType(id),
            2 => $"Idioma #{id}",
            _ => $"ID #{id}"
        };
    }

    private static int AddOffset(int rootOffset, int relativeOffset)
    {
        var offset = (long)rootOffset + relativeOffset;
        return offset is >= 0 and <= int.MaxValue ? (int)offset : -1;
    }

    private static string ReadResourceName(byte[] bytes, int rootOffset, int relativeOffset)
    {
        var offset = (long)rootOffset + relativeOffset;
        if (offset < 0 || offset + 2 > bytes.Length)
        {
            return "Nombre de recurso invalido";
        }

        var length = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)offset, 2));
        var byteLength = length * 2;
        return offset + 2 + byteLength <= bytes.Length
            ? Encoding.Unicode.GetString(bytes, (int)offset + 2, byteLength)
            : "Nombre de recurso invalido";
    }

    private static string TranslateResourceType(int id) => id switch
    {
        1 => "Cursor",
        2 => "Bitmap",
        3 => "Icono",
        4 => "Menu",
        5 => "Dialogo",
        6 => "Tabla de cadenas",
        9 => "Aceleradores",
        10 => "Datos RC",
        11 => "Tabla de mensajes",
        12 => "Grupo de cursores",
        14 => "Grupo de iconos",
        16 => "Version",
        23 => "HTML",
        24 => "Manifiesto",
        _ => $"Tipo #{id}"
    };

    private static string? ReadPdbPath(PEReader peReader)
    {
        try
        {
            foreach (var entry in peReader.ReadDebugDirectory())
            {
                if (entry.Type != DebugDirectoryEntryType.CodeView)
                {
                    continue;
                }

                return TrimValue(peReader.ReadCodeViewDebugDirectoryData(entry).Path);
            }
        }
        catch (BadImageFormatException)
        {
            return null;
        }

        return null;
    }

    private static VersionMetadata ReadVersionInfo(string filePath)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(filePath);
            return new VersionMetadata(
                TrimValue(info.FileDescription),
                TrimValue(info.CompanyName),
                TrimValue(info.ProductName),
                TrimValue(info.FileVersion));
        }
        catch (Exception ex) when (ex is FileNotFoundException or IOException or ArgumentException or UnauthorizedAccessException)
        {
            return VersionMetadata.Empty;
        }
    }

    private static string? TrimValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        const int maxLength = 500;
        var trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
    }

    private static ulong ReadPointer(byte[] bytes, int offset, bool is64)
    {
        return is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8))
            : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    }

    private static int VaToRva(ulong va, ulong imageBase)
    {
        var rva = va >= imageBase ? va - imageBase : va;
        return rva <= int.MaxValue ? (int)rva : -1;
    }

    private static int RvaToOffset(int rva, ImmutableArray<SectionHeader> sections)
    {
        if (rva <= 0)
        {
            return -1;
        }

        foreach (var section in sections)
        {
            var sectionStart = (long)section.VirtualAddress;
            var sectionEnd = sectionStart + Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (rva >= sectionStart && rva < sectionEnd)
            {
                var offset = (long)section.PointerToRawData + (rva - sectionStart);
                return offset is >= 0 and <= int.MaxValue ? (int)offset : -1;
            }
        }

        return -1;
    }

    private sealed record VersionMetadata(
        string? FileDescription,
        string? CompanyName,
        string? ProductName,
        string? FileVersion)
    {
        public static VersionMetadata Empty { get; } = new(null, null, null, null);
    }
}
