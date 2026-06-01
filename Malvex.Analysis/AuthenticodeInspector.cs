using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Malvex.Core.Models;

namespace Malvex.Analysis;

internal static class AuthenticodeInspector
{
    private static readonly Guid GenericVerifyV2Action = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionIgnore = 0;
    private const uint TrustENoSignature = 0x800B0100;
    private const uint TrustESubjectNotTrusted = 0x800B0004;
    private const uint TrustEBadDigest = 0x80096010;
    private const uint TrustEExplicitDistrust = 0x800B0111;
    private const uint CertEUntrustedRoot = 0x800B0109;
    private const uint CertEChaining = 0x800B010A;

    public static AuthenticodeInfo Inspect(string filePath, int certificateTableSize)
    {
        if (certificateTableSize <= 0)
        {
            return new AuthenticodeInfo(
                AuthenticodeStatus.NotPresent,
                "No se detecto tabla Authenticode.",
                null,
                null);
        }

        var (subject, issuer) = TryReadSigner(filePath);
        if (!OperatingSystem.IsWindows())
        {
            return new AuthenticodeInfo(
                AuthenticodeStatus.Unsupported,
                "Se detecto una tabla Authenticode, pero la validacion WinTrust solo esta disponible en Windows.",
                subject,
                issuer);
        }

        var status = VerifyTrust(filePath);
        return status switch
        {
            0 => new AuthenticodeInfo(
                AuthenticodeStatus.Valid,
                "Firma Authenticode valida segun WinTrust local.",
                subject,
                issuer),
            TrustENoSignature or TrustEBadDigest or TrustEExplicitDistrust => new AuthenticodeInfo(
                AuthenticodeStatus.Invalid,
                $"WinTrust rechazo la firma Authenticode con codigo 0x{status:X8}.",
                subject,
                issuer),
            TrustESubjectNotTrusted or CertEUntrustedRoot or CertEChaining => new AuthenticodeInfo(
                AuthenticodeStatus.PresentNotValidated,
                $"Firma presente, pero la confianza local no pudo establecerse completamente (0x{status:X8}).",
                subject,
                issuer),
            _ => new AuthenticodeInfo(
                AuthenticodeStatus.PresentNotValidated,
                $"Firma presente, con resultado WinTrust local no concluyente: 0x{status:X8}.",
                subject,
                issuer)
        };
    }

    private static uint VerifyTrust(string filePath)
    {
        var fileInfo = new WinTrustFileInfo(filePath);
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var trustData = new WinTrustData(fileInfoPointer);
            return WinVerifyTrust(IntPtr.Zero, GenericVerifyV2Action, trustData);
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    private static (string? Subject, string? Issuer) TryReadSigner(string filePath)
    {
        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
            return (NullIfWhiteSpace(certificate.Subject), NullIfWhiteSpace(certificate.Issuer));
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            return (null, null);
        }
    }

    private static string? NullIfWhiteSpace(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        WinTrustData trustData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo
    {
        public uint StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>();
        public string FilePath;
        public IntPtr FileHandle = IntPtr.Zero;
        public IntPtr KnownSubject = IntPtr.Zero;

        public WinTrustFileInfo(string filePath)
        {
            FilePath = filePath;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustData
    {
        public uint StructSize = (uint)Marshal.SizeOf<WinTrustData>();
        public IntPtr PolicyCallbackData = IntPtr.Zero;
        public IntPtr SipClientData = IntPtr.Zero;
        public uint UiChoice = WtdUiNone;
        public uint RevocationChecks = WtdRevokeNone;
        public uint UnionChoice = WtdChoiceFile;
        public IntPtr FileInfoPointer;
        public uint StateAction = WtdStateActionIgnore;
        public IntPtr StateData = IntPtr.Zero;
        public IntPtr UrlReference = IntPtr.Zero;
        public uint ProviderFlags = 0;
        public uint UiContext = 0;

        public WinTrustData(IntPtr fileInfoPointer)
        {
            FileInfoPointer = fileInfoPointer;
        }
    }
}
