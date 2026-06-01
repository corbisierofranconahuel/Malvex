using System.Globalization;
using System.IO;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Malvex.Analysis;
using Malvex.Core.Models;
using Microsoft.Win32;

namespace Malvex.App;

public partial class MainWindow : Window
{
    private readonly AnalysisSessionService _analysisSessionService;
    private readonly string _preferencesPath;
    private PeAnalysisResult? _lastResult;
    private bool _suppressUiEvents;
    private readonly IReadOnlyDictionary<string, string> _tutorialSections;

    private static readonly IReadOnlyDictionary<string, ThemePalette> Themes =
        new Dictionary<string, ThemePalette>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cyber Neon"] = new ThemePalette(
                "#070D1A", "#0D1630", "#0A1226", "#101D3B", "#2B3F6A", "#E9F2FF", "#9CB6E0", "#23F2B2", "#08111D", 0.09),
            ["Ocean Steel"] = new ThemePalette(
                "#0A1017", "#132536", "#0F1D2C", "#163148", "#3A5878", "#F1F7FF", "#A5BED7", "#3ED6FF", "#03212C", 0.08),
            ["Sunset Terminal"] = new ThemePalette(
                "#1A0E0B", "#2F1712", "#24120E", "#3A1F18", "#6B3E30", "#FFF2E9", "#E1BDAE", "#FF9D57", "#2E1306", 0.07),
            ["Clean Light"] = new ThemePalette(
                "#E9EEF5", "#DCE6F2", "#F3F7FC", "#FFFFFF", "#A6B7CB", "#1F2D3E", "#506277", "#1E9E7D", "#FFFFFF", 0.025)
        };

    public MainWindow()
    {
        StartupDiagnostics.Log("MainWindow ctor begin.");
        InitializeComponent();
        StartupDiagnostics.Log("MainWindow InitializeComponent done.");
        _analysisSessionService = new AnalysisSessionService(new PeStaticAnalyzer(), new ReportExporter());
        StartupDiagnostics.Log("AnalysisSessionService ready.");
        Closed += MainWindow_Closed;
        _preferencesPath = AppPaths.PreferencesFile;
        _tutorialSections = AnalysisPresentationBuilder.BuildTutorialSections();

        LoadPreferences();
        ApplyTheme(GetSelectedComboText(ThemeComboBox) ?? "Cyber Neon");
        InitializeTutorialUi();
        SetStatus("Estado: esperando analisis");
        StartupDiagnostics.Log("MainWindow ctor finished.");
    }

    private async void AnalyzeButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Archivos PE (*.exe;*.dll)|*.exe;*.dll|Todos los archivos (*.*)|*.*",
            Title = "Seleccionar archivo PE"
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        AnalyzeButton.IsEnabled = false;
        SetStatus("Estado: analizando...");

        try
        {
            var result = await Task.Run(() => _analysisSessionService.Analyze(dialog.FileName));
            _lastResult = result;
            RenderResult(result);

            var yaraSummary = result.YaraAvailable
                ? (result.YaraMatches.Count > 0
                    ? $" | YARA: {result.YaraMatches.Count} coincidencia(s)"
                    : " | YARA: sin coincidencias")
                : " | YARA: no disponible";
            SetStatus($"Estado: analisis finalizado{yaraSummary}");
            ExportJsonButton.IsEnabled = true;
            ExportHtmlButton.IsEnabled = true;
            CopySummaryTopButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            SetStatus("Estado: error");
            MessageBox.Show(
                "No se pudo analizar el archivo.\n\n" +
                $"Detalle: {ex.Message}\n\n" +
                "Sugerencias:\n" +
                "- Verifica que sea un .exe/.dll PE valido.\n" +
                "- Confirma que el archivo no este corrupto o bloqueado.\n" +
                "- Si el problema persiste, revisa startup.log y vuelve a intentar.",
                "Malvex",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            AnalyzeButton.IsEnabled = true;
        }
    }

    private void ExportJsonButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        try
        {
            var path = _analysisSessionService.ExportJson(_lastResult);
            SetStatus("Estado: reporte JSON exportado.");
            MessageBox.Show(
                "Reporte JSON exportado correctamente.\n\n" +
                $"Archivo: {path}\n" +
                $"Carpeta de reportes: {AppPaths.ReportsDirectory}",
                "Malvex",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "No se pudo exportar JSON.\n\n" +
                $"Detalle: {ex.Message}\n\n" +
                "Verifica permisos de escritura en la carpeta de reportes e intenta de nuevo.",
                "Malvex",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ExportHtmlButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        try
        {
            var path = _analysisSessionService.ExportHtml(_lastResult);
            SetStatus("Estado: reporte HTML exportado.");
            MessageBox.Show(
                "Reporte HTML exportado correctamente.\n\n" +
                $"Archivo: {path}\n" +
                $"Carpeta de reportes: {AppPaths.ReportsDirectory}",
                "Malvex",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "No se pudo exportar HTML.\n\n" +
                $"Detalle: {ex.Message}\n\n" +
                "Verifica permisos de escritura en la carpeta de reportes e intenta de nuevo.",
                "Malvex",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var theme = GetSelectedComboText(ThemeComboBox);
        if (!string.IsNullOrWhiteSpace(theme))
        {
            ApplyTheme(theme);
            if (!_suppressUiEvents)
            {
                SavePreferences();
            }
        }
    }

    private void TutorialSectionList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (TutorialSectionList.SelectedItem is not string selected)
        {
            return;
        }

        if (_tutorialSections.TryGetValue(selected, out var content))
        {
            TutorialContentTextBox.Text = content;
        }
    }

    private void FindingsFilterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        RenderFindings(_lastResult);
    }

    private void RenderResult(PeAnalysisResult result)
    {
        SetInfo(FileInfoText, $"Archivo: {result.FileName} | Tamano: {AnalysisPresentationBuilder.FormatSize(result.FileSize)}");
        SetInfo(ArchInfoText, $"Arquitectura: {result.Architecture} | {(result.Is64Bit ? "x64" : "x86")}");
        SetInfo(HashInfoText, $"SHA256: {result.Sha256[..Math.Min(18, result.Sha256.Length)]}...");
        SetInfo(RiskInfoText, $"Riesgo: {AnalysisPresentationBuilder.TranslateRiskLevel(result.Risk.Level)} ({result.Risk.Score}/100)");
        SetInfo(
            StaticMetadataText,
            $"{(result.Is64Bit ? "PE32+" : "PE32")} | Entry point RVA: 0x{result.EntryPointRva:X8} | Image base: 0x{result.ImageBase:X} | " +
            $"Secciones: {result.Sections.Count} | Imports: {result.Imports.Count} | Exports: {result.Exports.Count} | Cadenas: {result.Strings.Count}\n" +
            $"Timestamp COFF: {(result.CoffTimestampUtc?.ToString("yyyy-MM-dd HH:mm 'UTC'") ?? "ausente/no confiable")} | " +
            $"Overlay: {AnalysisPresentationBuilder.FormatSize(result.OverlaySize)} | " +
            $"Authenticode: {AnalysisPresentationBuilder.TranslateAuthenticodeStatus(result.AdvancedMetadata.Authenticode.Status)} | " +
            $"TLS callbacks: {result.AdvancedMetadata.TlsCallbackVas.Count}\n" +
            $"Imphash: {(string.IsNullOrWhiteSpace(result.AdvancedMetadata.Imphash) ? "no disponible" : result.AdvancedMetadata.Imphash)} | " +
            $"Rich Header: {(result.AdvancedMetadata.RichHeader.IsPresent ? "presente" : "no detectado")} | " +
            $"Recursos: {result.AdvancedMetadata.Resources.Count} entrada(s) / {AnalysisPresentationBuilder.FormatSize(result.AdvancedMetadata.ResourceTableSize)} | " +
            $"PDB: {result.AdvancedMetadata.DebugPdbPath ?? "no detectada"}");

        SectionsGrid.ItemsSource = SectionPresentationBuilder.BuildRows(result.Sections);
        SetInfo(SectionSignalsText, SectionPresentationBuilder.BuildSummary(result.Sections));
        RenderAdvancedMetadata(result);

        ImportsList.ItemsSource = result.Imports
            .Select(i =>
            {
                var preview = string.Join(", ", i.Functions.Take(10));
                var remainder = i.Functions.Count > 10 ? ", ..." : string.Empty;
                return $"{i.Name} ({i.Functions.Count}){(string.IsNullOrWhiteSpace(preview) ? string.Empty : $": {preview}{remainder}")}";
            })
            .ToList();

        ExportsList.ItemsSource = result.Exports
            .Take(600)
            .Select(x => $"{x.Name} | ord {x.Ordinal} | RVA 0x{x.AddressRva:X8}")
            .ToList();

        RenderFindings(result);
        ExecutiveSummaryTextBox.Text = AnalysisPresentationBuilder.BuildExecutiveSummary(result);

        YaraList.ItemsSource = result.YaraMatches.Count > 0
            ? new[] { result.YaraMessage }.Concat(result.YaraMatches).ToList()
            : [result.YaraMessage];
        SetInfo(YaraContextText, AnalysisPresentationBuilder.BuildYaraInterpretation(result));

        GuidedList.ItemsSource = AnalysisPresentationBuilder.BuildGuidedSteps(result);

        RenderStrings(result);

        DisassemblyGrid.ItemsSource = result.Disassembly
            .Take(260)
            .ToList();

        CfgGrid.ItemsSource = result.CfgNodes
            .Select(n => new CfgRow(n.Id, n.StartRva, n.EndRva, n.SuccessorIds.Count > 0 ? string.Join(", ", n.SuccessorIds) : "-"))
            .ToList();

        QuickTriageList.ItemsSource = AnalysisPresentationBuilder.BuildQuickTriage(result);
        TimelineList.ItemsSource = AnalysisPresentationBuilder.BuildTimeline(result);

        HypothesesList.ItemsSource = AnalysisPresentationBuilder.BuildHypotheses(result);

        ChecklistList.ItemsSource = AnalysisPresentationBuilder.BuildChecklist(result);

        SuggestedActionsList.ItemsSource = AnalysisPresentationBuilder.BuildSuggestedActions(result);

        RiskReasonsList.ItemsSource = result.Risk.Reasons;
        RiskReasonsListSummary.ItemsSource = result.Risk.Reasons;
        TutorialQuickStartList.ItemsSource = AnalysisPresentationBuilder.BuildTutorialQuickStart(result);

        HexRvaTextBox.Text = $"0x{result.EntryPointRva:X}";
    }

    private void RenderAdvancedMetadata(PeAnalysisResult result)
    {
        var metadata = result.AdvancedMetadata;
        AdvancedIdentityList.ItemsSource = new[]
        {
            $"Formato: {(result.Is64Bit ? "PE32+" : "PE32")} | Arquitectura: {result.Architecture}",
            $"Entry point RVA: 0x{result.EntryPointRva:X8} | Image base: 0x{result.ImageBase:X}",
            $"SHA256: {result.Sha256}",
            $"Imphash: {(string.IsNullOrWhiteSpace(metadata.Imphash) ? "no disponible" : metadata.Imphash)}",
            $"Rich Header: {(metadata.RichHeader.IsPresent ? $"presente | Hash {metadata.RichHeader.Hash} | Entradas {metadata.RichHeader.EntryCount}" : "no detectado")}",
            $"Timestamp COFF orientativo: {result.CoffTimestampUtc?.ToString("yyyy-MM-dd HH:mm 'UTC'") ?? "ausente/no confiable"}",
            $"Overlay fuera de secciones/certificado: {AnalysisPresentationBuilder.FormatSize(result.OverlaySize)}"
        };

        AuthenticodeDetailsList.ItemsSource = new[]
        {
            $"Estado: {AnalysisPresentationBuilder.TranslateAuthenticodeStatus(metadata.Authenticode.Status)}",
            metadata.Authenticode.Description,
            $"Firmante: {metadata.Authenticode.Subject ?? "no disponible"}",
            $"Emisor: {metadata.Authenticode.Issuer ?? "no disponible"}",
            $"Tabla de certificados: {(result.CertificateTableSize > 0 ? AnalysisPresentationBuilder.FormatSize(result.CertificateTableSize) : "no detectada")}"
        };

        TlsCallbacksList.ItemsSource = metadata.TlsCallbackVas.Count > 0
            ? metadata.TlsCallbackVas
                .Select((address, index) =>
                {
                    var rva = address >= result.ImageBase ? address - result.ImageBase : address;
                    return $"Callback #{index + 1}: VA 0x{address:X} | RVA 0x{rva:X}";
                })
                .ToList()
            : ["Sin callbacks TLS detectados."];
        TlsCallbacksList.SelectedIndex = metadata.TlsCallbackVas.Count > 0 ? 0 : -1;
        TlsToHexButton.IsEnabled = metadata.TlsCallbackVas.Count > 0;
        TlsDisassembleButton.IsEnabled = metadata.TlsCallbackVas.Count > 0;

        ResourceTypesList.ItemsSource = metadata.Resources.Count > 0
            ? new[] { $"Tamano de tabla: {AnalysisPresentationBuilder.FormatSize(metadata.ResourceTableSize)} | Entradas: {metadata.Resources.Count}" }
                .Concat(metadata.Resources.Select(resource =>
                    $"{resource.Type} | {resource.Name} | {resource.Language} | RVA 0x{resource.DataRva:X8} | {AnalysisPresentationBuilder.FormatSize(resource.Size)}"))
                .ToList()
            : ["Sin recursos PE detectados."];
        ResourceTypesList.SelectedIndex = metadata.Resources.Count > 0 ? 1 : -1;
        ResourceToHexButton.IsEnabled = metadata.Resources.Count > 0;

        VersionMetadataList.ItemsSource = new[]
        {
            $"Descripcion: {metadata.FileDescription ?? "no disponible"}",
            $"Producto: {metadata.ProductName ?? "no disponible"}",
            $"Empresa: {metadata.CompanyName ?? "no disponible"}",
            $"Version: {metadata.FileVersion ?? "no disponible"}",
            $"Ruta PDB: {metadata.DebugPdbPath ?? "no detectada"}"
        };
    }

    private void RenderFindings(PeAnalysisResult result)
    {
        var filter = GetSelectedComboText(FindingsFilterComboBox) ?? "Todos";
        FindingsList.ItemsSource = AnalysisPresentationBuilder.BuildFindings(result, filter);
    }

    private void StringsFilterTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_lastResult is not null)
        {
            RenderStrings(_lastResult);
        }
    }

    private void RenderStrings(PeAnalysisResult result)
    {
        var filter = StringsFilterTextBox.Text?.Trim();
        var strings = string.IsNullOrWhiteSpace(filter)
            ? result.Strings
            : result.Strings
                .Where(value => value.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .ToList();

        StringsList.ItemsSource = strings.Count > 0
            ? strings.Take(500).ToList()
            : ["Sin cadenas que coincidan con el filtro."];
    }

    private void CopySummaryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            MessageBox.Show("No hay analisis cargado para copiar resumen.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var summary = ExecutiveSummaryTextBox.Text;
            if (string.IsNullOrWhiteSpace(summary))
            {
                summary = AnalysisPresentationBuilder.BuildExecutiveSummary(_lastResult);
                ExecutiveSummaryTextBox.Text = summary;
            }

            Clipboard.SetText(summary);
            SetStatus("Estado: resumen ejecutivo copiado al portapapeles.");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"No se pudo copiar el resumen.\n{ex.Message}", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }


    private void LoadHexButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            MessageBox.Show("Primero analiza un PE para usar la Vista Hex.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!TryParseHexAddress(HexRvaTextBox.Text?.Trim() ?? string.Empty, out var rvaUlong))
        {
            MessageBox.Show("RVA invalido. Usa formato hex (0x...).", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (rvaUlong > int.MaxValue)
        {
            MessageBox.Show("RVA fuera de rango.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        LoadHexAtRva((int)rvaUlong);
    }

    private void LoadHexAtRva(int rva)
    {
        if (_lastResult is null)
        {
            return;
        }

        var offset = RvaToOffset(rva, _lastResult.Sections);
        if (offset < 0 || offset >= _lastResult.FileSize)
        {
            MessageBox.Show("No se pudo mapear RVA a offset de archivo.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var bytes = ReadFileWindow(_lastResult.FilePath, offset, 512);
            HexDumpTextBox.Text = BuildHexDump(bytes, offset);
            HexRvaTextBox.Text = $"0x{rva:X}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"No se pudo leer la vista hexadecimal.\n\nDetalle: {ex.Message}", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void TlsToHexButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryGetSelectedTlsCallbackRva(out var rva))
        {
            return;
        }

        LoadHexAtRva(rva);
        MainTabControl.SelectedItem = HexTabItem;
        SetStatus($"Estado: vista Hex posicionada en callback TLS RVA 0x{rva:X}.");
    }

    private void TlsDisassembleButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null || !TryGetSelectedTlsCallbackRva(out var rva))
        {
            return;
        }

        var offset = RvaToOffset(rva, _lastResult.Sections);
        if (offset < 0 || offset >= _lastResult.FileSize)
        {
            MessageBox.Show("No se pudo mapear el callback TLS a offset de archivo.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var bytes = ReadFileWindow(_lastResult.FilePath, offset, 4096);
            DisassemblyGrid.ItemsSource = new IcedDisassembler()
                .DisassembleCodeWindow(bytes, rva, _lastResult.Is64Bit, _lastResult.ImageBase, offset);
            MainTabControl.SelectedItem = DisassemblyTabItem;
            SetStatus($"Estado: desensamblado localizado en callback TLS RVA 0x{rva:X}.");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"No se pudo desensamblar el callback TLS.\n\nDetalle: {ex.Message}", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private bool TryGetSelectedTlsCallbackRva(out int rva)
    {
        rva = 0;
        if (_lastResult is null ||
            TlsCallbacksList.SelectedIndex < 0 ||
            TlsCallbacksList.SelectedIndex >= _lastResult.AdvancedMetadata.TlsCallbackVas.Count)
        {
            MessageBox.Show("Selecciona un callback TLS para continuar.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Information);
            return false;
        }

        var address = _lastResult.AdvancedMetadata.TlsCallbackVas[TlsCallbacksList.SelectedIndex];
        var rvaUlong = address >= _lastResult.ImageBase ? address - _lastResult.ImageBase : address;
        if (rvaUlong > int.MaxValue)
        {
            MessageBox.Show("El callback TLS esta fuera del rango RVA compatible.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        rva = (int)rvaUlong;
        return true;
    }

    private void ResourceToHexButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResult is null)
        {
            return;
        }

        var resourceIndex = ResourceTypesList.SelectedIndex - 1;
        if (resourceIndex < 0 || resourceIndex >= _lastResult.AdvancedMetadata.Resources.Count)
        {
            MessageBox.Show("Selecciona una entrada de recurso PE para continuar.", "Malvex", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var resource = _lastResult.AdvancedMetadata.Resources[resourceIndex];
        LoadHexAtRva(resource.DataRva);
        MainTabControl.SelectedItem = HexTabItem;
        SetStatus($"Estado: vista Hex posicionada en recurso {resource.Type} RVA 0x{resource.DataRva:X}.");
    }

    private static byte[] ReadFileWindow(string filePath, int offset, int maxBytes)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        stream.Seek(offset, SeekOrigin.Begin);
        var bytes = new byte[Math.Min(maxBytes, (int)Math.Min(int.MaxValue, Math.Max(0, stream.Length - offset)))];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static int RvaToOffset(int rva, IReadOnlyList<PeSectionInfo> sections)
    {
        foreach (var section in sections)
        {
            var start = (long)section.VirtualAddress;
            var end = start + Math.Max(section.VirtualSize, section.RawSize);
            if (rva < start || rva >= end)
            {
                continue;
            }

            var offset = (long)section.RawPointer + (rva - start);
            return offset is >= 0 and <= int.MaxValue ? (int)offset : -1;
        }

        return -1;
    }

    private static string BuildHexDump(byte[] bytes, int startOffset)
    {
        var sb = new StringBuilder();

        for (var i = 0; i < bytes.Length; i += 16)
        {
            var lineLen = Math.Min(16, bytes.Length - i);
            var offset = startOffset + i;
            var chunk = bytes.AsSpan(i, lineLen);

            sb.Append(offset.ToString("X8")).Append("  ");
            for (var j = 0; j < 16; j++)
            {
                if (j < lineLen)
                {
                    sb.Append(chunk[j].ToString("X2")).Append(' ');
                }
                else
                {
                    sb.Append("   ");
                }
            }

            sb.Append(" ");
            for (var j = 0; j < lineLen; j++)
            {
                var b = chunk[j];
                sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static bool TryParseHexAddress(string raw, out ulong value)
    {
        var cleaned = raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? raw[2..]
            : raw;
        return ulong.TryParse(cleaned, NumberStyles.HexNumber, null, out value);
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        SavePreferences();
    }

    private void OpenReportsButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = AppPaths.ReportsDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"No se pudo abrir la carpeta de reportes.\n\nDetalle: {ex.Message}", "Malvex", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void StatusBlock_ToolTipOpening(object sender, ToolTipEventArgs e)
    {
        if (sender is TextBlock block)
        {
            block.ToolTip = block.Text;
        }
    }

    private void SetStatus(string text)
    {
        SetInfo(StatusText, text);
    }

    private static void SetInfo(TextBlock block, string text)
    {
        block.Text = text;
        block.ToolTip = text;
    }

    private void ApplyTheme(string name)
    {
        if (!Themes.TryGetValue(name, out var palette))
        {
            return;
        }

        SetBrushColor("AppBackgroundBrush", palette.AppBackground);
        SetBrushColor("PanelBackgroundBrush", palette.PanelBackground);
        SetBrushColor("SurfaceBackgroundBrush", palette.SurfaceBackground);
        SetBrushColor("ControlBackgroundBrush", palette.ControlBackground);
        SetBrushColor("ControlBorderBrush", palette.ControlBorder);
        SetBrushColor("TextPrimaryBrush", palette.TextPrimary);
        SetBrushColor("TextMutedBrush", palette.TextMuted);
        SetBrushColor("AccentBrush", palette.Accent);
        SetBrushColor("AccentTextBrush", palette.AccentText);

        SetBrushColor(SystemColors.WindowBrushKey, palette.ControlBackground);
        SetBrushColor(SystemColors.WindowTextBrushKey, palette.TextPrimary);
        SetBrushColor(SystemColors.HighlightBrushKey, palette.PanelBackground);
        SetBrushColor(SystemColors.HighlightTextBrushKey, palette.TextPrimary);
        SetBrushColor(SystemColors.ControlBrushKey, palette.ControlBackground);
        SetBrushColor(SystemColors.ControlTextBrushKey, palette.TextPrimary);
        SetBrushColor(SystemColors.InfoBrushKey, palette.SurfaceBackground);
        SetBrushColor(SystemColors.InfoTextBrushKey, palette.TextPrimary);

        if (ThemeBackgroundImage is not null)
        {
            ThemeBackgroundImage.Opacity = palette.BackgroundImageOpacity;
        }
    }

    private void SetBrushColor(object key, string hex)
    {
        if (ColorConverter.ConvertFromString(hex) is not Color color)
        {
            return;
        }

        var brush = new SolidColorBrush(color);
        Resources[key] = brush;
        if (Application.Current is not null)
        {
            Application.Current.Resources[key] = brush;
        }
    }

    private void LoadPreferences()
    {
        _suppressUiEvents = true;
        try
        {
            if (!File.Exists(_preferencesPath))
            {
                return;
            }

            var json = File.ReadAllText(_preferencesPath);
            var preferences = JsonSerializer.Deserialize<UiPreferences>(json);
            if (preferences is null)
            {
                return;
            }

            SelectComboByText(ThemeComboBox, preferences.Theme);
        }
        catch
        {
            // Ignore malformed settings and continue with defaults.
        }
        finally
        {
            _suppressUiEvents = false;
        }
    }

    private void SavePreferences()
    {
        try
        {
            var preferences = new UiPreferences
            {
                Theme = GetSelectedComboText(ThemeComboBox) ?? "Cyber Neon"
            };

            var folder = Path.GetDirectoryName(_preferencesPath);
            if (!string.IsNullOrWhiteSpace(folder))
            {
                Directory.CreateDirectory(folder);
            }

            var json = JsonSerializer.Serialize(preferences, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_preferencesPath, json);
        }
        catch
        {
            // Ignore persistence failures to avoid blocking UI.
        }
    }

    private static void SelectComboByText(ComboBox comboBox, string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        foreach (var item in comboBox.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Content?.ToString(), text, StringComparison.OrdinalIgnoreCase))
            {
                comboBox.SelectedItem = item;
                return;
            }
        }
    }

    private static string? GetSelectedComboText(ComboBox comboBox)
    {
        return (comboBox.SelectedItem as ComboBoxItem)?.Content?.ToString();
    }

    private void InitializeTutorialUi()
    {
        TutorialSectionList.ItemsSource = _tutorialSections.Keys.ToList();
        TutorialQuickStartList.ItemsSource = AnalysisPresentationBuilder.BuildTutorialQuickStart(_lastResult);

        SelectTutorialSection("01 - Vision General");
    }

    private sealed record CfgRow(int Id, int StartRva, int EndRva, string SuccessorsText);

    private sealed record ThemePalette(
        string AppBackground,
        string PanelBackground,
        string SurfaceBackground,
        string ControlBackground,
        string ControlBorder,
        string TextPrimary,
        string TextMuted,
        string Accent,
        string AccentText,
        double BackgroundImageOpacity);

    private sealed class UiPreferences
    {
        public string Theme { get; set; } = "Cyber Neon";
    }

    private void SelectTutorialSection(string key)
    {
        for (var i = 0; i < TutorialSectionList.Items.Count; i++)
        {
            if (string.Equals(TutorialSectionList.Items[i]?.ToString(), key, StringComparison.OrdinalIgnoreCase))
            {
                TutorialSectionList.SelectedIndex = i;
                return;
            }
        }

        if (TutorialSectionList.Items.Count > 0)
        {
            TutorialSectionList.SelectedIndex = 0;
        }
    }
}
