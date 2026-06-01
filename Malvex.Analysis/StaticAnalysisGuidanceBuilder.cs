using Malvex.Core.Models;

namespace Malvex.Analysis;

internal static class StaticAnalysisGuidanceBuilder
{
    public static IReadOnlyList<GuidedStep> BuildGuidedSteps(
        IReadOnlyList<HeuristicFinding> findings,
        YaraScanResult yaraResult,
        IReadOnlyList<PeSectionInfo> sections,
        PeAdvancedMetadata advancedMetadata,
        IReadOnlyList<DisassemblyInstruction> disassembly,
        IReadOnlyList<CfgNode> cfg)
    {
        var yaraInterpretation = YaraCorrelationAdvisor.BuildInterpretation(yaraResult, sections, findings);

        return
        [
            new GuidedStep(1, "Paso 1: que es este archivo", "Revisa arquitectura, entrypoint y tamano para saber con que tipo de muestra trabajas."),
            new GuidedStep(2, "Paso 2: senales rapidas", "Busca entropia alta, secciones raras, nombres de packer y strings de comandos."),
            new GuidedStep(3, "Paso 3: capacidad tecnica", "Inspecciona imports y exports para detectar inyeccion, red, persistencia o anti-debug."),
            new GuidedStep(4, "Paso 4: evidencia de firmas", yaraInterpretation),
            new GuidedStep(5, "Paso 5: metadatos avanzados", BuildAdvancedMetadataExplanation(advancedMetadata)),
            new GuidedStep(6, "Paso 6: flujo interno", $"Desensamblado: {disassembly.Count} instrucciones | CFG: {cfg.Count} nodos."),
            new GuidedStep(7, "Paso 7: siguiente accion", BuildConclusion(findings))
        ];
    }

    public static AnalystGuidance BuildAnalystGuidance(
        IReadOnlyList<HeuristicFinding> findings,
        IReadOnlyList<ImportLibrary> imports,
        IReadOnlyList<ExportSymbol> exports,
        IReadOnlyList<PeSectionInfo> sections,
        IReadOnlyList<string> strings,
        YaraScanResult yaraResult,
        RiskScore risk,
        PeAdvancedMetadata advancedMetadata,
        IReadOnlyList<DisassemblyInstruction> disassembly,
        IReadOnlyList<CfgNode> cfg)
    {
        var importedFunctions = imports
            .SelectMany(i => i.Functions)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var yaraInterpretation = YaraCorrelationAdvisor.BuildInterpretation(yaraResult, sections, findings);
        var hypotheses = BuildHypotheses(findings, importedFunctions, exports, strings, yaraResult, risk);
        var checklist = BuildChecklist(importedFunctions, exports, strings, yaraResult, yaraInterpretation, advancedMetadata, disassembly, cfg);
        var actions = BuildActions(findings, risk, hypotheses, yaraResult, yaraInterpretation, advancedMetadata, disassembly, sections);

        var beginnerSummary = risk.Level switch
        {
            RiskLevel.High => $"La muestra requiere atencion prioritaria. Hay indicadores compatibles con comportamiento malicioso. {yaraInterpretation}",
            RiskLevel.Medium => $"La muestra presenta senales mixtas. Conviene validar en sandbox antes de considerarla segura. {yaraInterpretation}",
            _ => $"No hay indicadores criticos en este analisis inicial, pero se recomienda validacion complementaria. {yaraInterpretation}"
        };

        var expertSummary =
            $"Riesgo={risk.Level}({risk.Score}/100), Hallazgos={findings.Count}, YARA={yaraResult.Matches.Count}, " +
            $"TLSCallbacks={advancedMetadata.TlsCallbackVas.Count}, Authenticode={advancedMetadata.Authenticode.Status}, " +
            $"Desensamblado={disassembly.Count}, NodosCFG={cfg.Count}. ContextoYARA={yaraInterpretation}";

        return new AnalystGuidance(beginnerSummary, expertSummary, hypotheses, checklist, actions);
    }

    private static string BuildConclusion(IReadOnlyList<HeuristicFinding> findings)
    {
        var critical = findings.Count(f => f.Severity == AnalysisSeverity.Critical);
        var warnings = findings.Count(f => f.Severity == AnalysisSeverity.Warning);
        if (critical > 0)
        {
            return $"Prioridad alta: {critical} hallazgo(s) critico(s). Aisla la muestra, correlaciona evidencia estatica y escala la validacion externa.";
        }

        if (warnings > 0)
        {
            return $"Riesgo moderado: {warnings} advertencia(s). Correlaciona secciones, imports, cadenas y reglas YARA antes de concluir.";
        }

        return "Sin alertas destacables en analisis inicial. Mantener validacion cruzada con sandbox y reputacion externa.";
    }

    private static string BuildAdvancedMetadataExplanation(PeAdvancedMetadata metadata)
    {
        var tlsText = metadata.TlsCallbackVas.Count > 0
            ? $"{metadata.TlsCallbackVas.Count} callback(s) TLS para revisar antes del entrypoint"
            : "sin callbacks TLS detectados";
        var imphashText = string.IsNullOrWhiteSpace(metadata.Imphash)
            ? "imphash no disponible"
            : $"imphash {metadata.Imphash}";

        return $"Authenticode: {metadata.Authenticode.Description} Recursos: {metadata.ResourceTypes.Count} tipo(s); {tlsText}; {imphashText}.";
    }

    private static IReadOnlyList<AnalysisHypothesis> BuildHypotheses(
        IReadOnlyList<HeuristicFinding> findings,
        IReadOnlySet<string> importedFunctions,
        IReadOnlyList<ExportSymbol> exports,
        IReadOnlyList<string> strings,
        YaraScanResult yaraResult,
        RiskScore risk)
    {
        var list = new List<AnalysisHypothesis>();

        var hasStrongInjection = importedFunctions.Contains("WriteProcessMemory") &&
                                 importedFunctions.Contains("CreateRemoteThread");
        if (hasStrongInjection)
        {
            list.Add(new AnalysisHypothesis(
                "Posible inyeccion de codigo en proceso remoto",
                HypothesisConfidence.High,
                ["Se detecto el par WriteProcessMemory + CreateRemoteThread."]));
        }

        var hasEmbeddedUrl = strings.Any(s =>
            s.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("https://", StringComparison.OrdinalIgnoreCase));
        var hasNetworkImport = importedFunctions.Contains("URLDownloadToFile") ||
                               importedFunctions.Contains("HttpSendRequest");
        var hasCommandFinding = findings.Any(f =>
            f.Title.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ||
            f.Title.Contains("shell", StringComparison.OrdinalIgnoreCase));
        var hasDownloader = hasNetworkImport || (hasEmbeddedUrl && hasCommandFinding);
        if (hasDownloader)
        {
            list.Add(new AnalysisHypothesis(
                "Posible downloader o beacon de red",
                risk.Level == RiskLevel.High ? HypothesisConfidence.High : HypothesisConfidence.Medium,
                ["APIs/red strings relacionadas con descarga o HTTP detectadas."]));
        }

        if (findings.Any(f => f.Title.Contains("PowerShell", StringComparison.OrdinalIgnoreCase)))
        {
            list.Add(new AnalysisHypothesis(
                "Posible ejecucion por scripting (PowerShell)",
                HypothesisConfidence.Medium,
                ["Se detectaron cadenas de PowerShell con indicadores adicionales de automatizacion u ocultacion."]));
        }

        if (yaraResult.Matches.Count > 0)
        {
            list.Add(new AnalysisHypothesis(
                "Coincidencia con reglas YARA",
                HypothesisConfidence.High,
                [$"Reglas detectadas: {string.Join(", ", yaraResult.Matches)}"]));
        }

        if (exports.Any(e => StaticAnalysisPatterns.IsSensitiveExportName(e.Name)))
        {
            list.Add(new AnalysisHypothesis(
                "Posible DLL orientada a carga manual, servicio o abuso de exports",
                risk.Level == RiskLevel.High ? HypothesisConfidence.High : HypothesisConfidence.Medium,
                ["Se detectaron exports con nombres asociados a reflective loading, instalacion o servicios."]));
        }

        if (findings.Any(f => f.Title.Contains("persistencia", StringComparison.OrdinalIgnoreCase)))
        {
            list.Add(new AnalysisHypothesis(
                "Posible mecanismo de persistencia local",
                HypothesisConfidence.Medium,
                ["Se detectaron cadenas o indicadores asociados a claves Run/RunOnce."]));
        }

        if (findings.Any(f => f.Title.Contains("ransomware", StringComparison.OrdinalIgnoreCase) || f.Title.Contains("impacto", StringComparison.OrdinalIgnoreCase)))
        {
            list.Add(new AnalysisHypothesis(
                "Posible capacidad de impacto sobre disponibilidad o recuperacion",
                HypothesisConfidence.High,
                ["Se detectaron cadenas asociadas a borrado de copias sombra o backup."]));
        }

        if (list.Count == 0)
        {
            list.Add(new AnalysisHypothesis(
                "Sin patron malicioso dominante en estatico inicial",
                HypothesisConfidence.Low,
                ["No hubo coincidencias YARA ni APIs de alto riesgo destacables."]));
        }

        return list;
    }

    private static IReadOnlyList<AnalystChecklistItem> BuildChecklist(
        IReadOnlySet<string> importedFunctions,
        IReadOnlyList<ExportSymbol> exports,
        IReadOnlyList<string> strings,
        YaraScanResult yaraResult,
        string yaraInterpretation,
        PeAdvancedMetadata advancedMetadata,
        IReadOnlyList<DisassemblyInstruction> disassembly,
        IReadOnlyList<CfgNode> cfg)
    {
        return
        [
            new AnalystChecklistItem("YARA disponible", yaraResult.IsAvailable, yaraInterpretation),
            new AnalystChecklistItem(
                "Busqueda de cadenas de comando",
                strings.Any(s => s.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) || s.Contains("powershell", StringComparison.OrdinalIgnoreCase)),
                "Revisar posibles lineas de comando embebidas."),
            new AnalystChecklistItem(
                "APIs de inyeccion",
                importedFunctions.Contains("WriteProcessMemory") || importedFunctions.Contains("CreateRemoteThread"),
                "Correlacionar el par de APIs con imports, cadenas y desensamblado."),
            new AnalystChecklistItem("Exports sensibles", exports.Any(e => StaticAnalysisPatterns.IsSensitiveExportName(e.Name)), $"Exports totales detectados: {exports.Count}."),
            new AnalystChecklistItem("Firma Authenticode valida", advancedMetadata.Authenticode.Status == AuthenticodeStatus.Valid, advancedMetadata.Authenticode.Description),
            new AnalystChecklistItem("Callbacks TLS", advancedMetadata.TlsCallbackVas.Count > 0, advancedMetadata.TlsCallbackVas.Count > 0 ? $"Revisar {advancedMetadata.TlsCallbackVas.Count} callback(s) previos al entrypoint." : "No se detectaron callbacks TLS."),
            new AnalystChecklistItem("Recursos PE", advancedMetadata.ResourceTypes.Count > 0, advancedMetadata.ResourceTypes.Count > 0 ? $"Tipos detectados: {string.Join(", ", advancedMetadata.ResourceTypes)}." : "No se detectaron recursos PE."),
            new AnalystChecklistItem("Cobertura de desensamblado", disassembly.Count > 0, $"Instrucciones decodificadas: {disassembly.Count}."),
            new AnalystChecklistItem("Cobertura de CFG", cfg.Count > 0, $"Nodos CFG generados: {cfg.Count}.")
        ];
    }

    private static IReadOnlyList<SuggestedAction> BuildActions(
        IReadOnlyList<HeuristicFinding> findings,
        RiskScore risk,
        IReadOnlyList<AnalysisHypothesis> hypotheses,
        YaraScanResult yaraResult,
        string yaraInterpretation,
        PeAdvancedMetadata advancedMetadata,
        IReadOnlyList<DisassemblyInstruction> disassembly,
        IReadOnlyList<PeSectionInfo> sections)
    {
        var actions = new List<SuggestedAction>
        {
            new(1, "Revisar evidencia estatica correlacionada", "Empieza por hallazgos, secciones destacadas, imports y cadenas antes de emitir una conclusion."),
            new(2, "Correlacionar hash y reputacion", "Cruzar SHA256 con inteligencia externa acelera el triage sin ejecutar la muestra.")
        };

        if (hypotheses.Any(h => h.Title.Contains("inyeccion", StringComparison.OrdinalIgnoreCase)))
        {
            actions.Add(new SuggestedAction(
                1,
                "Inspeccionar imports de inyeccion y entrypoint",
                "La hipotesis principal combina WriteProcessMemory y CreateRemoteThread."));
        }

        if (yaraResult.IsAvailable &&
            yaraResult.Matches.Count == 0 &&
            findings.Any(f => f.Severity is AnalysisSeverity.Warning or AnalysisSeverity.Critical))
        {
            actions.Add(new SuggestedAction(
                2,
                "Ampliar set de reglas YARA",
                yaraInterpretation));
        }

        if (!yaraResult.IsAvailable)
        {
            actions.Add(new SuggestedAction(
                1,
                "Restaurar disponibilidad de YARA",
                "El analisis no pudo ejecutar el motor YARA. Revisa rules/, tools/yara/ y el runtime de Visual C++."));
        }

        if (yaraResult.IsAvailable && yaraResult.Matches.Count == 0 && sections.Any(SectionSignalClassifier.HasHighEntropy))
        {
            actions.Add(new SuggestedAction(
                1,
                "Intentar desempaquetado y re-ejecutar YARA",
                "La muestra presenta secciones con entropia alta; YARA puede estar viendo el payload aun empaquetado."));
        }

        if (disassembly.Count > 0)
        {
            actions.Add(new SuggestedAction(
                3,
                "Revisar primer bloque del entrypoint",
                "El flujo inicial suele contener loader, unpacking o redireccionamientos."));
        }

        if (advancedMetadata.TlsCallbackVas.Count > 0)
        {
            actions.Add(new SuggestedAction(
                2,
                "Revisar callbacks TLS antes del entrypoint",
                "Los callbacks TLS pueden ejecutar logica antes del flujo convencional y merecen inspeccion estatica manual."));
        }

        if (advancedMetadata.Authenticode.Status is AuthenticodeStatus.Invalid or AuthenticodeStatus.PresentNotValidated)
        {
            actions.Add(new SuggestedAction(
                3,
                "Confirmar firma Authenticode y reputacion",
                "WinTrust no valido localmente la firma. Revisa cadena de confianza, hash y procedencia antes de concluir."));
        }

        if (findings.Any(f => f.Title.Contains("Exports sensibles", StringComparison.OrdinalIgnoreCase)))
        {
            actions.Add(new SuggestedAction(
                2,
                "Revisar exports y modo de invocacion",
                "Los exports pueden revelar entrypoints alternativos, servicios o reflective loading."));
        }

        if (findings.Any(f => f.Title.Contains("persistencia", StringComparison.OrdinalIgnoreCase)))
        {
            actions.Add(new SuggestedAction(
                1,
                "Validar persistencia en registro y autoruns",
                "Las cadenas observadas sugieren claves Run/RunOnce u otros mecanismos locales."));
        }

        if (findings.Any(f => f.Title.Contains("ransomware", StringComparison.OrdinalIgnoreCase) || f.Title.Contains("impacto", StringComparison.OrdinalIgnoreCase)))
        {
            actions.Add(new SuggestedAction(
                1,
                "Aislar muestra y revisar impacto sobre backups",
                "Las cadenas encontradas son compatibles con comportamiento destructivo o anti-recuperacion."));
        }

        if (risk.Level == RiskLevel.High)
        {
            actions.Add(new SuggestedAction(
                1,
                "Elevar a respuesta de incidentes",
                "Puntaje alto con indicadores criticos."));
            actions.Add(new SuggestedAction(
                2,
                "Validar externamente en sandbox aislada",
                "La ejecucion controlada debe realizarse fuera de Malvex y nunca en el host principal."));
        }

        return actions
            .OrderBy(a => a.Priority)
            .ThenBy(a => a.Action, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
