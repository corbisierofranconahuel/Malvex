# Release Checklist

Checklist minima antes de publicar una version de Malvex.

## Codigo y build

1. Ejecutar `dotnet build .\Malvex.sln -c Release`.
2. Ejecutar `dotnet test .\Malvex.sln -c Release`.
3. Confirmar que no existan errores de XAML ni referencias rotas.
4. Revisar que `.gitignore` excluya `bin/`, `obj/`, `dist/`, `reports/` y artefactos temporales.

## Testing funcional

1. Abrir un `.exe` benigno y verificar:
   - metadata PE
   - imports / exports
   - strings
   - YARA
   - export JSON / HTML
2. Probar una muestra controlada en VM y validar:
   - puntaje de riesgo
   - hallazgos heurísticos
   - guia del analista
   - exportacion JSON / HTML
3. Verificar que la app siga abriendo en host y VM.

## Distribucion

1. Generar artefactos con `scripts/publish-release.ps1`.
2. Confirmar ZIP, MSI y `SHA256SUMS.txt` dentro de `dist\release`.
3. Validar que el instalador incluya:
   - icono
   - reglas base
   - binarios necesarios
4. Probar instalacion en una maquina limpia.
5. Verificar YARA en una VM con Microsoft Visual C++ Redistributable x64.

## Publicacion

1. Confirmar numero de version.
2. Preparar changelog corto de la release.
3. Si se firma binario, ejecutar `scripts/sign-release.ps1`.
4. Subir solo artefactos finales, no carpetas generadas de desarrollo.
5. Seguir `docs\PUBLICATION_GUIDE.md`.
