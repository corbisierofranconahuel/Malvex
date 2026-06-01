# Avisos de terceros

Malvex incluye o utiliza componentes de terceros. Sus licencias siguen vigentes.

## Componentes en tiempo de ejecucion

### Iced 1.21.0

- Proposito: decoder y desensamblador de instrucciones x86/x64.
- Licencia: MIT.
- Proyecto: https://github.com/icedland/iced
- Copia de licencia: `docs/licenses/ICED-MIT.txt`

### YARA 4.5.5

- Proposito: busqueda local de patrones para triage de malware.
- Distribucion: los paquetes portable y MSI incluyen `tools/yara/yara64.exe`.
- Licencia: BSD-3-Clause.
- Proyecto: https://github.com/VirusTotal/yara
- Copia de licencia: `docs/licenses/YARA-BSD-3-Clause.txt`

## Dependencias de build y pruebas

El repositorio tambien usa .NET SDK, WiX Toolset, xUnit, coverlet y Microsoft
.NET test SDK durante el desarrollo, empaquetado o pruebas. Revisa sus
metadatos y licencias antes de redistribuir builds modificados.
