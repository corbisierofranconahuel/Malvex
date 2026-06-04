# Integracion inicial con Wazuh

Malvex puede usarse como motor de triage estatico para enriquecer alertas de
Wazuh en endpoints Windows. La integracion recomendada es ejecutar
`Malvex.Cli.exe` localmente sobre el archivo observado y enviar el resultado a
Wazuh como JSON o como linea `key=value`.

## Estado

Esta guia describe la primera etapa de integracion:

- `Malvex.Cli.exe` analiza archivos PE sin ejecutarlos.
- El resultado incluye `verdict`, `confidence`, `risk_score`, YARA, hallazgos y
  resumen del archivo.
- El codigo de salida permite automatizar decisiones basicas.

La integracion completa con Active Response, decoders y reglas Wazuh puede
construirse encima de este contrato.

## Comando base

```powershell
Malvex.Cli.exe analyze "C:\Ruta\muestra.exe" --json --pretty
```

Salida compacta para reglas simples o logs:

```powershell
Malvex.Cli.exe analyze "C:\Ruta\muestra.exe" --wazuh
```

Ejemplo:

```text
malvex verdict=suspicious confidence=0.76 score=53 risk_level=medium is_pe=true sha256=... file="C:\\Ruta\\muestra.exe" yara="none" findings="Indicador de persistencia en registro|..."
```

## Verdicts

- `clean`: no se detectaron senales relevantes.
- `low_risk`: senales debiles o comunes; revisar contexto.
- `suspicious`: requiere revision del analista o correlacion adicional.
- `likely_malicious`: alta correlacion estatica.
- `unknown`: archivo no PE o analisis no concluyente.

Evita tratar el resultado como un booleano absoluto. Para SIEM conviene usar:

```text
verdict + confidence + risk_score + evidencias
```

## Exit codes

- `0`: analizado sin alerta operativa.
- `1`: sospechoso o probablemente malicioso.
- `2`: error tecnico.
- `3`: archivo no PE.
- `64`: argumentos invalidos.

## Flujo recomendado con Wazuh

1. Wazuh FIM detecta archivo nuevo o modificado.
2. Una regla identifica rutas de interes: `Downloads`, `Temp`, `AppData`,
   `Startup`, `ProgramData` o rutas corporativas sensibles.
3. Active Response ejecuta un wrapper local.
4. El wrapper extrae la ruta del evento Wazuh.
5. El wrapper ejecuta `Malvex.Cli.exe analyze <ruta> --wazuh`.
6. El resultado se escribe en log para que Wazuh lo procese con reglas propias.

## Wrapper Active Response incluido

Este repositorio incluye:

```text
docs\wazuh\malvex-wazuh-ar.cmd
docs\wazuh\malvex-wazuh-ar.ps1
docs\wazuh\malvex_decoder.xml
docs\wazuh\malvex_rules.xml
```

En un agente Windows, copia `malvex-wazuh-ar.cmd` y `malvex-wazuh-ar.ps1` en:

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

El wrapper:

- lee el evento Wazuh desde `STDIN`;
- busca una ruta PE en campos comunes de FIM/syscheck;
- valida que el archivo exista;
- ejecuta `Malvex.Cli.exe analyze <archivo> --wazuh`;
- escribe una linea `malvex_ar status=completed ...` en el log de Active Response.

Prueba manual con evento simulado:

```powershell
$event = @{
  parameters = @{
    alert = @{
      syscheck = @{
        path = "C:\Windows\System32\notepad.exe"
      }
    }
  }
} | ConvertTo-Json -Depth 8

$event | powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\docs\wazuh\malvex-wazuh-ar.ps1 -MalvexCliPath ".\dist\Malvex-win-x64-portable\Malvex.Cli.exe" -LogPath ".\reports\wazuh-test.log"
Get-Content .\reports\wazuh-test.log
```

Ejemplo de linea esperada:

```text
malvex_ar status=completed exit_code=0 malvex verdict=low_risk confidence=0.08 score=8 ...
```

En el manager Wazuh, adapta/copiar:

- `docs\wazuh\malvex_decoder.xml` a `/var/ossec/etc/decoders/local_decoder.xml`;
- `docs\wazuh\malvex_rules.xml` a `/var/ossec/etc/rules/local_rules.xml`.

Luego reinicia el manager Wazuh para cargar decoder y reglas.

## Ejemplo conceptual de Active Response

En el manager Wazuh, el comando puede declararse de forma similar a:

```xml
<command>
  <name>malvex-analyze</name>
  <executable>malvex-wazuh-ar.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>malvex-analyze</command>
  <location>local</location>
  <rules_group>syscheck</rules_group>
</active-response>
```

Recomendacion: primero probarlo en laboratorio con rutas controladas antes de
activarlo para todos los endpoints.

## Ejemplo conceptual de regla Wazuh

```xml
<rule id="100500" level="10">
  <match>malvex verdict=suspicious</match>
  <description>Malvex marco un PE como sospechoso</description>
  <group>malvex,malware,windows,</group>
</rule>

<rule id="100501" level="12">
  <match>malvex verdict=likely_malicious</match>
  <description>Malvex marco un PE como probablemente malicioso</description>
  <group>malvex,malware,windows,</group>
</rule>
```

## Seguridad operacional

- Malvex realiza analisis estatico y no ejecuta muestras.
- Ejecuta el analisis en el endpoint o en una VM controlada.
- Limita tamano con `--max-size-mb`.
- Evita analizar repetidamente el mismo SHA256.
- No subas muestras reales a servicios externos sin autorizacion.
- Considera falsos positivos: herramientas de seguridad pueden contener cadenas
  maliciosas como parte de sus reglas o firmas.

## Ejemplo de instalacion local en endpoint

```text
C:\Program Files\Malvex\Malvex.Cli.exe
C:\Program Files\Malvex\rules\
C:\Program Files\Malvex\tools\yara\yara64.exe
```

Prueba manual:

```powershell
& "C:\Program Files\Malvex\Malvex.Cli.exe" analyze "C:\Windows\System32\notepad.exe" --wazuh
```

## Proximo paso tecnico

Crear un wrapper especifico para Active Response que lea el JSON recibido por
Wazuh desde `STDIN`, extraiga la ruta del archivo y ejecute `Malvex.Cli.exe`.
