# Guia de publicacion en GitHub

## 1. Crear el repositorio

Crea un repositorio publico llamado `Malvex` en tu cuenta de GitHub. No agregues
un README, una licencia o un `.gitignore` automaticamente: este proyecto ya los
incluye.

## 2. Revisar el arbol de archivos

Antes del primer push, confirma que las carpetas generadas no esten preparadas:

```powershell
git status --short
git check-ignore -v dist reports bin obj TestResults
```

No publiques muestras de malware, reportes locales, certificados ni contrasenas.

## 3. Preparar y subir

Reemplaza `<TU_USUARIO_GITHUB>` por tu usuario de GitHub:

```powershell
git branch -M main
git add .
git commit -m "Initial open source release"
git remote add origin https://github.com/<TU_USUARIO_GITHUB>/Malvex.git
git push -u origin main
```

## 4. Generar artefactos de release

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-release.ps1
```

Sube estos archivos desde `dist\release\` a una GitHub Release con tag `v1.1.0`:

- `Malvex-win-x64-portable.zip`
- `Malvex-Setup-x64.msi`
- `SHA256SUMS.txt`

## 5. Configuracion recomendada

- Activa el reporte privado de vulnerabilidades.
- Activa Issues y Discussions si quieres recibir comentarios de la comunidad.
- Protege la rama `main` y exige CI antes de integrar cambios.
- Nunca subas un certificado de firma `.pfx` a GitHub.

## 6. Confianza y transparencia

Publica los hashes SHA256 con cada release. Cuando tengas un certificado de
firma confiable, firma el EXE y el MSI antes de calcular los hashes finales.
