# Contribuir a Malvex

Se aceptan contribuciones que mejoren el analisis estatico, la usabilidad, la
documentacion y la cobertura de pruebas.

## Antes de abrir un pull request

1. Crea una rama enfocada en un cambio concreto.
2. Manten el analisis estatico: no agregues ejecucion automatica de muestras.
3. Evita heuristicas que clasifiquen un archivo como malicioso por una sola senal debil.
4. Agrega o actualiza pruebas al modificar el comportamiento del parser.
5. Ejecuta:

```powershell
dotnet test .\Malvex.sln -c Release
```

## Informacion del pull request

Describe:

- el problema;
- la solucion elegida;
- el impacto esperado sobre falsos positivos;
- la validacion realizada;
- capturas para cambios visibles en la GUI.

## Reportes de seguridad

Sigue `SECURITY.md`. No divulgues vulnerabilidades mediante pull requests
publicos antes de coordinar una correccion.
