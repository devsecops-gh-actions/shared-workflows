# bots/exceptions (F-c, W1)

Herramientas para tramitar excepciones de seguridad (`security/exceptions.md`) a partir de un issue.

**Estado: W1.** Incluye la plantilla de issue, el generador de la entrada y los tests. **No** incluye
el workflow (`workflow.yml`, W2), ni el comando `/security-exception`, ni el aviso de caducidad.

## Ficheros

- `templates/issue-exception.yml`: issue form con los campos `id`, `scope`, `control`, `owner`, `reason`,
  `approved_by`, `created`, `expires` y `ticket`. El texto de ayuda de `expires` indica el máximo de 90 días.
- `scripts/build-exception-entry.mjs`: convierte los campos de un issue (JSON) en el bloque YAML que se
  añade a `security/exceptions.yml`. Valida con el parser compartido. Sin red.
- `fixtures/`: `valid.json`, `too-long.json` (91 días) y `expired.json`.
- `scripts/exceptions.test.mjs`: tests del parser compartido y del generador.

El parser y las reglas viven en `security/scripts/lib/exceptions-parse.mjs`. Lo usan
`security/scripts/gen-ignores.mjs` y el generador de este directorio. Cualquier cambio de reglas se hace allí.

## Instalar la plantilla

GitHub solo lee los formularios de `.github/ISSUE_TEMPLATE/` del **repo de plataforma**. Este repo no tiene `.github/`.
Al desplegar en el repo de plataforma:

1. Copiar `templates/issue-exception.yml` a `.github/ISSUE_TEMPLATE/issue-exception.yml`.
2. Crear la etiqueta `security-exception` (la plantilla la aplica al abrir el issue).

## Uso del generador

```bash
# campos.json: los campos del issue (sin "_No response_" o con él; cuenta como vacío)
node bots/exceptions/scripts/build-exception-entry.mjs campos.json --out entrada.yml
```

La salida es un bloque `  - id: ...` que se añade bajo `exceptions:` en `security/exceptions.yml`.
El registro vacío tiene `exceptions: []`: hay que sustituir esa línea por `exceptions:` y el bloque.
El PR resultante necesita aprobación de CODEOWNERS de AppSec (`security/exceptions.md`).

Códigos de salida: `0` entrada generada; `1` campos inválidos (no escribe nada); `2` uso o error interno.

## Tests

```bash
node --test security/scripts/fixtures/gen-ignores.test.mjs
node --test bots/exceptions/scripts/exceptions.test.mjs
```
