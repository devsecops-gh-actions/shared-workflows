#!/usr/bin/env bash
# Sustituye el placeholder de SHA de la referencia a report-action por el SHA real.
#
# Uso:
#   pin-report-action.sh --sha <40-hex> [--root <dir>] [--apply]
#
# Por defecto es dry-run: lista los ficheros y líneas que cambiaría, sin escribir.
# Con --apply escribe los cambios. Requiere un SHA completo de 40 caracteres hex.
# Solo toca la referencia exacta a pipelines/common/report-action; no toca otras líneas.
set -euo pipefail

PLACEHOLDER='<sha-completo>'
REF_PATH='pipelines/common/report-action@'
SHA=""
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APPLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --sha)   SHA="${2:-}"; shift 2 ;;
    --root)  ROOT="${2:-}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help)
      sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "[error] argumento desconocido: $1" >&2; exit 2 ;;
  esac
done

if ! printf '%s' "$SHA" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "[error] --sha debe ser un SHA completo de 40 caracteres hex (ls-remote)." >&2
  exit 2
fi

if [ ! -d "$ROOT/pipelines" ]; then
  echo "[error] no encuentro pipelines/ en $ROOT" >&2
  exit 2
fi

# Solo ficheros de workflows que referencian report-action con el placeholder.
mapfile -t FILES < <(grep -rl --include='*.yml' --include='*.yaml' -F "${REF_PATH}${PLACEHOLDER}" "$ROOT/pipelines" 2>/dev/null || true)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "# No hay referencias con '${REF_PATH}${PLACEHOLDER}'. Nada que cambiar."
  exit 0
fi

total=0
for f in "${FILES[@]}"; do
  n=$(grep -c -F "${REF_PATH}${PLACEHOLDER}" "$f" || true)
  total=$((total + n))
  if [ "$APPLY" -eq 1 ]; then
    tmp="$(mktemp)"
    sed "s|${REF_PATH}${PLACEHOLDER}|${REF_PATH}${SHA}|g" "$f" > "$tmp"
    cat "$tmp" > "$f"
    rm -f "$tmp"
    echo "[apply] $f ($n)"
  else
    echo "[dry-run] $f ($n)"
  fi
done

if [ "$APPLY" -eq 1 ]; then
  echo "# Sustituidas $total referencias por ${SHA}."
else
  echo "# Dry-run: $total referencias. Use --apply para escribir."
fi
