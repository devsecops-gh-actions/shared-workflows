#!/usr/bin/env bash
# Test de pipelines/common/report.sh. Uso: bash pipelines/common/test/report.test.sh
set -u

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
. "$ROOT/pipelines/common/report.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0
check() { if [ "$1" = "$2" ]; then echo "ok: $3"; else echo "FAIL: $3 (esperado '$2', obtenido '$1')"; fail=1; fi; }

# 1. Con GITHUB_STEP_SUMMARY: 4 líneas fijas + código.
SUM="$TMP/summary.md"
out=$(GITHUB_STEP_SUMMARY="$SUM" report_fail "VAL-999" "Falta el lockfile." "Genera el lockfile y haz commit." "docs/onboarding.md" "No hay lockfile en el repo.")
for label in "Qué pasó" "Por qué" "Qué hacer" "Ayuda"; do
  grep -q "^\*\*$label\*\*:" "$SUM" && r=yes || r=no
  check "$r" yes "summary contiene **$label**"
done
grep -q "### Error VAL-999" "$SUM" && r=yes || r=no
check "$r" yes "summary contiene el código"
check "$(printf '%s\n' "$out" | grep -c '^::error::')" "1" "stdout emite una sola anotación ::error::"
case "$out" in "::error::[VAL-999] Qué pasó: Falta el lockfile."*) r=yes ;; *) r=no ;; esac
check "$r" yes "anotación con el mismo texto"

# 2. Sin GITHUB_STEP_SUMMARY: sigue funcionando y no crea nada.
out=$(unset GITHUB_STEP_SUMMARY; report_fail "VAL-998" "x" "y" "z" 2>&1; echo "rc=$?")
case "$out" in *"::error::[VAL-998]"*"rc=0") r=yes ;; *) r=no ;; esac
check "$r" yes "fuera de GitHub funciona sin summary"

# 3. Saltos de línea y % se neutralizan en la anotación.
out=$(unset GITHUB_STEP_SUMMARY; report_fail "VAL-997" $'linea1\nlinea2' "100% hecho" "ayuda")
check "$(printf '%s\n' "$out" | grep -c '^::error::')" "1" "saltos de línea no rompen la anotación"
case "$out" in *"100%25 hecho"*) r=yes ;; *) r=no ;; esac
check "$r" yes "% escapado en la anotación"

# 4. source no altera opciones del shell del caller.
case $- in *e*) before=e ;; *) before=- ;; esac
case $- in *e*) after=e ;; *) after=- ;; esac
check "$after" "$before" "source no cambia set -e del caller"

exit $fail
