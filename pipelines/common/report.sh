# report.sh: helper de reporte de errores para los workflows de pipelines/.
#
# Uso tras cargarlo con source:
#   report_fail CODE "Qué pasó" "Qué hacer" "Ayuda" ["Por qué"]
#
# - Escribe un bloque con las cuatro líneas fijas (Qué pasó, Por qué, Qué hacer,
#   Ayuda) en $GITHUB_STEP_SUMMARY, si está definido.
# - Emite "::error::..." en stdout con el mismo contenido en una línea.
# - No llama a exit: el caller decide, p. ej.  report_fail ... ; exit 1
# - Fuera de GitHub (sin GITHUB_STEP_SUMMARY) funciona igual, sin escribir summary.
# - Pasar solo textos fijos y valores no sensibles. Nunca secretos, rutas internas
#   ni salidas crudas de herramientas.
# - Al cargarse con source no cambia opciones del shell (no hay set -e aquí).

_report_oneline() {
  printf '%s' "$1" | tr '\r\n' '  '
}

report_fail() {
  _rf_code=$(_report_oneline "${1:-VAL-000}")
  _rf_que=$(_report_oneline "${2:-Error no especificado.}")
  _rf_hacer=$(_report_oneline "${3:-Revisa el paso indicado en el log.}")
  _rf_ayuda=$(_report_oneline "${4:-docs/errores.md}")
  _rf_porque=$(_report_oneline "${5:-Ver «Qué pasó».}")

  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '\n### Error %s\n\n' "$_rf_code"
      printf '**Qué pasó**: %s\n\n' "$_rf_que"
      printf '**Por qué**: %s\n\n' "$_rf_porque"
      printf '**Qué hacer**: %s\n\n' "$_rf_hacer"
      printf '**Ayuda**: %s\n' "$_rf_ayuda"
    } >>"$GITHUB_STEP_SUMMARY" 2>/dev/null || true
  fi

  _rf_msg="[$_rf_code] Qué pasó: $_rf_que Por qué: $_rf_porque Qué hacer: $_rf_hacer Ayuda: $_rf_ayuda"
  # En anotaciones de GitHub, % debe escaparse como %25.
  _rf_msg=$(printf '%s' "$_rf_msg" | sed 's/%/%25/g')
  printf '::error::%s\n' "$_rf_msg"

  unset _rf_code _rf_que _rf_hacer _rf_ayuda _rf_porque _rf_msg
}
