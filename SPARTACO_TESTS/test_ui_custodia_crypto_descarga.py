# ===============================================================
# SPARTACO-SECURITY — tests/test_ui_custodia_crypto_descarga.py
# ===============================================================
#
# AUDITORÍA ESTRICTA DE CUSTODIA / DESCARGA DE RESULTADOS CRYPTO USER
#
# PROPÓSITO
# ---------
# Garantizar que TODO resultado público de una operación USER que llegue
# como archivo/bytes pueda regresar al dispositivo de la persona.
#
# Cadena:
#
#   capability pública USER
#       -> resultado público
#       -> transporte bytes/archivo
#       -> entrega USER
#       -> nombre identificable
#       -> descarga explícita
#
# Casos centinela:
#   - protección: el artefacto protegido debe poder descargarse
#   - claves de firma: .priv/.pub deben poder descargarse
#   - apertura/descifrado: el contenido recuperado debe poder descargarse
#   - recuperación: el contenido recuperado debe poder descargarse
#   - cualquier OUTPUT_PATH futuro: no puede requerir un if hardcodeado
#
# LÍMITES
# -------
# No abre HTTP. No ejecuta crypto. No resuelve IKM. No genera claves.
# Inspecciona el runtime, las declaraciones USER y el renderer.
# ===============================================================

from __future__ import annotations

import importlib
import inspect
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

import pytest


@dataclass(frozen=True)
class Diagnostico:
    familia: str
    accion_id: str
    estado: str
    origen: str
    falta: str
    correccion: str

    def texto(self) -> str:
        return "\n".join(
            (
                f"- familia: {self.familia}",
                f"  accion: {self.accion_id}",
                f"  estado: {self.estado}",
                f"  origen: {self.origen}",
                f"  falta: {self.falta}",
                f"  correccion: {self.correccion}",
            )
        )


def _d(
    familia: str,
    accion_id: str,
    estado: str,
    origen: str,
    falta: str,
    correccion: str,
) -> Diagnostico:
    return Diagnostico(
        familia=familia,
        accion_id=accion_id,
        estado=estado,
        origen=origen,
        falta=falta,
        correccion=correccion,
    )


def _reporte(
    diagnosticos: Iterable[Diagnostico],
    resumen: Mapping[str, int],
) -> str:
    filas = list(diagnosticos)
    lineas = [
        "",
        "UI_CUSTODIA_CRYPTO_DESCARGA: FAIL",
        "================================",
        "",
        "RESUMEN",
        "-------",
    ]
    lineas.extend(
        f"{clave}: {valor}"
        for clave, valor in sorted(resumen.items())
    )
    lineas.extend(("", "DIAGNOSTICOS", "------------"))
    for fila in filas:
        lineas.extend(("", fila.texto()))
    return "\n".join(lineas)


def _texto(valor: Any) -> bool:
    return isinstance(valor, str) and bool(valor.strip())


def _campos(accion: Any) -> Mapping[str, Any]:
    valor = getattr(accion, "campos", {})
    return valor if isinstance(valor, Mapping) else {}


def _kind(campo: Any) -> str:
    return str(getattr(campo, "kind", "") or "")


def _cargar() -> Tuple[Optional[Any], Optional[Any], Optional[Any], List[Diagnostico]]:
    try:
        ui = importlib.import_module(
            "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI"
        )
    except Exception as exc:
        return None, None, None, [
            _d(
                "RUNTIME",
                "SPARTACO_WEB",
                "UI_NO_IMPORTABLE",
                "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI",
                f"{type(exc).__name__}: {exc}",
                "Corregir el runtime antes de auditar custodia USER.",
            )
        ]

    capa = getattr(ui, "CAPA", None)
    vista = getattr(ui, "VISTA_USER", None)
    fallos: List[Diagnostico] = []

    if capa is None:
        fallos.append(
            _d(
                "RUNTIME",
                "CAPA",
                "CAPA_NO_DISPONIBLE",
                "Spartaco_UI.CAPA",
                "El runtime no expone CAPA.",
                "Restaurar la capa semántica real.",
            )
        )
    if vista is None:
        fallos.append(
            _d(
                "RUNTIME",
                "VISTA_USER",
                "VISTA_NO_DISPONIBLE",
                "Spartaco_UI.VISTA_USER",
                "El runtime no expone VISTA_USER.",
                "Restaurar la vista USER real.",
            )
        )

    return ui, capa, vista, fallos


def _workflows(vista: Any) -> Dict[str, Mapping[str, Any]]:
    bruto = getattr(vista, "USER_WORKFLOWS", {})
    if not isinstance(bruto, Mapping):
        return {}
    return {
        str(wid): wf
        for wid, wf in bruto.items()
        if isinstance(wid, str) and isinstance(wf, Mapping)
    }


def _acciones_user(vista: Any) -> Set[str]:
    ids: Set[str] = set()

    for idioma in ("es", "en"):
        try:
            salida = vista.vista(idioma=idioma)
        except Exception:
            continue
        if not isinstance(salida, Mapping):
            continue

        pila: List[Any] = [salida]
        while pila:
            actual = pila.pop()
            if isinstance(actual, Mapping):
                aid = actual.get("accion_id")
                if isinstance(aid, str) and "." in aid:
                    ids.add(aid)
                pila.extend(actual.values())
            elif isinstance(actual, (list, tuple)):
                pila.extend(actual)

    for wf in _workflows(vista).values():
        if wf.get("interno") is True or wf.get("publicado") is False:
            continue
        for paso in wf.get("pasos") or []:
            if not isinstance(paso, Mapping):
                continue
            aid = paso.get("accion_id")
            if isinstance(aid, str) and "." in aid:
                ids.add(aid)

    return ids


def _funcion_html(html: str, nombre: str) -> str:
    patrones = (
        rf"async\s+function\s+{re.escape(nombre)}\s*\([^)]*\)\s*\{{",
        rf"function\s+{re.escape(nombre)}\s*\([^)]*\)\s*\{{",
    )
    inicio = None
    for patron in patrones:
        m = re.search(patron, html)
        if m:
            inicio = m.start()
            break
    if inicio is None:
        return ""

    siguiente = re.search(
        r"\n(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(",
        html[inicio + 1:],
    )
    if siguiente is None:
        return html[inicio:]
    return html[inicio: inicio + 1 + siguiente.start()]


def _helpers_descarga_generica(html: str) -> Set[str]:
    candidatos: Set[str] = set()
    patron = re.compile(
        r"(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{"
    )
    matches = list(patron.finditer(html))

    for i, match in enumerate(matches):
        nombre = match.group(1)
        ini = match.start()
        fin = matches[i + 1].start() if i + 1 < len(matches) else len(html)
        cuerpo = html[ini:fin]

        iteracion_generica = (
            "Object.entries" in cuerpo
            or "Object.values" in cuerpo
            or "for(const [" in cuerpo
            or "for (const [" in cuerpo
        )
        reconoce_bytes = (
            '"bytes"' in cuerpo
            or "'bytes'" in cuerpo
            or ".b64" in cuerpo
            or "b64" in cuerpo
        )
        entrega = "registrarEntrega" in cuerpo
        nombre_archivo = (
            ".nombre" in cuerpo
            or '["nombre"]' in cuerpo
            or "nombre:" in cuerpo
        )

        if iteracion_generica and reconoce_bytes and entrega and nombre_archivo:
            candidatos.add(nombre)

    return candidatos


def _diagnosticar_normalizacion(ui: Any) -> List[Diagnostico]:
    fallos: List[Diagnostico] = []
    normalizar = getattr(ui, "_normalizar", None)

    if not callable(normalizar):
        return [
            _d(
                "TRANSPORTE",
                "Spartaco_UI._normalizar",
                "NORMALIZADOR_NO_CALLABLE",
                "Spartaco_UI._normalizar",
                "No existe normalizador de resultados.",
                "Restaurar el transporte JSON de bytes del backend al cliente.",
            )
        ]

    try:
        fuente = inspect.getsource(normalizar)
    except Exception as exc:
        return [
            _d(
                "TRANSPORTE",
                "Spartaco_UI._normalizar",
                "NORMALIZADOR_NO_INSPECCIONABLE",
                "inspect.getsource",
                f"{type(exc).__name__}: {exc}",
                "Mantener _normalizar inspeccionable por CI.",
            )
        ]

    if "bytes" not in fuente or "b64" not in fuente or "base64" not in fuente:
        fallos.append(
            _d(
                "TRANSPORTE",
                "bytes",
                "BYTES_PUBLICOS_NO_TRANSPORTABLES",
                "Spartaco_UI._normalizar",
                "El normalizador no demuestra bytes -> b64 transportable.",
                "Conservar todo resultado bytes público como descriptor descargable.",
            )
        )

    return fallos


def _diagnosticar_output_path(capa: Any, html: str) -> Tuple[List[Diagnostico], int]:
    fallos: List[Diagnostico] = []
    total = 0

    acciones_map = getattr(capa, "ACCIONES_MAP", {})
    if not isinstance(acciones_map, Mapping):
        return fallos, total

    for _, accion in acciones_map.items():
        for _, campo in _campos(accion).items():
            if _kind(campo) == "OUTPUT_PATH":
                total += 1

    if total:
        generico = bool(
            re.search(r"Object\.entries\s*\(\s*r\.archivos", html)
            or re.search(r"Object\.entries\s*\(\s*resultado\.archivos", html)
            or re.search(r"for\s*\([^)]*\.archivos", html)
        )
        if not generico:
            fallos.append(
                _d(
                    "CUSTODIA",
                    "OUTPUT_PATH",
                    "OUTPUT_PATH_NO_DESCARGABLE_GENERICO",
                    "Spartaco_UI.HTML",
                    (
                        f"CAPA contiene {total} OUTPUT_PATH, pero el renderer no "
                        "demuestra que recorra genéricamente todos los archivos "
                        "producidos."
                    ),
                    (
                        "Registrar cada entrada de r.archivos como entrega USER; "
                        "no hardcodear solo ruta_priv/ruta_pub."
                    ),
                )
            )

    return fallos, total


def _diagnosticar_resultado_bytes_generico(
    *,
    html: str,
) -> Tuple[List[Diagnostico], Set[str]]:
    fallos: List[Diagnostico] = []
    helpers = _helpers_descarga_generica(html)

    if not helpers:
        fallos.append(
            _d(
                "CUSTODIA",
                "RESULTADO_BYTES",
                "SIN_COLECTOR_DESCARGABLE_GENERICO",
                "Spartaco_UI.HTML",
                (
                    "El renderer no contiene una maquinaria genérica que recorra "
                    "el resultado público y convierta cualquier bytes/b64 de USER "
                    "en una entrega descargable."
                ),
                (
                    "Crear un colector genérico de artefactos públicos. Debe "
                    "registrar bytes normalizados y archivos retornados sin "
                    "depender de nombres como blob/ruta_priv/ruta_pub."
                ),
            )
        )
        return fallos, helpers

    for consumidor in ("runWorkflowStep", "runUserAction"):
        cuerpo = _funcion_html(html, consumidor)
        if not cuerpo:
            fallos.append(
                _d(
                    "CUSTODIA",
                    consumidor,
                    "CONSUMIDOR_RESULTADO_AUSENTE",
                    f"Spartaco_UI.HTML.{consumidor}",
                    f"No existe {consumidor} inspeccionable.",
                    "Restaurar el dispatcher USER correspondiente.",
                )
            )
            continue

        if not any(re.search(rf"\b{re.escape(h)}\s*\(", cuerpo) for h in helpers):
            fallos.append(
                _d(
                    "CUSTODIA",
                    consumidor,
                    "RESULTADO_NO_PASA_POR_COLECTOR_DESCARGA",
                    f"Spartaco_UI.HTML.{consumidor}",
                    (
                        f"{consumidor} recibe resultados públicos pero no los "
                        "pasa por el colector genérico de descargas."
                    ),
                    (
                        "Después de una ejecución exitosa, pasar el resultado "
                        "público por el colector antes de refrescar la vista."
                    ),
                )
            )

    return fallos, helpers


def _diagnosticar_apertura_recuperacion(
    *,
    vista: Any,
    acciones_user: Set[str],
    html: str,
) -> Tuple[List[Diagnostico], int]:
    fallos: List[Diagnostico] = []
    auditadas = 0
    workflows = _workflows(vista)

    centinelas = (
        "CREDENCIAL.abrir_documento",
        "CREDENCIAL.recuperar",
    )

    helper_ok = bool(_helpers_descarga_generica(html))

    for aid in centinelas:
        if aid not in acciones_user:
            continue

        auditadas += 1

        apariciones: List[Tuple[str, Mapping[str, Any]]] = []
        for wid, wf in workflows.items():
            if wf.get("interno") is True or wf.get("publicado") is False:
                continue
            for paso in wf.get("pasos") or []:
                if isinstance(paso, Mapping) and paso.get("accion_id") == aid:
                    apariciones.append((wid, paso))

        for wid, paso in apariciones:
            tc = paso.get("to_context")
            if tc is None:
                fallos.append(
                    _d(
                        "RECUPERACION",
                        aid,
                        "RESULTADO_RECUPERADO_SIN_CONTEXTO",
                        f"vista_user.USER_WORKFLOWS.{wid}.{paso.get('id')}",
                        (
                            "El paso abre/recupera información USER pero no declara "
                            "to_context; el resultado puede desaparecer al refrescar."
                        ),
                        (
                            "Mapear el campo real retornado por backend a un slot USER. "
                            "No inventar el nombre del campo."
                        ),
                    )
                )
                continue

            if not isinstance(tc, Mapping):
                fallos.append(
                    _d(
                        "RECUPERACION",
                        aid,
                        "TO_CONTEXT_RECUPERACION_INVALIDO",
                        f"vista_user.USER_WORKFLOWS.{wid}.{paso.get('id')}",
                        "to_context no es Mapping.",
                        "Declarar result_field y slot con el retorno real del backend.",
                    )
                )
                continue

            if not _texto(tc.get("result_field")):
                fallos.append(
                    _d(
                        "RECUPERACION",
                        aid,
                        "RECUPERADO_SIN_RESULT_FIELD",
                        f"vista_user.USER_WORKFLOWS.{wid}.{paso.get('id')}",
                        "No se declara qué campo real contiene el resultado recuperado.",
                        "Auditar el retorno real y declarar result_field.",
                    )
                )
            if not _texto(tc.get("slot")):
                fallos.append(
                    _d(
                        "RECUPERACION",
                        aid,
                        "RECUPERADO_SIN_SLOT",
                        f"vista_user.USER_WORKFLOWS.{wid}.{paso.get('id')}",
                        "El resultado recuperado no tiene slot USER reutilizable.",
                        "Declarar un slot de contexto para conservarlo en la sesión.",
                    )
                )

        if not helper_ok:
            fallos.append(
                _d(
                    "RECUPERACION",
                    aid,
                    "RECUPERADO_SIN_DESCARGA_GENERICA",
                    "Spartaco_UI.HTML",
                    (
                        "Aunque el backend devuelva el contenido recuperado como "
                        "bytes públicos, el renderer no demuestra una ruta genérica "
                        "bytes -> entrega -> Descargar."
                    ),
                    (
                        "Todo bytes público devuelto por esta operación debe poder "
                        "guardarse en el dispositivo, conservando nombre cuando exista."
                    ),
                )
            )

    return fallos, auditadas


def _diagnosticar_descarga_explicita(html: str) -> List[Diagnostico]:
    fallos: List[Diagnostico] = []

    requisitos = (
        ("registrarEntrega", "registro persistente de sesión"),
        ("renderEntregas", "visualización de entregas"),
        ("descargarEntrega", "acción explícita de descarga"),
        ("saveBlobToDevice", "transferencia al dispositivo"),
    )
    for nombre, que in requisitos:
        if (
            f"function {nombre}" not in html
            and f"async function {nombre}" not in html
        ):
            fallos.append(
                _d(
                    "CUSTODIA",
                    nombre,
                    "MECANISMO_DESCARGA_AUSENTE",
                    f"Spartaco_UI.HTML.{nombre}",
                    f"Falta {que}.",
                    "Restaurar la cadena resultado -> entrega -> descarga.",
                )
            )

    if "Descargar" not in html or "Download" not in html:
        fallos.append(
            _d(
                "BILINGUE",
                "DOWNLOAD",
                "DESCARGA_NO_BILINGUE",
                "Spartaco_UI.HTML",
                "La acción de descarga no está disponible en ES y EN.",
                "Mostrar control explícito Descargar / Download.",
            )
        )

    return fallos


def test_ui_custodia_crypto_descarga_total() -> None:
    diagnosticos: List[Diagnostico] = []
    resumen: Dict[str, int] = {
        "acciones_user": 0,
        "output_paths": 0,
        "helpers_descarga_generica": 0,
        "apertura_recuperacion_user": 0,
    }

    ui, capa, vista, fallos = _cargar()
    diagnosticos.extend(fallos)

    if ui is None or capa is None or vista is None:
        pytest.fail(_reporte(diagnosticos, resumen), pytrace=False)

    html = str(getattr(ui, "HTML", "") or "")
    acciones = _acciones_user(vista)
    resumen["acciones_user"] = len(acciones)

    diagnosticos.extend(_diagnosticar_normalizacion(ui))
    diagnosticos.extend(_diagnosticar_descarga_explicita(html))

    f_out, n_out = _diagnosticar_output_path(capa, html)
    diagnosticos.extend(f_out)
    resumen["output_paths"] = n_out

    f_gen, helpers = _diagnosticar_resultado_bytes_generico(html=html)
    diagnosticos.extend(f_gen)
    resumen["helpers_descarga_generica"] = len(helpers)

    f_rec, n_rec = _diagnosticar_apertura_recuperacion(
        vista=vista,
        acciones_user=acciones,
        html=html,
    )
    diagnosticos.extend(f_rec)
    resumen["apertura_recuperacion_user"] = n_rec

    unicos: List[Diagnostico] = []
    vistos: Set[Tuple[str, str, str, str]] = set()
    for d in diagnosticos:
        clave = (d.familia, d.accion_id, d.estado, d.origen)
        if clave in vistos:
            continue
        vistos.add(clave)
        unicos.append(d)

    if unicos:
        pytest.fail(_reporte(unicos, resumen), pytrace=False)
