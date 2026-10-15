# ===============================================================
# SPARTACO-SECURITY — tests/test_ui_abrir_documento_descargable.py
# ===============================================================
#
# PROPÓSITO
# ---------
# Auditar una garantía USER muy concreta:
#
#   archivo protegido
#       -> CREDENCIAL.abrir_documento
#       -> contenido recuperado
#       -> Tus entregas
#       -> Descargar / Download
#
# "Comprobar" NO satisface este contrato: verificar/verificar_manifiesto
# solo validan integridad/firma. Para recuperar el contenido debe existir
# una ruta USER explícita a CREDENCIAL.abrir_documento.
#
# Este test NO ejecuta criptografía, NO resuelve IKM, NO abre HTTP y
# NO genera archivos. Inspecciona contratos, workflow y renderer.
# ===============================================================

from __future__ import annotations

import importlib
import inspect
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

import pytest


ACCION_ABRIR = "CREDENCIAL.abrir_documento"


@dataclass(frozen=True)
class Diagnostico:
    estado: str
    origen: str
    falta: str
    correccion: str

    def texto(self) -> str:
        return "\n".join(
            (
                f"- accion: {ACCION_ABRIR}",
                f"  estado: {self.estado}",
                f"  origen: {self.origen}",
                f"  falta: {self.falta}",
                f"  correccion: {self.correccion}",
            )
        )


def _d(estado: str, origen: str, falta: str, correccion: str) -> Diagnostico:
    return Diagnostico(
        estado=estado,
        origen=origen,
        falta=falta,
        correccion=correccion,
    )


def _reporte(
    diagnosticos: Iterable[Diagnostico],
    resumen: Mapping[str, Any],
) -> str:
    lineas = [
        "",
        "UI_ABRIR_DOCUMENTO_DESCARGABLE: FAIL",
        "====================================",
        "",
        "CONTRATO",
        "--------",
        "CREDENCIAL.abrir_documento",
        "  -> contenido recuperado",
        "  -> Tus entregas",
        "  -> Descargar / Download",
        "",
        "RESUMEN",
        "-------",
    ]
    lineas.extend(
        f"{k}: {v}"
        for k, v in sorted(resumen.items())
    )
    lineas.extend(("", "DIAGNOSTICOS", "------------"))
    for diagnostico in diagnosticos:
        lineas.extend(("", diagnostico.texto()))
    return "\n".join(lineas)


def _cargar_runtime() -> Tuple[Optional[Any], Optional[Any], Optional[Any], List[Diagnostico]]:
    try:
        ui = importlib.import_module(
            "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI"
        )
    except Exception as exc:
        return None, None, None, [
            _d(
                "RUNTIME_UI_NO_IMPORTABLE",
                "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI",
                f"{type(exc).__name__}: {exc}",
                "Corregir el runtime antes de auditar la apertura USER.",
            )
        ]

    capa = getattr(ui, "CAPA", None)
    vista = getattr(ui, "VISTA_USER", None)
    fallos: List[Diagnostico] = []

    if capa is None:
        fallos.append(
            _d(
                "RUNTIME_SIN_CAPA",
                "Spartaco_UI.CAPA",
                "El renderer no expone la CAPA que realmente consume.",
                "Restaurar CAPA en Spartaco_UI.",
            )
        )

    if vista is None:
        fallos.append(
            _d(
                "RUNTIME_SIN_VISTA_USER",
                "Spartaco_UI.VISTA_USER",
                "El renderer no expone VISTA_USER.",
                "Restaurar VISTA_USER en Spartaco_UI.",
            )
        )

    return ui, capa, vista, fallos


def _workflow_de_apertura(vista: Any) -> Tuple[Optional[str], Optional[Mapping[str, Any]]]:
    bruto = getattr(vista, "USER_WORKFLOWS", {})
    if not isinstance(bruto, Mapping):
        return None, None

    for workflow_id, workflow in bruto.items():
        if not isinstance(workflow, Mapping):
            continue
        if workflow.get("interno") is True or workflow.get("publicado") is False:
            continue
        for paso in workflow.get("pasos") or []:
            if (
                isinstance(paso, Mapping)
                and paso.get("accion_id") == ACCION_ABRIR
            ):
                return str(workflow_id), paso

    return None, None


def _esta_publicado_en_menu(vista: Any, workflow_id: str) -> bool:
    for idioma in ("es", "en"):
        try:
            menu = vista.menu(idioma=idioma)
        except Exception:
            return False
        if not isinstance(menu, Mapping):
            return False

        encontrado = False
        for seccion in menu.get("secciones") or []:
            if not isinstance(seccion, Mapping):
                continue
            for ref in seccion.get("workflows") or []:
                if isinstance(ref, Mapping) and ref.get("id") == workflow_id:
                    encontrado = True
                    break
            if encontrado:
                break

        if not encontrado:
            return False

    return True


def _callable_real(ui: Any) -> Tuple[Optional[Any], str]:
    resolver = getattr(ui, "_resolver_capacidad", None)
    if not callable(resolver):
        return None, "Spartaco_UI no expone _resolver_capacidad"

    try:
        funcion, error = resolver("CREDENCIAL", "abrir_documento")
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if not callable(funcion):
        return None, str(error or "capability no resuelta")

    return funcion, ""


def _firma_parametros(funcion: Any) -> Set[str]:
    try:
        firma = inspect.signature(funcion)
    except Exception:
        return set()

    return {
        nombre
        for nombre, parametro in firma.parameters.items()
        if nombre != "self"
        and parametro.kind not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    }


def _funcion_js(html: str, nombre: str) -> str:
    patron = re.compile(
        rf"(?:async\s+)?function\s+{re.escape(nombre)}\s*\([^)]*\)\s*\{{"
    )
    inicio = patron.search(html)
    if inicio is None:
        return ""

    siguiente = re.search(
        r"\n(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(",
        html[inicio.end():],
    )
    if siguiente is None:
        return html[inicio.start():]

    return html[
        inicio.start():
        inicio.end() + siguiente.start()
    ]


def _hay_colector_generico_de_archivos(html: str) -> bool:
    """El resultado no puede depender del nombre 'blob'.

    Debe existir una maquinaria que inspeccione genéricamente el resultado
    y registre cualquier descriptor bytes/b64/archivo como entrega.
    """
    patrones_funcion = list(
        re.finditer(
            r"(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{",
            html,
        )
    )

    for indice, match in enumerate(patrones_funcion):
        inicio = match.start()
        fin = (
            patrones_funcion[indice + 1].start()
            if indice + 1 < len(patrones_funcion)
            else len(html)
        )
        cuerpo = html[inicio:fin]

        itera = (
            "Object.entries" in cuerpo
            or "Object.values" in cuerpo
            or re.search(r"for\s*\([^)]*(resultado|result|r)[^)]*\)", cuerpo)
        )
        bytes_publicos = (
            ".b64" in cuerpo
            or '"b64"' in cuerpo
            or "'b64'" in cuerpo
            or '"bytes"' in cuerpo
            or "'bytes'" in cuerpo
        )
        entrega = "registrarEntrega" in cuerpo
        nombre = (
            ".nombre" in cuerpo
            or '"nombre"' in cuerpo
            or "'nombre'" in cuerpo
        )

        if itera and bytes_publicos and entrega and nombre:
            return True

    return False


def _diagnosticar_bilingue(vista: Any, workflow_id: str, paso_id: str) -> List[Diagnostico]:
    fallos: List[Diagnostico] = []

    for campo in ("etiqueta", "descripcion"):
        valores: Dict[str, Any] = {}
        for idioma in ("es", "en"):
            try:
                workflow = vista.workflow(workflow_id, idioma=idioma)
            except Exception as exc:
                fallos.append(
                    _d(
                        "WORKFLOW_NO_RESUELVE_BILINGUE",
                        f"vista_user.workflow.{workflow_id}",
                        f"{idioma}: {type(exc).__name__}: {exc}",
                        "Publicar el flujo de apertura en español e inglés.",
                    )
                )
                return fallos
            if not isinstance(workflow, Mapping):
                continue
            valores[idioma] = workflow.get(campo)

        if not all(
            isinstance(valores.get(idioma), str)
            and valores[idioma].strip()
            for idioma in ("es", "en")
        ):
            fallos.append(
                _d(
                    "WORKFLOW_TEXTO_NO_BILINGUE",
                    f"vista_user.workflow.{workflow_id}.{campo}",
                    f"'{campo}' no existe en ambos idiomas.",
                    "Completar ES/EN.",
                )
            )

    pasos: Dict[str, Mapping[str, Any]] = {}
    for idioma in ("es", "en"):
        workflow = vista.workflow(workflow_id, idioma=idioma)
        encontrados = {
            str(p.get("id")): p
            for p in (workflow.get("pasos") or [])
            if isinstance(p, Mapping) and p.get("id")
        }
        if paso_id in encontrados:
            pasos[idioma] = encontrados[paso_id]

    if set(pasos) != {"es", "en"}:
        fallos.append(
            _d(
                "PASO_APERTURA_NO_BILINGUE",
                f"vista_user.workflow.{workflow_id}.{paso_id}",
                "El paso abrir_documento no existe en ambas proyecciones.",
                "Publicar el mismo paso en ES y EN.",
            )
        )
        return fallos

    for campo in ("etiqueta", "ayuda"):
        if not all(
            isinstance(pasos[i].get(campo), str)
            and pasos[i][campo].strip()
            for i in ("es", "en")
        ):
            fallos.append(
                _d(
                    "PASO_APERTURA_TEXTO_NO_BILINGUE",
                    f"vista_user.workflow.{workflow_id}.{paso_id}.{campo}",
                    f"'{campo}' no está explicado en ES y EN.",
                    "Explicar qué se carga, qué se recupera y qué se descarga en ambos idiomas.",
                )
            )

    return fallos


def test_ui_abrir_documento_entrega_archivo_original() -> None:
    diagnosticos: List[Diagnostico] = []
    resumen: Dict[str, Any] = {
        "capability_publica_resuelta": 0,
        "workflow_user": 0,
        "workflow_publicado_es_en": 0,
        "resultado_mapeado": 0,
        "colector_descarga_generico": 0,
        "descarga_explicita_es_en": 0,
    }

    ui, capa, vista, fallos = _cargar_runtime()
    diagnosticos.extend(fallos)

    if ui is None or capa is None or vista is None:
        pytest.fail(_reporte(diagnosticos, resumen), pytrace=False)

    # -----------------------------------------------------------
    # 1. La capability real debe existir y ser pública/resoluble.
    # -----------------------------------------------------------
    funcion, error = _callable_real(ui)
    if funcion is None:
        diagnosticos.append(
            _d(
                "ABRIR_DOCUMENTO_NO_RESUELVE",
                "Spartaco_UI._resolver_capacidad",
                error,
                "Restaurar CREDENCIAL.abrir_documento como capability pública USER.",
            )
        )
    else:
        resumen["capability_publica_resuelta"] = 1

    # -----------------------------------------------------------
    # 2. Debe existir un flujo USER explícito para ABRIR.
    #    Verificar/comprobar NO cuenta como descifrar.
    # -----------------------------------------------------------
    workflow_id, paso = _workflow_de_apertura(vista)
    if workflow_id is None or paso is None:
        diagnosticos.append(
            _d(
                "ABRIR_DOCUMENTO_SIN_WORKFLOW_USER",
                "vista_user.USER_WORKFLOWS",
                (
                    "CREDENCIAL.abrir_documento no aparece como paso de ningún "
                    "workflow USER publicado."
                ),
                (
                    "Crear/publicar un flujo humano 'Abrir el documento cifrado' "
                    "que use CREDENCIAL.abrir_documento."
                ),
            )
        )
        pytest.fail(_reporte(diagnosticos, resumen), pytrace=False)

    resumen["workflow_user"] = 1
    paso_id = str(paso.get("id") or "<sin-id>")

    # -----------------------------------------------------------
    # 3. El workflow debe estar alcanzable en ES y EN.
    # -----------------------------------------------------------
    if not _esta_publicado_en_menu(vista, workflow_id):
        diagnosticos.append(
            _d(
                "WORKFLOW_APERTURA_NO_PUBLICADO",
                "vista_user.menu",
                (
                    f"El workflow {workflow_id!r} contiene abrir_documento pero "
                    "no está publicado en el menú USER en ambos idiomas."
                ),
                "Publicarlo en una sección USER accesible en ES y EN.",
            )
        )
    else:
        resumen["workflow_publicado_es_en"] = 1

    diagnosticos.extend(
        _diagnosticar_bilingue(vista, workflow_id, paso_id)
    )

    # -----------------------------------------------------------
    # 4. Los inputs del paso deben coincidir con la firma real.
    # -----------------------------------------------------------
    if funcion is not None:
        reales = _firma_parametros(funcion)
        inputs = paso.get("inputs")
        if not isinstance(inputs, Mapping):
            diagnosticos.append(
                _d(
                    "PASO_APERTURA_SIN_INPUTS",
                    f"vista_user.USER_WORKFLOWS.{workflow_id}.{paso_id}",
                    "El paso no declara inputs.",
                    "Declarar únicamente los inputs reales de abrir_documento.",
                )
            )
        else:
            inventados = sorted(set(inputs) - reales)
            if inventados:
                diagnosticos.append(
                    _d(
                        "PASO_APERTURA_PARAMETRO_INVENTADO",
                        f"vista_user.USER_WORKFLOWS.{workflow_id}.{paso_id}",
                        f"Inputs inexistentes en firma real: {inventados}",
                        "Corregir vista_user; no modificar backend para satisfacer UI.",
                    )
                )

    # -----------------------------------------------------------
    # 5. Debe mapear el resultado recuperado a contexto USER.
    #    No inventamos que se llame plaintext/datos/blob.
    # -----------------------------------------------------------
    to_context = paso.get("to_context")
    if not isinstance(to_context, Mapping):
        diagnosticos.append(
            _d(
                "ABRIR_DOCUMENTO_SIN_RESULTADO_USER",
                f"vista_user.USER_WORKFLOWS.{workflow_id}.{paso_id}.to_context",
                (
                    "El paso no declara qué campo real retornado contiene el "
                    "contenido recuperado."
                ),
                (
                    "Declarar to_context.result_field y to_context.slot usando "
                    "el retorno real de CREDENCIAL.abrir_documento."
                ),
            )
        )
    else:
        result_field = to_context.get("result_field")
        slot = to_context.get("slot")
        if not (
            isinstance(result_field, str) and result_field.strip()
            and isinstance(slot, str) and slot.strip()
        ):
            diagnosticos.append(
                _d(
                    "ABRIR_DOCUMENTO_RESULTADO_INCOMPLETO",
                    f"vista_user.USER_WORKFLOWS.{workflow_id}.{paso_id}.to_context",
                    (
                        "to_context necesita result_field real + slot USER para "
                        "que el archivo recuperado no desaparezca al refrescar."
                    ),
                    "Completar ambos valores.",
                )
            )
        else:
            resumen["resultado_mapeado"] = 1

    # -----------------------------------------------------------
    # 6. El transporte debe conservar bytes públicos como b64.
    # -----------------------------------------------------------
    normalizar = getattr(ui, "_normalizar", None)
    if not callable(normalizar):
        diagnosticos.append(
            _d(
                "RESULTADO_BYTES_NO_TRANSPORTABLE",
                "Spartaco_UI._normalizar",
                "No existe _normalizar callable.",
                "Conservar bytes públicos para enviarlos al navegador.",
            )
        )
    else:
        try:
            fuente_normalizar = inspect.getsource(normalizar)
        except Exception:
            fuente_normalizar = ""
        if not all(x in fuente_normalizar for x in ("bytes", "b64", "base64")):
            diagnosticos.append(
                _d(
                    "RESULTADO_BYTES_NO_TRANSPORTABLE",
                    "Spartaco_UI._normalizar",
                    "No demuestra bytes -> b64.",
                    "Normalizar todo bytes público sin descartarlo.",
                )
            )

    # -----------------------------------------------------------
    # 7. ÉSTA ES LA GARANTÍA PRINCIPAL:
    #    cualquier bytes público recuperado debe acabar en Tus entregas.
    #    No aceptamos if(r.blob) como solución específica.
    # -----------------------------------------------------------
    html = str(getattr(ui, "HTML", "") or "")
    colector = _hay_colector_generico_de_archivos(html)

    if not colector:
        diagnosticos.append(
            _d(
                "ARCHIVO_DESCIFRADO_NO_ENTREGABLE",
                "Spartaco_UI.HTML",
                (
                    "No existe un colector genérico que convierta cualquier "
                    "resultado bytes/b64 público de abrir_documento en una "
                    "entrada de 'Tus entregas'. Un resultado llamado distinto "
                    "de blob/ruta_priv/ruta_pub podría quedar solo en JSON."
                ),
                (
                    "Crear un colector genérico resultado -> descriptor de archivo "
                    "-> registrarEntrega(). Debe conservar el nombre original "
                    "cuando el backend lo entregue."
                ),
            )
        )
    else:
        resumen["colector_descarga_generico"] = 1

    # Tanto workflow como acción directa deben consumir el colector.
    for consumidor in ("runWorkflowStep", "runUserAction"):
        cuerpo = _funcion_js(html, consumidor)
        if not cuerpo:
            diagnosticos.append(
                _d(
                    "DISPATCHER_USER_SIN_ENTREGA",
                    f"Spartaco_UI.HTML.{consumidor}",
                    f"No existe {consumidor} inspeccionable.",
                    "Restaurar el dispatcher USER.",
                )
            )
            continue

        if colector and "registrarEntrega" not in cuerpo:
            # El dispatcher puede llamar un helper; aceptamos nombres de helper
            # que contengan artefact/entrega/resultado/descarga y estén presentes.
            llama_helper = bool(
                re.search(
                    r"\b[A-Za-z_$][A-Za-z0-9_$]*(?:artefact|entrega|resultado|descarg)[A-Za-z0-9_$]*\s*\(",
                    cuerpo,
                    flags=re.I,
                )
            )
            if not llama_helper:
                diagnosticos.append(
                    _d(
                        "DISPATCHER_NO_COLECTA_RESULTADO",
                        f"Spartaco_UI.HTML.{consumidor}",
                        (
                            f"{consumidor} recibe el resultado pero no demuestra "
                            "que lo envíe al colector genérico de entregas."
                        ),
                        "Colectar todo resultado exitoso antes de refrescar la vista.",
                    )
                )

    # -----------------------------------------------------------
    # 8. El usuario debe poder pulsar Descargar / Download.
    # -----------------------------------------------------------
    if (
        "Tus entregas" not in html
        or "Your receipts" not in html
        or "Descargar" not in html
        or "Download" not in html
        or "descargarEntrega" not in html
        or "saveBlobToDevice" not in html
    ):
        diagnosticos.append(
            _d(
                "DESCARGA_EXPLICITA_NO_DISPONIBLE",
                "Spartaco_UI.HTML",
                (
                    "La cadena visual Tus entregas -> Descargar / "
                    "Your receipts -> Download no está completa."
                ),
                "Mantener control explícito de descarga en ambos idiomas.",
            )
        )
    else:
        resumen["descarga_explicita_es_en"] = 1

    # -----------------------------------------------------------
    # 9. Verificación no puede presentarse como apertura.
    # -----------------------------------------------------------
    classic = _funcion_js(html, "verifyProtected")
    if classic and (
        "descifr" in classic.lower()
        or "decrypt" in classic.lower()
        or "abrir_documento" in classic
    ):
        diagnosticos.append(
            _d(
                "VERIFICAR_CONFUNDIDO_CON_DESCIFRAR",
                "Spartaco_UI.HTML.verifyProtected",
                (
                    "El flujo de comprobación contiene semántica de apertura/"
                    "descifrado. Verificar no debe prometer recuperar el archivo."
                ),
                (
                    "Mantener verificar como comprobación y abrir_documento como "
                    "ruta separada de recuperación del contenido."
                ),
            )
        )

    if diagnosticos:
        pytest.fail(_reporte(diagnosticos, resumen), pytrace=False)
