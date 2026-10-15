# ===============================================================
# SPARTACO-SECURITY — tests/test_ui_experiencia_operativa.py
# ===============================================================
# Auditoría determinista de experiencia operativa USER.
# No abre HTTP, no abre navegador, no genera claves, no cifra,
# no resuelve IKM y no ejecuta workflows sensibles.
# ===============================================================

from __future__ import annotations

import ast
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
        return "\n".join((
            f"- familia: {self.familia}",
            f"  accion: {self.accion_id}",
            f"  estado: {self.estado}",
            f"  origen: {self.origen}",
            f"  falta: {self.falta}",
            f"  correccion: {self.correccion}",
        ))


@dataclass(frozen=True)
class Runtime:
    ui: Optional[Any]
    capa: Optional[Any]
    vista: Optional[Any]


REUTILIZABLES_ARCHIVO = frozenset({
    "PRIVATE_KEY", "PUBLIC_KEY", "MANIFEST", "FILE",
    "CONTENT", "FOLDER", "DIRECTORY",
})

KIND_REFERENCIA = "KEY_REF"

# TRANSITORIO: eliminar cuando CAPA declare formalmente outputs USER.
SALIDAS_USER_CONOCIDAS = frozenset({
    "ruta_priv", "ruta_pub", "blob", "manifiesto", "ref_id",
    "prueba", "estado", "paquete", "archivo_protegido",
    "manifiesto_nombre", "solicitud", "credencial",
})

SOURCES = (
    "USER", "CONTEXT", "PREVIOUS_RESULT", "CONNECTION",
    "FIXED", "SIGNATURE_DEFAULT",
)

CALLS_PROHIBIDAS_UI = frozenset({
    "resolver_clave", "reiniciar_plano", "registrar_puerto",
    "registrar_capacidad", "declarar_compatibilidad",
    "declarar_obligacion", "sellar_plano",
})


def _d(familia: str, accion_id: str, estado: str, origen: str,
       falta: str, correccion: str) -> Diagnostico:
    return Diagnostico(familia, accion_id, estado, origen, falta, correccion)


def _texto_no_vacio(valor: Any) -> bool:
    return isinstance(valor, str) and bool(valor.strip())


def _accion_id_valido(valor: Any) -> bool:
    if not isinstance(valor, str):
        return False
    recurso, punto, capacidad = valor.partition(".")
    return bool(recurso and punto and capacidad and "." not in capacidad)


def _origen_paso(workflow_id: str, paso: Mapping[str, Any]) -> str:
    return f"vista_user.USER_WORKFLOWS.{workflow_id}.{paso.get('id', '<sin-id>')}"


def _campos_de_accion(accion: Any) -> Mapping[str, Any]:
    campos = getattr(accion, "campos", {})
    return campos if isinstance(campos, Mapping) else {}


def _kind(campo: Any) -> str:
    return str(getattr(campo, "kind", "") or "")


def _source_de(spec: Mapping[str, Any]) -> str:
    return str(spec.get("source") or "")


def _slot_de(spec: Mapping[str, Any]) -> str:
    return str(spec.get("slot") or "")


def _terminal_de(spec: Mapping[str, Any]) -> str:
    return str(spec.get("terminal") or "")


def _es_interno(workflow: Mapping[str, Any]) -> bool:
    return bool(workflow.get("interno", False) or workflow.get("publicado") is False)


def _reporte(diagnosticos: Iterable[Diagnostico], resumen: Mapping[str, int]) -> str:
    filas = list(diagnosticos)
    lineas = ["", "UI_EXPERIENCIA_OPERATIVA: FAIL", "==============================",
              "", "RESUMEN", "-------"]
    for clave, valor in sorted(resumen.items()):
        lineas.append(f"{clave}: {valor}")
    lineas.extend(("", "DIAGNOSTICOS", "------------"))
    for fila in filas:
        lineas.extend(("", fila.texto()))
    return "\n".join(lineas)


def _workflows(vista: Any) -> Tuple[Dict[str, Dict[str, Any]], List[Diagnostico]]:
    bruto = getattr(vista, "USER_WORKFLOWS", None)
    if not isinstance(bruto, Mapping):
        return {}, [_d("RUNTIME", "USER_WORKFLOWS", "WORKFLOWS_NO_UTILIZABLES",
                       "vista_user.USER_WORKFLOWS",
                       "USER_WORKFLOWS no existe o no es Mapping.",
                       "Declarar los workflows USER como Mapping.")]
    salida: Dict[str, Dict[str, Any]] = {}
    fallos: List[Diagnostico] = []
    for workflow_id, workflow in bruto.items():
        if not _texto_no_vacio(workflow_id):
            fallos.append(_d("RUNTIME", str(workflow_id), "WORKFLOW_ID_INVALIDO",
                              "vista_user.USER_WORKFLOWS",
                              "El workflow_id no es un str no vacío.",
                              "Usar un workflow_id contractual válido."))
            continue
        if not isinstance(workflow, Mapping):
            fallos.append(_d("RUNTIME", f"WORKFLOW.{workflow_id}",
                              "WORKFLOW_DECLARACION_INVALIDA",
                              f"vista_user.USER_WORKFLOWS.{workflow_id}",
                              "La declaración del workflow no es Mapping.",
                              "Declarar cada workflow como Mapping."))
            continue
        salida[str(workflow_id)] = dict(workflow)
    return salida, fallos


def _cargar_runtime() -> Tuple[Runtime, List[Diagnostico]]:
    fallos: List[Diagnostico] = []
    try:
        ui = importlib.import_module("modules.interfaz.paquetes.spartaco_ui.Spartaco_UI")
    except Exception as exc:
        return Runtime(None, None, None), [_d(
            "RUNTIME", "SPARTACO_WEB", "RUNTIME_UI_NO_IMPORTABLE",
            "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI",
            f"{type(exc).__name__}: {exc}",
            "Corregir los imports o el empaquetado de Spartaco_UI.")]
    capa = getattr(ui, "CAPA", None)
    vista = getattr(ui, "VISTA_USER", None)
    if capa is None:
        fallos.append(_d("RUNTIME", "SPARTACO_UI.CAPA", "RUNTIME_SIN_CAPA",
                          "Spartaco_UI.CAPA", "El runtime no expone la capa semántica real.",
                          "Restaurar el enlace CAPA en Spartaco_UI."))
    if vista is None:
        fallos.append(_d("RUNTIME", "SPARTACO_UI.VISTA_USER", "RUNTIME_SIN_VISTA",
                          "Spartaco_UI.VISTA_USER", "El runtime no expone la vista USER real.",
                          "Restaurar el enlace VISTA_USER en Spartaco_UI."))
    return Runtime(ui, capa, vista), fallos


def _diagnosticar_bilingue(*, capa: Any, vista: Any,
                           workflows: Mapping[str, Mapping[str, Any]]) -> Tuple[List[Diagnostico], Dict[str, int]]:
    fallos: List[Diagnostico] = []
    cont = {"bilingue_secciones": 0, "bilingue_workflows": 0,
            "bilingue_pasos": 0, "bilingue_acciones": 0,
            "bilingue_campos": 0}
    try:
        menu_es = vista.menu(idioma="es")
        menu_en = vista.menu(idioma="en")
    except Exception as exc:
        return [_d("BILINGUE", "VISTA_USER.menu", "MENU_BILINGUE_NO_RESUELVE",
                   "vista_user.menu", f"{type(exc).__name__}: {exc}",
                   "Hacer que menu(idioma='es'|'en') resuelva ambas vistas.")], cont
    if not isinstance(menu_es, Mapping) or not isinstance(menu_en, Mapping):
        return [_d("BILINGUE", "VISTA_USER.menu", "MENU_BILINGUE_INVALIDO",
                   "vista_user.menu", "menu() no devolvió Mapping en ambos idiomas.",
                   "Restaurar la proyección bilingüe del menú USER.")], cont
    sec_es = {str(s.get("id")): s for s in (menu_es.get("secciones") or [])
              if isinstance(s, Mapping) and s.get("id")}
    sec_en = {str(s.get("id")): s for s in (menu_en.get("secciones") or [])
              if isinstance(s, Mapping) and s.get("id")}
    for sid in sorted(set(sec_es) | set(sec_en)):
        es, en = sec_es.get(sid), sec_en.get(sid)
        if es is None or en is None:
            fallos.append(_d("BILINGUE", f"SECCION.{sid}", "SECCION_FALTA_EN_IDIOMA",
                              "vista_user.menu", "La sección no existe en ambos idiomas.",
                              "Publicar la misma sección en español e inglés."))
            continue
        for campo in ("titulo", "texto"):
            if not _texto_no_vacio(es.get(campo)) or not _texto_no_vacio(en.get(campo)):
                fallos.append(_d("BILINGUE", f"SECCION.{sid}", "SECCION_TEXTO_NO_BILINGUE",
                                  f"vista_user.menu.{sid}.{campo}",
                                  f"'{campo}' debe existir y no estar vacío en es/en.",
                                  "Completar la redacción en español e inglés."))
            else:
                cont["bilingue_secciones"] += 1
    for wid, raw in sorted(workflows.items()):
        if _es_interno(raw):
            continue
        try:
            wf_es = vista.workflow(wid, idioma="es")
            wf_en = vista.workflow(wid, idioma="en")
        except Exception as exc:
            fallos.append(_d("BILINGUE", f"WORKFLOW.{wid}", "WORKFLOW_BILINGUE_NO_RESUELVE",
                              f"vista_user.workflow.{wid}", f"{type(exc).__name__}: {exc}",
                              "Hacer que el workflow resuelva en español e inglés."))
            continue
        if not isinstance(wf_es, Mapping) or not isinstance(wf_en, Mapping):
            fallos.append(_d("BILINGUE", f"WORKFLOW.{wid}", "WORKFLOW_BILINGUE_INVALIDO",
                              f"vista_user.workflow.{wid}",
                              "La proyección del workflow no es Mapping en ambos idiomas.",
                              "Restaurar la proyección bilingüe."))
            continue
        for campo in ("etiqueta", "descripcion"):
            if not _texto_no_vacio(wf_es.get(campo)) or not _texto_no_vacio(wf_en.get(campo)):
                fallos.append(_d("BILINGUE", f"WORKFLOW.{wid}", "WORKFLOW_TEXTO_NO_BILINGUE",
                                  f"vista_user.workflow.{wid}.{campo}",
                                  f"'{campo}' debe existir y no estar vacío en es/en.",
                                  "Completar la redacción del workflow en español e inglés."))
            else:
                cont["bilingue_workflows"] += 1
        pasos_es = {str(p.get("id")): p for p in (wf_es.get("pasos") or [])
                    if isinstance(p, Mapping) and p.get("id")}
        pasos_en = {str(p.get("id")): p for p in (wf_en.get("pasos") or [])
                    if isinstance(p, Mapping) and p.get("id")}
        for pid in sorted(set(pasos_es) | set(pasos_en)):
            pe, pn = pasos_es.get(pid), pasos_en.get(pid)
            if pe is None or pn is None:
                fallos.append(_d("BILINGUE", f"{wid}.{pid}", "PASO_FALTA_EN_IDIOMA",
                                  f"vista_user.workflow.{wid}",
                                  "El paso no existe en ambos idiomas.",
                                  "Publicar el mismo paso en español e inglés."))
                continue
            aid = str(pe.get("accion_id") or f"{wid}.{pid}")
            if not _texto_no_vacio(pe.get("etiqueta")) or not _texto_no_vacio(pn.get("etiqueta")):
                fallos.append(_d("BILINGUE", aid, "PASO_ETIQUETA_NO_BILINGUE",
                                  f"vista_user.workflow.{wid}.{pid}.etiqueta",
                                  "La etiqueta del paso no existe en ambos idiomas.",
                                  "Completar etiqueta ES/EN."))
            else:
                cont["bilingue_pasos"] += 1
            ayuda_es, ayuda_en = pe.get("ayuda") or pe.get("truth"), pn.get("ayuda") or pn.get("truth")
            if not _texto_no_vacio(ayuda_es) or not _texto_no_vacio(ayuda_en):
                fallos.append(_d("BILINGUE", aid, "PASO_AYUDA_NO_BILINGUE",
                                  f"vista_user.workflow.{wid}.{pid}",
                                  "El paso USER no explica su función en ambos idiomas.",
                                  "Añadir ayuda breve ES/EN desde la capa/vista explicativa."))
            in_es = pe.get("inputs") if isinstance(pe.get("inputs"), Mapping) else {}
            in_en = pn.get("inputs") if isinstance(pn.get("inputs"), Mapping) else {}
            for nombre in sorted(set(in_es) | set(in_en)):
                se, sn = in_es.get(nombre), in_en.get(nombre)
                if not isinstance(se, Mapping) or not isinstance(sn, Mapping):
                    continue
                src = str(se.get("source") or "")
                if src in {"FIXED", "SIGNATURE_DEFAULT"}:
                    continue
                if not _texto_no_vacio(se.get("etiqueta")) or not _texto_no_vacio(sn.get("etiqueta")):
                    fallos.append(_d("BILINGUE", aid, "CAMPO_ETIQUETA_NO_BILINGUE",
                                      f"vista_user.workflow.{wid}.{pid}.inputs.{nombre}",
                                      f"El campo '{nombre}' no tiene etiqueta USER ES/EN.",
                                      "Declarar etiqueta bilingüe en metadata; no depender del nombre técnico."))
                else:
                    cont["bilingue_campos"] += 1
                if not _texto_no_vacio(se.get("ayuda")) or not _texto_no_vacio(sn.get("ayuda")):
                    fallos.append(_d("BILINGUE", aid, "CAMPO_AYUDA_NO_BILINGUE",
                                      f"vista_user.workflow.{wid}.{pid}.inputs.{nombre}",
                                      f"El campo '{nombre}' no explica en ES/EN qué aportar o reutilizar.",
                                      "Declarar ayuda bilingüe para el campo."))
    acciones_ids: Set[str] = set()
    for sec in sec_es.values():
        for a in sec.get("acciones") or []:
            if isinstance(a, Mapping) and _accion_id_valido(a.get("accion_id")):
                acciones_ids.add(str(a.get("accion_id")))
    accion_de = getattr(capa, "accion_de", None)
    if callable(accion_de):
        for aid in sorted(acciones_ids):
            recurso, _, capacidad = aid.partition(".")
            try:
                aes = accion_de(recurso=recurso, capacidad=capacidad, idioma="es")
                aen = accion_de(recurso=recurso, capacidad=capacidad, idioma="en")
            except Exception as exc:
                fallos.append(_d("BILINGUE", aid, "ACCION_BILINGUE_NO_RESUELVE",
                                  "capa_universal.accion_de", f"{type(exc).__name__}: {exc}",
                                  "Hacer que accion_de resuelva ES/EN."))
                continue
            if not isinstance(aes, Mapping) or not isinstance(aen, Mapping):
                continue
            for campo in ("etiqueta", "truth"):
                if not _texto_no_vacio(aes.get(campo)) or not _texto_no_vacio(aen.get(campo)):
                    fallos.append(_d("BILINGUE", aid, "ACCION_TEXTO_NO_BILINGUE",
                                      f"capa_universal.accion_de.{aid}.{campo}",
                                      f"'{campo}' debe existir en español e inglés.",
                                      "Completar la metadata bilingüe de la acción."))
                else:
                    cont["bilingue_acciones"] += 1
    return fallos, cont


def _diagnosticar_inputs_y_contexto(*, workflows: Mapping[str, Mapping[str, Any]],
                                     capa: Any, vista: Any, html: str) -> Tuple[List[Diagnostico], Dict[str, int]]:
    fallos: List[Diagnostico] = []
    cont = {"inputs_auditados": 0, "reutilizables": 0, "connection_inputs": 0}
    acciones_map = getattr(capa, "ACCIONES_MAP", {})
    if not isinstance(acciones_map, Mapping):
        return [_d("INPUTS", "CAPA.ACCIONES_MAP", "CATALOGO_NO_UTILIZABLE",
                   "capa_universal.ACCIONES_MAP", "ACCIONES_MAP no es Mapping.",
                   "Restaurar ACCIONES_MAP.")], cont
    sources_validos = {str(getattr(vista, nombre, nombre)) for nombre in SOURCES}
    src_user = str(getattr(vista, "USER", "USER"))
    src_context = str(getattr(vista, "CONTEXT", "CONTEXT"))
    src_prev = str(getattr(vista, "PREVIOUS_RESULT", "PREVIOUS_RESULT"))
    src_connection = str(getattr(vista, "CONNECTION", "CONNECTION"))
    contexto_corta = bool(re.search(
        r'if\s*\(\s*src\s*===\s*"CONTEXT".*?if\s*\(\s*ok\s*\)\s*continue\s*;',
        html, flags=re.S))
    tiene_reemplazo_generico = bool(re.search(
        r"(reemplaz|replace|choose.?another|elegir.?otr|override)", html, flags=re.I))
    for wid, workflow in sorted(workflows.items()):
        if _es_interno(workflow):
            continue
        pasos = workflow.get("pasos")
        if not isinstance(pasos, list):
            continue
        for paso in pasos:
            if not isinstance(paso, Mapping) or paso.get("paso_interno") is True:
                continue
            accion_id = str(paso.get("accion_id") or "")
            accion = acciones_map.get(accion_id)
            if accion is None:
                continue
            campos = _campos_de_accion(accion)
            inputs = paso.get("inputs")
            if not isinstance(inputs, Mapping):
                continue
            for nombre, spec in inputs.items():
                if not isinstance(nombre, str) or not isinstance(spec, Mapping):
                    continue
                cont["inputs_auditados"] += 1
                source = _source_de(spec)
                if source not in sources_validos:
                    fallos.append(_d("INPUTS", accion_id, "SOURCE_NO_SOPORTADO",
                                      f"{_origen_paso(wid, paso)}.inputs.{nombre}",
                                      f"source={source!r} no pertenece al contrato USER.",
                                      "Usar una fuente declarada por vista_user."))
                    continue
                campo = campos.get(nombre)
                if source in {src_user, src_context, src_prev} and campo is None:
                    fallos.append(_d("INPUTS", accion_id, "INPUT_SIN_METADATA",
                                      f"{_origen_paso(wid, paso)}.inputs.{nombre}",
                                      f"'{nombre}' necesita interacción/reutilización pero CAPA no declara Campo.",
                                      "Declarar kind/wire y ayuda del campo en CAPA."))
                    continue
                kind = _kind(campo)
                if kind in REUTILIZABLES_ARCHIVO:
                    cont["reutilizables"] += 1
                    if source in {src_context, src_prev} and contexto_corta and not tiene_reemplazo_generico:
                        fallos.append(_d("REUSE", accion_id,
                                          "CONTEXTO_REUTILIZABLE_SIN_REEMPLAZO",
                                          f"{_origen_paso(wid, paso)}.inputs.{nombre}",
                                          f"'{nombre}' ({kind}) puede quedar satisfecho por contexto, pero el renderer corta con 'if(ok) continue' y no demuestra una vía genérica para elegir otro archivo.",
                                          "Mantener el valor activo y ofrecer 'Elegir otro / Choose another' sin obligar a regenerar."))
                if source == src_connection:
                    cont["connection_inputs"] += 1
                    slot, terminal = _slot_de(spec), _terminal_de(spec)
                    if not slot:
                        fallos.append(_d("CONNECTION", accion_id, "CONNECTION_SIN_SLOT",
                                          f"{_origen_paso(wid, paso)}.inputs.{nombre}",
                                          "El input CONNECTION no declara la referencia que consume.",
                                          "Declarar slot de referencia; no material secreto."))
                    if not terminal:
                        fallos.append(_d("CONNECTION", accion_id, "CONNECTION_SIN_TERMINAL",
                                          f"{_origen_paso(wid, paso)}.inputs.{nombre}",
                                          "El input CONNECTION no declara terminal causal.",
                                          "Declarar el terminal real autorizado por CONEXION."))
    return fallos, cont


def _diagnosticar_custodia(*, capa: Any, html: str) -> Tuple[List[Diagnostico], Dict[str, int]]:
    fallos: List[Diagnostico] = []
    cont = {"outputs_path": 0, "entrega_generica_archivos": 0, "referencias_visibles": 0}
    for nombre in ("registrarEntrega", "renderEntregas", "descargarEntrega", "saveBlobToDevice"):
        if f"function {nombre}" not in html and f"async function {nombre}" not in html:
            fallos.append(_d("CUSTODY", "SPARTACO_WEB", "CUSTODIA_SIN_MECANISMO",
                              f"Spartaco_UI.HTML.{nombre}",
                              f"No existe la operación de renderer '{nombre}'.",
                              "Restaurar la infraestructura de entregas USER."))
    if "ref_id" not in html or "registrarEntrega" not in html:
        fallos.append(_d("CONNECTION", "GENERADOR_CLAVES.ref_id", "REFERENCIA_NO_VISIBLE",
                          "Spartaco_UI.HTML", "No se demuestra que ref_id quede visible/entregable para USER.",
                          "Mostrar y registrar la referencia; nunca el IKM material."))
    else:
        cont["referencias_visibles"] += 1
    acciones_map = getattr(capa, "ACCIONES_MAP", {})
    if isinstance(acciones_map, Mapping):
        for _, accion in acciones_map.items():
            for _, campo in _campos_de_accion(accion).items():
                if _kind(campo) == "OUTPUT_PATH":
                    cont["outputs_path"] += 1
    if cont["outputs_path"]:
        entrega_generica = bool(re.search(r"Object\.entries\s*\(\s*r\.archivos", html)
                                 or re.search(r"for\s*\([^)]*r\.archivos", html))
        if not entrega_generica:
            fallos.append(_d("CUSTODY", "OUTPUT_PATH", "OUTPUT_PATH_SIN_ENTREGA_GENERICA",
                              "Spartaco_UI.HTML.updateUserContext",
                              "CAPA declara OUTPUT_PATH, pero el renderer no demuestra una iteración genérica sobre r.archivos; outputs nuevos pueden quedar sin botón de descarga.",
                              "Registrar dinámicamente cada archivo de r.archivos en Tus entregas usando metadata de CAPA/VISTA."))
        else:
            cont["entrega_generica_archivos"] = 1
    requisitos = {
        "ref_id": ("ref_id", "registrarEntrega"),
        "blob": ("r.blob", "registrarEntrega"),
        "manifiesto": ("r.manifiesto", "registrarEntrega"),
    }
    for salida, tokens in requisitos.items():
        if all(tok in html for tok in tokens):
            continue
        fallos.append(_d("RESULTS", salida, "OUTPUT_USER_NO_EXPORTABLE",
                          "Spartaco_UI.HTML.updateUserContext",
                          f"La salida USER '{salida}' no demuestra visibilidad + entrega descargable.",
                          "Registrar la salida en Tus entregas y mantener un control explícito de descarga."))
    return fallos, cont


def _nombre_call(nodo: ast.Call) -> Optional[str]:
    if isinstance(nodo.func, ast.Attribute):
        return nodo.func.attr
    if isinstance(nodo.func, ast.Name):
        return nodo.func.id
    return None


def _diagnosticar_boundary(ui: Any) -> Tuple[List[Diagnostico], Dict[str, int]]:
    fallos: List[Diagnostico] = []
    cont = {"boundary_calls_prohibidas": 0}
    try:
        fuente = inspect.getsource(ui)
        arbol = ast.parse(fuente)
    except Exception as exc:
        return [_d("BOUNDARY", "SPARTACO_WEB", "SOURCE_UI_NO_INSPECCIONABLE",
                   "inspect.getsource(Spartaco_UI)", f"{type(exc).__name__}: {exc}",
                   "Mantener Spartaco_UI como módulo Python inspeccionable por CI.")], cont
    for nodo in ast.walk(arbol):
        if not isinstance(nodo, ast.Call):
            continue
        nombre = _nombre_call(nodo)
        if nombre in CALLS_PROHIBIDAS_UI:
            cont["boundary_calls_prohibidas"] += 1
            estado = "UI_RESUELVE_MATERIAL_INTERNO" if nombre == "resolver_clave" else "UI_CONSTRUYE_PLANO_CAUSAL"
            fallos.append(_d("BOUNDARY", nombre, estado,
                              f"Spartaco_UI:{getattr(nodo, 'lineno', '?')}",
                              f"La superficie UI realiza '{nombre}()', operación que pertenece al backend/CONEXION y no al renderer.",
                              "Mover esa responsabilidad al backend. La UI puede consumir el entrypoint público de CONEXION, pero no resolver material ni construir/reiniciar/sellar topología."))
        if (isinstance(nodo.func, ast.Name) and nodo.func.id == "getattr"
                and len(nodo.args) >= 2 and isinstance(nodo.args[1], ast.Constant)
                and nodo.args[1].value in CALLS_PROHIBIDAS_UI):
            nombre = str(nodo.args[1].value)
            cont["boundary_calls_prohibidas"] += 1
            estado = "UI_RESUELVE_MATERIAL_INTERNO" if nombre == "resolver_clave" else "UI_CONSTRUYE_PLANO_CAUSAL"
            fallos.append(_d("BOUNDARY", nombre, estado,
                              f"Spartaco_UI:{getattr(nodo, 'lineno', '?')}",
                              f"La UI obtiene dinámicamente '{nombre}' mediante getattr().",
                              "Eliminar el acceso interno desde UI y usar el contrato público del backend."))
    if "modules.spartaco_seguridad.generador_claves" in fuente and "resolver_clave" in fuente:
        if not any(d.estado == "UI_RESUELVE_MATERIAL_INTERNO" for d in fallos):
            fallos.append(_d("BOUNDARY", "GENERADOR_CLAVES.resolver_clave",
                              "UI_RESUELVE_MATERIAL_INTERNO", "Spartaco_UI",
                              "La UI referencia el resolver interno del almacén de secretos.",
                              "CONEXION/backend debe resolver material opacamente."))
    return fallos, cont


def _diagnosticar_renderer_bilingue(html: str) -> Tuple[List[Diagnostico], Dict[str, int]]:
    fallos: List[Diagnostico] = []
    cont = {"renderer_pares_bilingues": 0}
    pares = (
        ("Tus entregas", "Your receipts"),
        ("Descargar", "Download"),
        ("Ejecutar", "Run"),
        ("Volver", "Back"),
        ("Clave privada", "Private key"),
        ("Clave publica", "Public key"),
        ("Manifiesto", "Manifest"),
        ("Documento cifrado", "Sealed document"),
        ("Cargando", "Loading"),
    )
    for es, en in pares:
        if es not in html or en not in html:
            fallos.append(_d("BILINGUE", "SPARTACO_WEB", "RENDERER_CONTROL_NO_BILINGUE",
                              "Spartaco_UI.HTML",
                              f"El renderer no contiene el par crítico ES/EN: {es!r} / {en!r}.",
                              "Proveer ambos idiomas. Idealmente mover la redacción semántica a metadata/doctrina y dejar el renderer neutral."))
        else:
            cont["renderer_pares_bilingues"] += 1
    return fallos, cont


def test_ui_experiencia_operativa_bilingue_total() -> None:
    diagnosticos: List[Diagnostico] = []
    resumen: Dict[str, int] = {
        "workflows": 0,
        "inputs_auditados": 0,
        "reutilizables": 0,
        "connection_inputs": 0,
        "outputs_path": 0,
        "referencias_visibles": 0,
        "boundary_calls_prohibidas": 0,
        "bilingue_secciones": 0,
        "bilingue_workflows": 0,
        "bilingue_pasos": 0,
        "bilingue_acciones": 0,
        "bilingue_campos": 0,
        "renderer_pares_bilingues": 0,
    }
    runtime, fallos_runtime = _cargar_runtime()
    diagnosticos.extend(fallos_runtime)
    if runtime.ui is None or runtime.capa is None or runtime.vista is None:
        pytest.fail(_reporte(diagnosticos, resumen), pytrace=False)
    workflows, fallos_workflows = _workflows(runtime.vista)
    diagnosticos.extend(fallos_workflows)
    resumen["workflows"] = len(workflows)
    html = str(getattr(runtime.ui, "HTML", "") or "")
    if not html:
        diagnosticos.append(_d("RUNTIME", "SPARTACO_WEB.HTML", "HTML_NO_DISPONIBLE",
                                "Spartaco_UI.HTML", "El renderer USER no expone HTML inspeccionable.",
                                "Mantener la superficie HTML declarada/inspeccionable para CI."))
    for funcion, kwargs in (
        (_diagnosticar_bilingue, {"capa": runtime.capa, "vista": runtime.vista, "workflows": workflows}),
        (_diagnosticar_inputs_y_contexto, {"workflows": workflows, "capa": runtime.capa, "vista": runtime.vista, "html": html}),
        (_diagnosticar_custodia, {"capa": runtime.capa, "html": html}),
        (_diagnosticar_boundary, {"ui": runtime.ui}),
        (_diagnosticar_renderer_bilingue, {"html": html}),
    ):
        fallos, cont = funcion(**kwargs)
        diagnosticos.extend(fallos)
        resumen.update(cont)
    unicos: List[Diagnostico] = []
    vistos: Set[Tuple[str, str, str, str]] = set()
    for diag in diagnosticos:
        clave = (diag.familia, diag.accion_id, diag.estado, diag.origen)
        if clave in vistos:
            continue
        vistos.add(clave)
        unicos.append(diag)
    if unicos:
        pytest.fail(_reporte(unicos, resumen), pytrace=False)
