# ===============================================================
# SPARTACO-SECURITY
# tests/test_ui_backend_fidelidad_contractual.py
# ===============================================================
#
# RECURSO
# -------
# Contrato determinista de fidelidad entre la superficie USER y
# el backend público real de SPARTACO.
#
# PROPÓSITO
# ---------
# Este test verifica que la UI:
#
#   1. No inventa capacidades que SC no declara.
#   2. No deja capacidades públicas de SC sin clasificación.
#   3. No publica acciones USER inexistentes en el backend.
#   4. No declara parámetros que la firma real no acepta.
#   5. No omite parámetros obligatorios de la firma.
#   6. No declara SIGNATURE_DEFAULT cuando no existe default real.
#   7. No declara CONNECTION sin slot ni terminal.
#   8. Resuelve acciones mediante el resolver contractual de UI.
#   9. Mantiene dispatcher directo y dispatcher de workflow.
#
# CADENA AUDITADA
# ---------------
#
#     SC público
#         ↓
#     ACCIONES_MAP
#         ↓
#     vista_user
#         ↓
#     firma real
#         ↓
#     resolver UI
#         ↓
#     dispatcher USER
#
# ECUACIONES
# ----------
#
#     Publicas(SC) = Catalogadas(CAPA)
#
#     Publicadas(USER) ⊆ Publicas(SC) ∩ Catalogadas(CAPA)
#
#     Inputs(paso) - Params(firma) = ∅
#
#     Required(firma) - Inputs(paso) - Defaults(firma) = ∅
#
#     source == CONNECTION → slot ∧ terminal
#
# LÍMITES
# -------
# Este test NO:
#
#   - Levanta ThreadingHTTPServer.
#   - Abre navegador.
#   - Genera claves.
#   - Cifra documentos.
#   - Ejecuta launcher.
#   - Resuelve IKM.
#   - Llama resolver_clave().
#   - Ejecuta workflows.
#   - Modifica archivos de producción.
#
# Es una auditoría estructural y determinista. Si falla, muestra
# qué acción, qué enlace, qué dato falta y qué debe corregirse.
#
# ===============================================================

from __future__ import annotations

import ast
import importlib
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


# ===============================================================
# PARTE 1 — RESULTADOS ESTRUCTURADOS
# ===============================================================


@dataclass(frozen=True)
class Diagnostico:
    """
    Un fallo causal del contrato UI ↔ backend.

    enlace:
        Tramo exacto de la cadena auditada.

    accion_id:
        RECURSO.capacidad, workflow o componente afectado.

    estado:
        Código estable, legible por CI.

    origen:
        Declaración, función o ruta contractual donde aparece
        la contradicción.

    falta:
        Evidencia concreta del defecto.

    correccion:
        Acción mínima para reparar el enlace.
    """

    enlace: str
    accion_id: str
    estado: str
    origen: str
    falta: str
    correccion: str

    def texto(self) -> str:
        return "\n".join(
            (
                f"- enlace: {self.enlace}",
                f"  accion: {self.accion_id}",
                f"  estado: {self.estado}",
                f"  origen: {self.origen}",
                f"  falta: {self.falta}",
                f"  correccion: {self.correccion}",
            )
        )


@dataclass(frozen=True)
class ResultadoModulo:
    """
    Resultado de resolver un módulo backend desde la ruta que
    SC.inventario() declaró como fuente de verdad.
    """

    modulo: Optional[Any]
    estado: str
    detalle: str


@dataclass(frozen=True)
class ResultadoCallable:
    """
    Resultado de resolver una capability backend y su firma real.
    """

    funcion: Optional[Any]
    firma: Optional[inspect.Signature]
    estado: str
    detalle: str


@dataclass(frozen=True)
class RuntimeUI:
    """
    Objetos reales usados por el runtime de Spartaco_UI.

    No se importan copias independientes de CAPA o VISTA_USER:
    se auditan exactamente los objetos que Spartaco_UI expone.
    """

    sc: Optional[Any]
    ui: Optional[Any]
    capa: Optional[Any]
    vista: Optional[Any]


# ===============================================================
# PARTE 2 — AYUDAS DETERMINISTAS
# ===============================================================


def _diagnostico(
    *,
    enlace: str,
    accion_id: str,
    estado: str,
    origen: str,
    falta: str,
    correccion: str,
) -> Diagnostico:
    return Diagnostico(
        enlace=enlace,
        accion_id=accion_id,
        estado=estado,
        origen=origen,
        falta=falta,
        correccion=correccion,
    )


def _lista_texto(valor: Any) -> List[str]:
    """
    Convierte una declaración permitida a lista de strings.

    Esta función no decide si la declaración era válida:
    esa responsabilidad corresponde a la auditoría de esquema.
    """
    if isinstance(valor, str):
        return [valor.strip()] if valor.strip() else []

    if not isinstance(valor, (list, tuple, set, frozenset)):
        return []

    return [
        item.strip()
        for item in valor
        if isinstance(item, str) and item.strip()
    ]


def _accion_id_valido(valor: Any) -> bool:
    """
    Contrato de identificador público:

        RECURSO.capacidad

    No se admiten identificadores sin punto ni con más de un
    punto porque el runtime los resuelve mediante partition(".").
    """
    if not isinstance(valor, str):
        return False

    recurso, punto, capacidad = valor.partition(".")

    return bool(
        recurso
        and punto
        and capacidad
        and "." not in capacidad
    )


def _origen_paso(
    workflow_id: str,
    paso: Mapping[str, Any],
) -> str:
    paso_id = paso.get("id", "<paso-sin-id>")

    return (
        "vista_user.USER_WORKFLOWS."
        f"{workflow_id}.{paso_id}"
    )


def _parametros_reales(
    firma: inspect.Signature,
) -> Dict[str, inspect.Parameter]:
    """
    Parámetros que el dispatcher puede recibir explícitamente.

    *self*, *args y **kwargs no son entradas declarables de
    workflow; por eso no se incluyen.
    """
    return {
        nombre: parametro
        for nombre, parametro in firma.parameters.items()
        if nombre != "self"
        and parametro.kind
        not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    }


def _reporte(
    diagnosticos: Iterable[Diagnostico],
    resumen: Mapping[str, int],
) -> str:
    """
    Texto único y determinista para el fallo de CI.
    """
    filas = list(diagnosticos)

    lineas = [
        "",
        "UI_BACKEND_FIDELIDAD_CONTRACTUAL: FAIL",
        "=======================================",
        "",
        "RESUMEN",
        "-------",
    ]

    for clave, valor in sorted(resumen.items()):
        lineas.append(f"{clave}: {valor}")

    if filas:
        lineas.extend(("", "DIAGNOSTICOS", "------------"))

        for fila in filas:
            lineas.extend(("", fila.texto()))

    return "\n".join(lineas)


# ===============================================================
# PARTE 3 — CARGA DEL RUNTIME REAL
# ===============================================================


def _cargar_runtime() -> Tuple[RuntimeUI, List[Diagnostico]]:
    """
    Carga los objetos reales del runtime.

    Si falla una importación o un enlace CAPA/VISTA_USER, devuelve
    un diagnóstico causal; no lanza un assert incidental.
    """
    fallos: List[Diagnostico] = []

    try:
        sc = importlib.import_module(
            "modules.spartaco_seguridad"
        )
    except Exception as exc:
        fallos.append(
            _diagnostico(
                enlace="BACKEND_DECLARADO",
                accion_id="SC.inventario",
                estado="SC_NO_IMPORTABLE",
                origen="modules.spartaco_seguridad",
                falta=f"{type(exc).__name__}: {exc}",
                correccion=(
                    "Corregir el paquete SC antes de auditar "
                    "la fidelidad UI ↔ backend."
                ),
            )
        )

        return RuntimeUI(None, None, None, None), fallos

    try:
        ui = importlib.import_module(
            "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI"
        )
    except Exception as exc:
        fallos.append(
            _diagnostico(
                enlace="DISPATCHER_USER",
                accion_id="SPARTACO_WEB",
                estado="RUNTIME_UI_NO_IMPORTABLE",
                origen=(
                    "modules.interfaz.paquetes.spartaco_ui."
                    "Spartaco_UI"
                ),
                falta=f"{type(exc).__name__}: {exc}",
                correccion=(
                    "Corregir el empaquetado o los imports "
                    "contractuales de Spartaco_UI."
                ),
            )
        )

        return RuntimeUI(sc, None, None, None), fallos

    capa = getattr(ui, "CAPA", None)
    vista = getattr(ui, "VISTA_USER", None)

    if capa is None:
        fallos.append(
            _diagnostico(
                enlace="CATALOGO_SEMANTICO",
                accion_id="SPARTACO_UI.CAPA",
                estado="RUNTIME_SIN_CAPA",
                origen="Spartaco_UI.CAPA",
                falta=(
                    "El runtime no expone la capa semántica "
                    "que debe utilizar."
                ),
                correccion=(
                    "Restaurar el enlace CAPA en Spartaco_UI."
                ),
            )
        )

    if vista is None:
        fallos.append(
            _diagnostico(
                enlace="VISTA_PUBLICADA",
                accion_id="SPARTACO_UI.VISTA_USER",
                estado="RUNTIME_SIN_VISTA",
                origen="Spartaco_UI.VISTA_USER",
                falta=(
                    "El runtime no expone la vista declarativa "
                    "USER que debe utilizar."
                ),
                correccion=(
                    "Restaurar el enlace VISTA_USER en Spartaco_UI."
                ),
            )
        )

    return RuntimeUI(sc, ui, capa, vista), fallos


# ===============================================================
# PARTE 4 — BACKEND DECLARADO
# ===============================================================


def _leer_inventario_sc(
    sc: Any,
) -> Tuple[Optional[Mapping[str, Any]], List[Diagnostico]]:
    """
    Lee SC.inventario() como única fuente de verdad de la
    superficie pública backend.
    """
    if sc is None:
        return None, []

    inventario_fn = getattr(sc, "inventario", None)

    if not callable(inventario_fn):
        return None, [
            _diagnostico(
                enlace="BACKEND_DECLARADO",
                accion_id="SC.inventario",
                estado="INVENTARIO_SC_NO_CALLABLE",
                origen="modules.spartaco_seguridad",
                falta="SC no expone inventario() callable.",
                correccion=(
                    "Exponer inventario() como capacidad contractual de SC."
                ),
            )
        ]

    try:
        inventario = inventario_fn()
    except Exception as exc:
        return None, [
            _diagnostico(
                enlace="BACKEND_DECLARADO",
                accion_id="SC.inventario",
                estado="INVENTARIO_SC_FALLA",
                origen="modules.spartaco_seguridad.inventario",
                falta=f"{type(exc).__name__}: {exc}",
                correccion=(
                    "Corregir inventario() antes de auditar "
                    "las capas dependientes."
                ),
            )
        ]

    if not isinstance(inventario, Mapping):
        return None, [
            _diagnostico(
                enlace="BACKEND_DECLARADO",
                accion_id="SC.inventario",
                estado="INVENTARIO_SC_INVALIDO",
                origen="modules.spartaco_seguridad.inventario",
                falta="inventario() no devolvió Mapping.",
                correccion=(
                    "Restaurar el contrato de salida de inventario()."
                ),
            )
        ]

    if inventario.get("coherente") is not True:
        return None, [
            _diagnostico(
                enlace="BACKEND_DECLARADO",
                accion_id="SC.inventario",
                estado="INVENTARIO_SC_INCOHERENTE",
                origen="modules.spartaco_seguridad.inventario",
                falta=(
                    f"errores={inventario.get('errores', [])!r}; "
                    f"choques={inventario.get('choques', [])!r}"
                ),
                correccion=(
                    "Resolver los errores o choques del inventario "
                    "SC antes de auditar UI ↔ backend."
                ),
            )
        ]

    return inventario, []


def _diagnosticar_esquema_inventario(
    inventario: Mapping[str, Any],
) -> List[Diagnostico]:
    """
    Impide falsos PASS por ignorar recursos o capacidades mal
    declarados dentro del inventario.
    """
    fallos: List[Diagnostico] = []

    recursos = inventario.get("recursos")

    if not isinstance(recursos, Mapping):
        return [
            _diagnostico(
                enlace="BACKEND_DECLARADO",
                accion_id="SC.inventario.recursos",
                estado="INVENTARIO_RECURSOS_INVALIDO",
                origen="modules.spartaco_seguridad.inventario",
                falta="'recursos' no es Mapping.",
                correccion=(
                    "Restaurar recursos como Mapping "
                    "recurso_id → declaración."
                ),
            )
        ]

    for recurso_id, entrada in recursos.items():
        if not isinstance(recurso_id, str) or not recurso_id.strip():
            fallos.append(
                _diagnostico(
                    enlace="BACKEND_DECLARADO",
                    accion_id=str(recurso_id),
                    estado="INVENTARIO_RECURSO_ID_INVALIDO",
                    origen=(
                        "modules.spartaco_seguridad."
                        "inventario.recursos"
                    ),
                    falta=(
                        "El identificador de recurso no es "
                        "str no vacío."
                    ),
                    correccion=(
                        "Usar un id contractual de recurso no vacío."
                    ),
                )
            )
            continue

        if not isinstance(entrada, Mapping):
            fallos.append(
                _diagnostico(
                    enlace="BACKEND_DECLARADO",
                    accion_id=recurso_id,
                    estado="INVENTARIO_RECURSO_INVALIDO",
                    origen=(
                        "modules.spartaco_seguridad."
                        "inventario.recursos"
                    ),
                    falta=(
                        "La declaración de recurso no es Mapping."
                    ),
                    correccion=(
                        "Restaurar la declaración estructurada "
                        "del recurso."
                    ),
                )
            )
            continue

        ruta = entrada.get("ruta")

        if not isinstance(ruta, str) or not ruta.strip():
            fallos.append(
                _diagnostico(
                    enlace="BACKEND_DECLARADO",
                    accion_id=recurso_id,
                    estado="INVENTARIO_RUTA_AUSENTE",
                    origen=(
                        "modules.spartaco_seguridad."
                        "inventario.recursos"
                    ),
                    falta=(
                        "El recurso no declara una ruta Python "
                        "utilizable."
                    ),
                    correccion=(
                        "Incluir ruta relativa del recurso en "
                        "SC.inventario()."
                    ),
                )
            )

        capacidades = entrada.get("capacidades_recurso")

        if not isinstance(capacidades, (str, list, tuple)):
            fallos.append(
                _diagnostico(
                    enlace="BACKEND_DECLARADO",
                    accion_id=recurso_id,
                    estado="CAPACIDADES_RECURSO_INVALIDAS",
                    origen=(
                        "modules.spartaco_seguridad."
                        "inventario.recursos"
                    ),
                    falta=(
                        "capacidades_recurso debe ser str, list "
                        "o tuple."
                    ),
                    correccion=(
                        "Declarar explícitamente las capacidades "
                        "públicas del recurso."
                    ),
                )
            )
            continue

        if isinstance(capacidades, str):
            if not capacidades.strip():
                fallos.append(
                    _diagnostico(
                        enlace="BACKEND_DECLARADO",
                        accion_id=recurso_id,
                        estado="CAPACIDADES_RECURSO_AUSENTES",
                        origen=(
                            "modules.spartaco_seguridad."
                            "inventario.recursos"
                        ),
                        falta=(
                            "capacidades_recurso es una cadena vacía."
                        ),
                        correccion=(
                            "Declarar capacidades públicas no vacías."
                        ),
                    )
                )

        if isinstance(capacidades, (list, tuple)):
            for capacidad in capacidades:
                if not isinstance(capacidad, str) or not capacidad.strip():
                    fallos.append(
                        _diagnostico(
                            enlace="BACKEND_DECLARADO",
                            accion_id=recurso_id,
                            estado="CAPACIDAD_DECLARADA_INVALIDA",
                            origen=(
                                "modules.spartaco_seguridad."
                                "inventario.recursos"
                            ),
                            falta=(
                                "Elemento inválido en "
                                f"capacidades_recurso: {capacidad!r}."
                            ),
                            correccion=(
                                "Usar nombres str no vacíos para "
                                "las capacidades públicas."
                            ),
                        )
                    )

        normalizadas = _lista_texto(capacidades)

        if len(normalizadas) != len(set(normalizadas)):
            fallos.append(
                _diagnostico(
                    enlace="BACKEND_DECLARADO",
                    accion_id=recurso_id,
                    estado="CAPACIDAD_DECLARADA_DUPLICADA",
                    origen=(
                        "modules.spartaco_seguridad."
                        "inventario.recursos"
                    ),
                    falta=(
                        "capacidades_recurso contiene duplicados: "
                        f"{normalizadas!r}."
                    ),
                    correccion=(
                        "Declarar cada capacidad pública una sola vez."
                    ),
                )
            )

    return fallos


def _acciones_backend(
    inventario: Mapping[str, Any],
) -> Dict[str, Dict[str, Any]]:
    """
    Deriva el conjunto B de capacidades públicas de SC:

        B = { RECURSO.capacidad }

    Se llama solo después de que el esquema haya sido validado.
    """
    recursos = inventario.get("recursos", {})
    acciones: Dict[str, Dict[str, Any]] = {}

    if not isinstance(recursos, Mapping):
        return acciones

    for recurso_id, entrada in recursos.items():
        if not isinstance(recurso_id, str):
            continue

        if not isinstance(entrada, Mapping):
            continue

        for capacidad in _lista_texto(
            entrada.get("capacidades_recurso")
        ):
            accion_id = f"{recurso_id}.{capacidad}"

            acciones[accion_id] = {
                "accion_id": accion_id,
                "recurso_id": recurso_id,
                "capacidad": capacidad,
                "entrada": dict(entrada),
            }

    return acciones


# ===============================================================
# PARTE 5 — BACKEND CALLABLE Y FIRMA REAL
# ===============================================================


def _modulo_backend(
    accion: Mapping[str, Any],
) -> ResultadoModulo:
    """
    Importa exactamente el módulo que SC declaró mediante ruta.

    No usa fallbacks por nombre: si SC entrega una ruta incorrecta,
    el test debe informar esa contradicción y no adivinar otro
    módulo que pudiera ocultarla.
    """
    entrada = accion["entrada"]
    ruta = entrada.get("ruta")

    if not isinstance(ruta, str) or not ruta.strip():
        return ResultadoModulo(
            modulo=None,
            estado="BACKEND_RUTA_AUSENTE",
            detalle="SC no entregó ruta del recurso.",
        )

    nombre = Path(
        ruta.replace("\\", "/")
    ).stem

    if not nombre:
        return ResultadoModulo(
            modulo=None,
            estado="BACKEND_RUTA_INVALIDA",
            detalle=(
                f"No se pudo derivar un módulo desde ruta={ruta!r}."
            ),
        )

    nombre_modulo = (
        "modules.spartaco_seguridad."
        f"{nombre}"
    )

    try:
        return ResultadoModulo(
            modulo=importlib.import_module(nombre_modulo),
            estado="OK",
            detalle="",
        )
    except ModuleNotFoundError as exc:
        if exc.name == nombre_modulo:
            estado = "BACKEND_NO_IMPORTABLE"
        else:
            estado = "BACKEND_DEPENDENCIA_ROTA"

        return ResultadoModulo(
            modulo=None,
            estado=estado,
            detalle=(
                f"Al importar {nombre_modulo}: "
                f"{type(exc).__name__}: {exc}"
            ),
        )
    except Exception as exc:
        return ResultadoModulo(
            modulo=None,
            estado="BACKEND_NO_IMPORTABLE",
            detalle=(
                f"Al importar {nombre_modulo}: "
                f"{type(exc).__name__}: {exc}"
            ),
        )


def _callable_y_firma(
    accion: Mapping[str, Any],
) -> ResultadoCallable:
    """
    Resuelve la capability y su firma real.

    Estados posibles:

    - BACKEND_RUTA_AUSENTE
    - BACKEND_RUTA_INVALIDA
    - BACKEND_NO_IMPORTABLE
    - BACKEND_DEPENDENCIA_ROTA
    - BACKEND_NO_CALLABLE
    - BACKEND_FIRMA_NO_INSPECCIONABLE
    - OK
    """
    resultado_modulo = _modulo_backend(accion)

    if resultado_modulo.modulo is None:
        return ResultadoCallable(
            funcion=None,
            firma=None,
            estado=resultado_modulo.estado,
            detalle=resultado_modulo.detalle,
        )

    capacidad = accion["capacidad"]
    funcion = getattr(
        resultado_modulo.modulo,
        capacidad,
        None,
    )

    if not callable(funcion):
        return ResultadoCallable(
            funcion=None,
            firma=None,
            estado="BACKEND_NO_CALLABLE",
            detalle=(
                f"{resultado_modulo.modulo.__name__}.{capacidad} "
                "está declarada como pública, pero no es callable."
            ),
        )

    try:
        firma = inspect.signature(funcion)
    except (TypeError, ValueError) as exc:
        return ResultadoCallable(
            funcion=funcion,
            firma=None,
            estado="BACKEND_FIRMA_NO_INSPECCIONABLE",
            detalle=f"{type(exc).__name__}: {exc}",
        )

    return ResultadoCallable(
        funcion=funcion,
        firma=firma,
        estado="OK",
        detalle="",
    )


def _diagnosticar_backend_callable(
    acciones_backend: Mapping[str, Mapping[str, Any]],
) -> List[Diagnostico]:
    fallos: List[Diagnostico] = []

    for accion_id, accion in sorted(acciones_backend.items()):
        resultado = _callable_y_firma(accion)

        if resultado.estado == "OK":
            continue

        fallos.append(
            _diagnostico(
                enlace="BACKEND_CALLABLE",
                accion_id=accion_id,
                estado=resultado.estado,
                origen="SC.inventario → módulo backend",
                falta=resultado.detalle,
                correccion=(
                    "Corregir ruta, importación, dependencia, "
                    "capacidad declarada o firma del backend."
                ),
            )
        )

    return fallos


# ===============================================================
# PARTE 6 — CATÁLOGO SEMÁNTICO
# ===============================================================


def _catalogo(
    capa: Any,
) -> Tuple[Optional[Mapping[str, Any]], List[Diagnostico]]:
    """
    Lee y valida ACCIONES_MAP antes de realizar ecuaciones de
    cobertura.
    """
    acciones_map = getattr(capa, "ACCIONES_MAP", None)

    if not isinstance(acciones_map, Mapping):
        return None, [
            _diagnostico(
                enlace="CATALOGO_SEMANTICO",
                accion_id="CAPA.ACCIONES_MAP",
                estado="CATALOGO_NO_UTILIZABLE",
                origen="capa_universal.ACCIONES_MAP",
                falta="ACCIONES_MAP no existe o no es Mapping.",
                correccion=(
                    "Exponer ACCIONES_MAP como Mapping "
                    "accion_id → Accion."
                ),
            )
        ]

    fallos: List[Diagnostico] = []

    for accion_id, accion in sorted(
        acciones_map.items(),
        key=lambda item: str(item[0]),
    ):
        if not _accion_id_valido(accion_id):
            fallos.append(
                _diagnostico(
                    enlace="CATALOGO_SEMANTICO",
                    accion_id=str(accion_id),
                    estado="ACCION_ID_INVALIDO",
                    origen="capa_universal.ACCIONES_MAP",
                    falta=(
                        "La clave no cumple RECURSO.capacidad."
                    ),
                    correccion=(
                        "Usar un accion_id canónico "
                        "RECURSO.capacidad."
                    ),
                )
            )

        if accion is None:
            fallos.append(
                _diagnostico(
                    enlace="CATALOGO_SEMANTICO",
                    accion_id=str(accion_id),
                    estado="CATALOGO_ACCION_INVALIDA",
                    origen="capa_universal.ACCIONES_MAP",
                    falta="La entrada de catálogo es None.",
                    correccion=(
                        "Registrar una Accion válida en ACCIONES_MAP."
                    ),
                )
            )
            continue

        disponibilidad = getattr(accion, "disponibilidad", None)

        if not callable(disponibilidad):
            fallos.append(
                _diagnostico(
                    enlace="CATALOGO_SEMANTICO",
                    accion_id=str(accion_id),
                    estado="CATALOGO_ACCION_INVALIDA",
                    origen="capa_universal.ACCIONES_MAP",
                    falta=(
                        "La entrada no expone "
                        "disponibilidad() contractual."
                    ),
                    correccion=(
                        "Registrar una Accion válida en ACCIONES_MAP."
                    ),
                )
            )

    return acciones_map, fallos


def _diagnosticar_cobertura_catalogo(
    acciones_backend: Set[str],
    acciones_catalogo: Set[str],
) -> List[Diagnostico]:
    """
    Verifica B = C:

        Publicas(SC) = Catalogadas(CAPA)
    """
    fallos: List[Diagnostico] = []

    for accion_id in sorted(acciones_backend - acciones_catalogo):
        fallos.append(
            _diagnostico(
                enlace="CATALOGO_SEMANTICO",
                accion_id=accion_id,
                estado="BACKEND_SIN_CATALOGO_UI",
                origen="capa_universal.ACCIONES_MAP",
                falta=(
                    "La capability pública declarada por SC "
                    "no tiene clasificación semántica."
                ),
                correccion=(
                    "Agregar una Accion contractual a ACCIONES_MAP."
                ),
            )
        )

    for accion_id in sorted(acciones_catalogo - acciones_backend):
        fallos.append(
            _diagnostico(
                enlace="CATALOGO_SEMANTICO",
                accion_id=accion_id,
                estado="CATALOGO_UI_SIN_BACKEND",
                origen="capa_universal.ACCIONES_MAP",
                falta=(
                    "La acción catalogada no existe en la superficie "
                    "pública real de SC."
                ),
                correccion=(
                    "Retirar o corregir la acción; UI no debe "
                    "inventar capacidades backend."
                ),
            )
        )

    return fallos


# ===============================================================
# PARTE 7 — VISTA USER PUBLICADA
# ===============================================================


def _publicaciones_vista(
    vista: Any,
) -> Tuple[
    Dict[str, List[str]],
    Set[str],
    List[Diagnostico],
]:
    """
    Extrae acciones publicadas desde menu() y workflows visibles.

    Conserva todas las ubicaciones de cada acción para que un Set
    de cobertura no oculte trazabilidad ni duplicidad de presencia.
    """
    publicaciones: Dict[str, List[str]] = {}
    workflows_publicados: Set[str] = set()
    fallos: List[Diagnostico] = []

    menu_fn = getattr(vista, "menu", None)

    if not callable(menu_fn):
        return publicaciones, workflows_publicados, [
            _diagnostico(
                enlace="VISTA_PUBLICADA",
                accion_id="USUARIO.menu",
                estado="VISTA_MENU_NO_CALLABLE",
                origen="vista_user.menu",
                falta="La vista USER no expone menu() callable.",
                correccion=(
                    "Exponer menu(idioma=...) como proyección "
                    "declarativa USER."
                ),
            )
        ]

    try:
        menu = menu_fn(idioma="es")
    except Exception as exc:
        return publicaciones, workflows_publicados, [
            _diagnostico(
                enlace="VISTA_PUBLICADA",
                accion_id="USUARIO.menu",
                estado="VISTA_MENU_NO_RESUELVE",
                origen="vista_user.menu",
                falta=f"{type(exc).__name__}: {exc}",
                correccion=(
                    "Corregir menu() antes de publicar "
                    "acciones USER."
                ),
            )
        ]

    if not isinstance(menu, Mapping) or menu.get("ok") is not True:
        return publicaciones, workflows_publicados, [
            _diagnostico(
                enlace="VISTA_PUBLICADA",
                accion_id="USUARIO.menu",
                estado="VISTA_MENU_NO_RESUELVE",
                origen="vista_user.menu",
                falta=f"menu() devolvió {menu!r}.",
                correccion=(
                    "Devolver Mapping con ok=True y secciones válidas."
                ),
            )
        ]

    secciones = menu.get("secciones")

    if not isinstance(secciones, list):
        return publicaciones, workflows_publicados, [
            _diagnostico(
                enlace="VISTA_PUBLICADA",
                accion_id="USUARIO.menu",
                estado="VISTA_SECCIONES_INVALIDAS",
                origen="vista_user.menu",
                falta="menu()['secciones'] no es lista.",
                correccion=(
                    "Declarar secciones como lista de estructuras USER."
                ),
            )
        ]

    workflow_fn = getattr(vista, "workflow", None)

    for indice, seccion in enumerate(secciones):
        if not isinstance(seccion, Mapping):
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id="USUARIO.menu",
                    estado="VISTA_SECCION_INVALIDA",
                    origen=f"vista_user.menu.secciones[{indice}]",
                    falta="La sección no es Mapping.",
                    correccion=(
                        "Declarar cada sección como Mapping."
                    ),
                )
            )
            continue

        seccion_id = str(seccion.get("id") or indice)

        acciones = seccion.get("acciones", [])

        if not isinstance(acciones, list):
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id="USUARIO.menu",
                    estado="VISTA_ACCIONES_INVALIDAS",
                    origen=f"vista_user.menu.{seccion_id}",
                    falta="'acciones' no es lista.",
                    correccion=(
                        "Declarar acciones directas como lista."
                    ),
                )
            )
            acciones = []

        for accion in acciones:
            accion_id = (
                accion.get("accion_id")
                if isinstance(accion, Mapping)
                else None
            )

            if not _accion_id_valido(accion_id):
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id=str(accion_id),
                        estado="ACCION_ID_INVALIDO",
                        origen=(
                            f"vista_user.menu.{seccion_id}.acciones"
                        ),
                        falta=(
                            "La acción directa no declara "
                            "RECURSO.capacidad."
                        ),
                        correccion=(
                            "Usar un accion_id canónico "
                            "RECURSO.capacidad."
                        ),
                    )
                )
                continue

            publicaciones.setdefault(
                str(accion_id),
                [],
            ).append(
                f"menu.{seccion_id}.acciones"
            )

        referencias = seccion.get("workflows", [])

        if not isinstance(referencias, list):
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id="USUARIO.menu",
                    estado="VISTA_WORKFLOWS_INVALIDOS",
                    origen=f"vista_user.menu.{seccion_id}",
                    falta="'workflows' no es lista.",
                    correccion=(
                        "Declarar workflows como lista de referencias."
                    ),
                )
            )
            referencias = []

        for referencia in referencias:
            workflow_id = (
                referencia.get("id")
                if isinstance(referencia, Mapping)
                else None
            )

            if not isinstance(workflow_id, str) or not workflow_id:
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id="USUARIO.workflow",
                        estado="WORKFLOW_REFERENCIA_INVALIDA",
                        origen=f"vista_user.menu.{seccion_id}",
                        falta=(
                            "La sección referencia un workflow "
                            "sin id válido."
                        ),
                        correccion=(
                            "Declarar un workflow_id existente."
                        ),
                    )
                )
                continue

            workflows_publicados.add(workflow_id)

            if not callable(workflow_fn):
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id=f"WORKFLOW.{workflow_id}",
                        estado="WORKFLOW_PUBLICADO_NO_RESUELVE",
                        origen=f"vista_user.menu.{seccion_id}",
                        falta="La vista no expone workflow() callable.",
                        correccion=(
                            "Exponer workflow(workflow_id, idioma=...)."
                        ),
                    )
                )
                continue

            try:
                workflow = workflow_fn(
                    workflow_id,
                    idioma="es",
                )
            except Exception as exc:
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id=f"WORKFLOW.{workflow_id}",
                        estado="WORKFLOW_PUBLICADO_NO_RESUELVE",
                        origen=f"vista_user.menu.{seccion_id}",
                        falta=f"{type(exc).__name__}: {exc}",
                        correccion=(
                            "Corregir workflow() o la referencia "
                            "de menú."
                        ),
                    )
                )
                continue

            if (
                not isinstance(workflow, Mapping)
                or workflow.get("ok") is not True
            ):
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id=f"WORKFLOW.{workflow_id}",
                        estado="WORKFLOW_PUBLICADO_NO_RESUELVE",
                        origen=f"vista_user.menu.{seccion_id}",
                        falta=f"workflow() devolvió {workflow!r}.",
                        correccion=(
                            "Devolver Mapping con ok=True."
                        ),
                    )
                )
                continue

            pasos = workflow.get("pasos")

            if not isinstance(pasos, list):
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id=f"WORKFLOW.{workflow_id}",
                        estado="WORKFLOW_PASOS_INVALIDOS",
                        origen=f"vista_user.workflow.{workflow_id}",
                        falta="workflow()['pasos'] no es lista.",
                        correccion=(
                            "Declarar pasos como lista."
                        ),
                    )
                )
                continue

            for paso in pasos:
                accion_id = (
                    paso.get("accion_id")
                    if isinstance(paso, Mapping)
                    else None
                )

                if not _accion_id_valido(accion_id):
                    fallos.append(
                        _diagnostico(
                            enlace="VISTA_PUBLICADA",
                            accion_id=str(accion_id),
                            estado="ACCION_ID_INVALIDO",
                            origen=(
                                f"vista_user.workflow.{workflow_id}"
                            ),
                            falta=(
                                "El paso no declara un accion_id "
                                "canónico."
                            ),
                            correccion=(
                                "Usar RECURSO.capacidad en cada paso."
                            ),
                        )
                    )
                    continue

                paso_id = (
                    paso.get("id", "<sin-id>")
                    if isinstance(paso, Mapping)
                    else "<sin-id>"
                )

                publicaciones.setdefault(
                    str(accion_id),
                    [],
                ).append(
                    f"workflow.{workflow_id}.{paso_id}"
                )

    return publicaciones, workflows_publicados, fallos


def _workflows_crudos(
    vista: Any,
) -> Tuple[Dict[str, Dict[str, Any]], List[Diagnostico]]:
    """
    Lee USER_WORKFLOWS sin pasar por una proyección renderizada.

    Esta es la fuente correcta para auditar inputs y firmas.
    """
    bruto = getattr(vista, "USER_WORKFLOWS", None)

    if not isinstance(bruto, Mapping):
        return {}, [
            _diagnostico(
                enlace="VISTA_PUBLICADA",
                accion_id="USER_WORKFLOWS",
                estado="WORKFLOWS_NO_UTILIZABLES",
                origen="vista_user.USER_WORKFLOWS",
                falta=(
                    "USER_WORKFLOWS no existe o no es Mapping."
                ),
                correccion=(
                    "Exponer los workflows declarados como Mapping."
                ),
            )
        ]

    workflows: Dict[str, Dict[str, Any]] = {}
    fallos: List[Diagnostico] = []

    for workflow_id, workflow in bruto.items():
        if not isinstance(workflow_id, str) or not workflow_id:
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id=str(workflow_id),
                    estado="WORKFLOW_ID_INVALIDO",
                    origen="vista_user.USER_WORKFLOWS",
                    falta=(
                        "El workflow_id no es str no vacío."
                    ),
                    correccion=(
                        "Usar un id válido para el workflow."
                    ),
                )
            )
            continue

        if not isinstance(workflow, Mapping):
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id=f"WORKFLOW.{workflow_id}",
                    estado="WORKFLOW_DECLARACION_INVALIDA",
                    origen=f"vista_user.USER_WORKFLOWS.{workflow_id}",
                    falta=(
                        "La declaración de workflow no es Mapping."
                    ),
                    correccion=(
                        "Declarar cada workflow como Mapping."
                    ),
                )
            )
            continue

        workflows[workflow_id] = dict(workflow)

    return workflows, fallos


def _diagnosticar_workflows_no_publicados(
    workflows: Mapping[str, Mapping[str, Any]],
    workflows_publicados: Set[str],
) -> List[Diagnostico]:
    fallos: List[Diagnostico] = []

    for workflow_id, workflow in sorted(workflows.items()):
        interno = bool(
            workflow.get("interno", False)
            or workflow.get("publicado") is False
        )

        if workflow_id not in workflows_publicados and not interno:
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id=f"WORKFLOW.{workflow_id}",
                    estado="WORKFLOW_DECLARADO_NO_PUBLICADO",
                    origen=f"vista_user.USER_WORKFLOWS.{workflow_id}",
                    falta=(
                        "El workflow está declarado, pero no aparece "
                        "en menu()."
                    ),
                    correccion=(
                        "Publicarlo en una sección o marcarlo "
                        "explícitamente interno=True/publicado=False."
                    ),
                )
            )

    return fallos


def _diagnosticar_vista(
    publicaciones: Mapping[str, List[str]],
    acciones_backend: Set[str],
    acciones_catalogo: Set[str],
    capa: Any,
    vista: Any,
) -> List[Diagnostico]:
    """
    Verifica:

        Publicadas(USER) ⊆ Publicas(SC) ∩ Catalogadas(CAPA)
    """
    fallos: List[Diagnostico] = []
    acciones_map = getattr(capa, "ACCIONES_MAP", {})
    renderizable = getattr(vista, "_renderizable", None)

    for accion_id, ubicaciones in sorted(publicaciones.items()):
        origen = ", ".join(ubicaciones)

        if accion_id not in acciones_catalogo:
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id=accion_id,
                    estado="VISTA_SIN_CATALOGO_UI",
                    origen=origen,
                    falta=(
                        "La vista USER publica una acción que no "
                        "existe en ACCIONES_MAP."
                    ),
                    correccion=(
                        "Catalogar la acción o retirarla de USER."
                    ),
                )
            )

        if accion_id not in acciones_backend:
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id=accion_id,
                    estado="VISTA_SIN_BACKEND",
                    origen=origen,
                    falta=(
                        "La vista USER publica una acción que no "
                        "existe en la superficie pública de SC."
                    ),
                    correccion=(
                        "Corregir accion_id o declarar la capability "
                        "pública real en SC."
                    ),
                )
            )

        accion = (
            acciones_map.get(accion_id)
            if isinstance(acciones_map, Mapping)
            else None
        )

        if accion is None:
            continue

        if (
            getattr(accion, "clase", None)
            == getattr(capa, "SYSTEM", "SYSTEM")
        ):
            fallos.append(
                _diagnostico(
                    enlace="VISTA_PUBLICADA",
                    accion_id=accion_id,
                    estado="SYSTEM_PUBLICADO_EN_USER",
                    origen=origen,
                    falta=(
                        "Una acción clasificada como SYSTEM fue "
                        "publicada en USER."
                    ),
                    correccion=(
                        "Retirarla de vista_user."
                    ),
                )
            )

        if callable(renderizable):
            try:
                estado_render = renderizable(accion_id)
            except Exception as exc:
                estado_render = {
                    "renderizable": False,
                    "missing_metadata": [
                        f"{type(exc).__name__}: {exc}"
                    ],
                }

            if (
                isinstance(estado_render, Mapping)
                and not estado_render.get("renderizable")
            ):
                fallos.append(
                    _diagnostico(
                        enlace="VISTA_PUBLICADA",
                        accion_id=accion_id,
                        estado="VISTA_NO_RENDERIZABLE",
                        origen=origen,
                        falta=(
                            "La acción está publicada, pero no tiene "
                            "metadata suficiente. "
                            "missing_metadata="
                            f"{estado_render.get('missing_metadata', [])!r}"
                        ),
                        correccion=(
                            "Completar la metadata de render o "
                            "retirar la acción publicada."
                        ),
                    )
                )

    return fallos


# ===============================================================
# PARTE 8 — WORKFLOW Y FIRMA REAL
# ===============================================================


def _diagnosticar_firmas_workflow(
    workflows: Mapping[str, Mapping[str, Any]],
    vista: Any,
    acciones_backend: Mapping[str, Mapping[str, Any]],
) -> List[Diagnostico]:
    """
    Audita, para cada paso crudo:

        Inputs(paso) - Params(firma) = ∅

        Required(firma) - Inputs(paso) - Defaults(firma) = ∅

    La firma proviene del callable real backend, no de metadata
    duplicada de UI.
    """
    fallos: List[Diagnostico] = []

    source_default = getattr(
        vista,
        "SIGNATURE_DEFAULT",
        "SIGNATURE_DEFAULT",
    )

    for workflow_id, workflow in sorted(workflows.items()):
        pasos = workflow.get("pasos")

        if not isinstance(pasos, list):
            fallos.append(
                _diagnostico(
                    enlace="FIRMA_WORKFLOW",
                    accion_id=f"WORKFLOW.{workflow_id}",
                    estado="WORKFLOW_PASOS_INVALIDOS",
                    origen=f"vista_user.USER_WORKFLOWS.{workflow_id}",
                    falta="'pasos' no es lista.",
                    correccion=(
                        "Declarar pasos como lista de Mapping."
                    ),
                )
            )
            continue

        for paso in pasos:
            if not isinstance(paso, Mapping):
                fallos.append(
                    _diagnostico(
                        enlace="FIRMA_WORKFLOW",
                        accion_id=f"WORKFLOW.{workflow_id}",
                        estado="WORKFLOW_PASO_INVALIDO",
                        origen=f"vista_user.USER_WORKFLOWS.{workflow_id}",
                        falta="Un paso no es Mapping.",
                        correccion=(
                            "Declarar cada paso como Mapping."
                        ),
                    )
                )
                continue

            origen = _origen_paso(workflow_id, paso)
            accion_id = paso.get("accion_id")

            if not _accion_id_valido(accion_id):
                fallos.append(
                    _diagnostico(
                        enlace="FIRMA_WORKFLOW",
                        accion_id=str(accion_id),
                        estado="ACCION_ID_INVALIDO",
                        origen=origen,
                        falta=(
                            "El paso no declara RECURSO.capacidad."
                        ),
                        correccion=(
                            "Corregir accion_id del workflow."
                        ),
                    )
                )
                continue

            accion = acciones_backend.get(str(accion_id))

            if accion is None:
                continue

            resultado = _callable_y_firma(accion)

            if resultado.firma is None:
                continue

            parametros = _parametros_reales(resultado.firma)
            inputs = paso.get("inputs", {})

            if not isinstance(inputs, Mapping):
                fallos.append(
                    _diagnostico(
                        enlace="FIRMA_WORKFLOW",
                        accion_id=str(accion_id),
                        estado="WORKFLOW_INPUTS_INVALIDOS",
                        origen=origen,
                        falta="'inputs' no es Mapping.",
                        correccion=(
                            "Declarar inputs como parámetro → "
                            "especificación de fuente."
                        ),
                    )
                )
                continue

            for nombre, spec in sorted(inputs.items()):
                if nombre not in parametros:
                    fallos.append(
                        _diagnostico(
                            enlace="FIRMA_WORKFLOW",
                            accion_id=str(accion_id),
                            estado="WORKFLOW_PARAMETRO_INEXISTENTE",
                            origen=origen,
                            falta=(
                                f"'{nombre}' no aparece en la firma "
                                f"real {resultado.firma}."
                            ),
                            correccion=(
                                "Corregir vista_user; no modificar "
                                "backend para aceptar un parámetro "
                                "inventado por UI."
                            ),
                        )
                    )
                    continue

                if not isinstance(spec, Mapping):
                    fallos.append(
                        _diagnostico(
                            enlace="FIRMA_WORKFLOW",
                            accion_id=str(accion_id),
                            estado="WORKFLOW_INPUT_SPEC_INVALIDA",
                            origen=f"{origen}.{nombre}",
                            falta=(
                                "La especificación del input no es "
                                "Mapping."
                            ),
                            correccion=(
                                "Declarar source y metadata "
                                "correspondiente."
                            ),
                        )
                    )
                    continue

                if (
                    spec.get("source") == source_default
                    and parametros[nombre].default
                    is inspect.Parameter.empty
                ):
                    fallos.append(
                        _diagnostico(
                            enlace="FIRMA_WORKFLOW",
                            accion_id=str(accion_id),
                            estado=(
                                "SIGNATURE_DEFAULT_SIN_DEFAULT_REAL"
                            ),
                            origen=f"{origen}.{nombre}",
                            falta=(
                                f"'{nombre}' usa SIGNATURE_DEFAULT, "
                                f"pero la firma real {resultado.firma} "
                                "no tiene default."
                            ),
                            correccion=(
                                "Declarar una fuente real para "
                                "el parámetro."
                            ),
                        )
                    )

            for nombre, parametro in sorted(parametros.items()):
                if (
                    parametro.kind
                    == inspect.Parameter.POSITIONAL_ONLY
                ):
                    fallos.append(
                        _diagnostico(
                            enlace="DISPATCHER_USER",
                            accion_id=str(accion_id),
                            estado=(
                                "PARAMETRO_POSITIONAL_ONLY_"
                                "NO_DESPACHABLE"
                            ),
                            origen=origen,
                            falta=(
                                f"'{nombre}' es positional-only en "
                                f"{resultado.firma}; el dispatcher "
                                "USER construye kwargs."
                            ),
                            correccion=(
                                "Usar una firma keyword-compatible "
                                "o declarar un adaptador contractual."
                            ),
                        )
                    )

                if (
                    parametro.default is inspect.Parameter.empty
                    and nombre not in inputs
                ):
                    fallos.append(
                        _diagnostico(
                            enlace="FIRMA_WORKFLOW",
                            accion_id=str(accion_id),
                            estado=(
                                "WORKFLOW_PARAMETRO_"
                                "OBLIGATORIO_SIN_FUENTE"
                            ),
                            origen=origen,
                            falta=(
                                f"'{nombre}' es obligatorio en "
                                f"{resultado.firma}, pero el workflow "
                                "no declara una fuente."
                            ),
                            correccion=(
                                "Declarar USER, CONTEXT, FIXED, "
                                "PREVIOUS_RESULT o CONNECTION según "
                                "corresponda."
                            ),
                        )
                    )

    return fallos


# ===============================================================
# PARTE 9 — CONNECTION
# ===============================================================


def _diagnosticar_connection(
    workflows: Mapping[str, Mapping[str, Any]],
    vista: Any,
) -> List[Diagnostico]:
    """
    Para todo input con source=CONNECTION exige:

        slot ∧ terminal

    No resuelve referencias, no abre secretos y no ejecuta el
    plano. Solo comprueba que la declaración contiene el cable
    causal mínimo que el dispatcher necesita.
    """
    fallos: List[Diagnostico] = []

    source_connection = getattr(
        vista,
        "CONNECTION",
        "CONNECTION",
    )

    try:
        conexion = importlib.import_module(
            "modules.spartaco_seguridad.conexion"
        )
    except Exception as exc:
        return [
            _diagnostico(
                enlace="CONNECTION_METADATA",
                accion_id="CONEXION",
                estado="CONEXION_NO_IMPORTABLE",
                origen="modules.spartaco_seguridad.conexion",
                falta=f"{type(exc).__name__}: {exc}",
                correccion=(
                    "Corregir CONEXION antes de publicar "
                    "workflows con source=CONNECTION."
                ),
            )
        ]

    if not callable(getattr(conexion, "ejecutar", None)):
        fallos.append(
            _diagnostico(
                enlace="CONNECTION_METADATA",
                accion_id="CONEXION.ejecutar",
                estado="CONEXION_EJECUTAR_NO_DISPONIBLE",
                origen="modules.spartaco_seguridad.conexion",
                falta="conexion.ejecutar() no es callable.",
                correccion=(
                    "Exponer la API causal que utiliza el "
                    "dispatcher USER."
                ),
            )
        )

    if not callable(getattr(conexion, "panel", None)):
        fallos.append(
            _diagnostico(
                enlace="CONNECTION_METADATA",
                accion_id="CONEXION.panel",
                estado="CONEXION_PANEL_NO_DISPONIBLE",
                origen="modules.spartaco_seguridad.conexion",
                falta="conexion.panel() no es callable.",
                correccion=(
                    "Exponer panel() de solo lectura del plano causal."
                ),
            )
        )

    for workflow_id, workflow in sorted(workflows.items()):
        pasos = workflow.get("pasos", [])

        if not isinstance(pasos, list):
            continue

        for paso in pasos:
            if not isinstance(paso, Mapping):
                continue

            accion_id = str(paso.get("accion_id") or "")
            inputs = paso.get("inputs", {})

            if not isinstance(inputs, Mapping):
                continue

            for parametro, spec in sorted(inputs.items()):
                if not isinstance(spec, Mapping):
                    continue

                if spec.get("source") != source_connection:
                    continue

                origen = (
                    f"{_origen_paso(workflow_id, paso)}."
                    f"{parametro}"
                )

                slot = spec.get("slot")
                terminal = spec.get("terminal")

                if (
                    not isinstance(slot, str)
                    or not slot.strip()
                ):
                    fallos.append(
                        _diagnostico(
                            enlace="CONNECTION_METADATA",
                            accion_id=accion_id,
                            estado="CONNECTION_SIN_SLOT",
                            origen=origen,
                            falta=(
                                "El input usa CONNECTION, pero no "
                                "declara slot de referencia."
                            ),
                            correccion=(
                                "Declarar el slot de referencia; "
                                "no resolver IKM desde UI."
                            ),
                        )
                    )

                if (
                    not isinstance(terminal, str)
                    or not terminal.strip()
                ):
                    fallos.append(
                        _diagnostico(
                            enlace="CONNECTION_METADATA",
                            accion_id=accion_id,
                            estado="CONNECTION_SIN_TERMINAL",
                            origen=origen,
                            falta=(
                                "El input usa CONNECTION desde "
                                f"slot={slot!r}, pero no declara "
                                "terminal causal."
                            ),
                            correccion=(
                                "Declarar el terminal autorizado "
                                "por CONEXION."
                            ),
                        )
                    )

    return fallos


# ===============================================================
# PARTE 10 — RESOLVER Y DISPATCHER USER
# ===============================================================


def _dispatcher_usa_resolver(
    ui: Any,
    nombre: str,
) -> Tuple[bool, str, str]:
    """
    Comprueba estáticamente que el dispatcher cruza la frontera
    contractual mediante _resolver_capacidad.

    No ejecuta el dispatcher ni ninguna capability sensible.
    """
    funcion = getattr(ui, nombre, None)

    if not callable(funcion):
        return (
            False,
            "DISPATCHER_USER_AUSENTE",
            "El dispatcher está ausente o no es callable.",
        )

    try:
        fuente = inspect.getsource(funcion)
        arbol = ast.parse(fuente)
    except Exception as exc:
        return (
            False,
            "DISPATCHER_FUENTE_NO_INSPECCIONABLE",
            f"{type(exc).__name__}: {exc}",
        )

    for nodo in ast.walk(arbol):
        if (
            isinstance(nodo, ast.Name)
            and nodo.id == "_resolver_capacidad"
        ):
            return True, "OK", ""

    return (
        False,
        "DISPATCHER_NO_USA_RESOLVER_CONTRACTUAL",
        (
            "El dispatcher no referencia "
            "_resolver_capacidad."
        ),
    )


def _diagnosticar_resolver_y_dispatcher(
    publicaciones: Mapping[str, List[str]],
    acciones_backend: Mapping[str, Mapping[str, Any]],
    capa: Any,
    ui: Any,
) -> List[Diagnostico]:
    """
    Verifica que las acciones USER operables lleguen al resolver
    contractual y que el resolver produzca la misma firma que el
    callable backend real.
    """
    fallos: List[Diagnostico] = []

    resolver = getattr(ui, "_resolver_capacidad", None)

    if not callable(resolver):
        fallos.append(
            _diagnostico(
                enlace="RESOLVER_UI",
                accion_id="USER.resolver",
                estado="RESOLVER_UI_AUSENTE",
                origen="Spartaco_UI._resolver_capacidad",
                falta=(
                    "El runtime no expone el resolver contractual "
                    "de capacidades públicas."
                ),
                correccion=(
                    "Restaurar el resolver contractual de UI."
                ),
            )
        )

    dispatchers = (
        (
            "ejecutar_accion_usuario",
            "USER.dispatch_directo",
        ),
        (
            "ejecutar_paso_usuario",
            "USER.dispatch_workflow",
        ),
    )

    for nombre, accion_id in dispatchers:
        ok, estado, detalle = _dispatcher_usa_resolver(
            ui,
            nombre,
        )

        if not ok:
            fallos.append(
                _diagnostico(
                    enlace="DISPATCHER_USER",
                    accion_id=accion_id,
                    estado=estado,
                    origen=f"Spartaco_UI.{nombre}",
                    falta=detalle,
                    correccion=(
                        "Restaurar el dispatcher y hacer que "
                        "resuelva capacidades mediante la "
                        "frontera contractual."
                    ),
                )
            )

    if not callable(resolver):
        return fallos

    acciones_map = getattr(capa, "ACCIONES_MAP", {})

    for accion_id, ubicaciones in sorted(publicaciones.items()):
        accion_backend = acciones_backend.get(accion_id)

        accion_ui = (
            acciones_map.get(accion_id)
            if isinstance(acciones_map, Mapping)
            else None
        )

        if accion_backend is None or accion_ui is None:
            continue

        if (
            getattr(accion_ui, "clase", None)
            == getattr(capa, "SYSTEM", "SYSTEM")
        ):
            continue

        recurso = accion_backend["recurso_id"]
        capacidad = accion_backend["capacidad"]

        try:
            funcion_ui, error_ui = resolver(
                recurso,
                capacidad,
            )
        except Exception as exc:
            funcion_ui = None
            error_ui = f"{type(exc).__name__}: {exc}"

        if not callable(funcion_ui):
            fallos.append(
                _diagnostico(
                    enlace="RESOLVER_UI",
                    accion_id=accion_id,
                    estado="UI_NO_CONECTADA_AL_BACKEND",
                    origen=", ".join(ubicaciones),
                    falta=(
                        "_resolver_capacidad() no devolvió "
                        f"callable: {error_ui!r}"
                    ),
                    correccion=(
                        "Corregir recurso, capacidad, inventario SC "
                        "o resolución UI."
                    ),
                )
            )
            continue

        resultado_backend = _callable_y_firma(accion_backend)

        if resultado_backend.firma is None:
            continue

        try:
            firma_ui = inspect.signature(funcion_ui)
        except (TypeError, ValueError) as exc:
            fallos.append(
                _diagnostico(
                    enlace="RESOLVER_UI",
                    accion_id=accion_id,
                    estado=(
                        "RESOLVER_UI_FIRMA_NO_INSPECCIONABLE"
                    ),
                    origen="Spartaco_UI._resolver_capacidad",
                    falta=f"{type(exc).__name__}: {exc}",
                    correccion=(
                        "Resolver el callable público real con "
                        "firma inspeccionable."
                    ),
                )
            )
            continue

        if firma_ui != resultado_backend.firma:
            fallos.append(
                _diagnostico(
                    enlace="RESOLVER_UI",
                    accion_id=accion_id,
                    estado="UI_RESUELVE_FIRMA_DISTINTA",
                    origen="Spartaco_UI._resolver_capacidad",
                    falta=(
                        f"firma backend={resultado_backend.firma}; "
                        f"firma UI={firma_ui}"
                    ),
                    correccion=(
                        "Eliminar wrapper o redirección de dominio; "
                        "UI debe resolver la capability pública "
                        "declarada."
                    ),
                )
            )

    return fallos


# ===============================================================
# PARTE 11 — RESUMEN
# ===============================================================


def _resumen(
    *,
    acciones_backend: Mapping[str, Any],
    acciones_catalogo: Set[str],
    publicaciones: Mapping[str, List[str]],
    workflows: Mapping[str, Any],
    diagnosticos: Iterable[Diagnostico],
) -> Dict[str, int]:
    filas = list(diagnosticos)

    resumen = {
        "backend_publicas": len(acciones_backend),
        "catalogo_acciones": len(acciones_catalogo),
        "vista_acciones_unicas": len(publicaciones),
        "vista_publicaciones": sum(
            len(ubicaciones)
            for ubicaciones in publicaciones.values()
        ),
        "workflows_declarados": len(workflows),
        "fallos_total": len(filas),
    }

    enlaces = (
        "BACKEND_DECLARADO",
        "BACKEND_CALLABLE",
        "CATALOGO_SEMANTICO",
        "VISTA_PUBLICADA",
        "FIRMA_WORKFLOW",
        "CONNECTION_METADATA",
        "RESOLVER_UI",
        "DISPATCHER_USER",
    )

    for enlace in enlaces:
        resumen[
            f"fallos_{enlace.lower()}"
        ] = sum(
            1
            for fila in filas
            if fila.enlace == enlace
        )

    return resumen


# ===============================================================
# PARTE 12 — TEST
# ===============================================================


def test_ui_backend_fidelidad_contractual() -> None:
    """
    Compuerta CI independiente de fidelidad UI ↔ backend.

    Este test es intencionalmente estructural: valida que USER
    describe, publica y resuelve la misma superficie que el backend
    público declara, sin ejecutar criptografía ni material sensible.
    """
    fallos: List[Diagnostico] = []

    runtime, fallos_runtime = _cargar_runtime()
    fallos.extend(fallos_runtime)

    inventario, fallos_inventario = _leer_inventario_sc(runtime.sc)
    fallos.extend(fallos_inventario)

    # La fuente de verdad está rota: no generar síntomas secundarios
    # en catálogo, vista, firma, CONNECTION o dispatcher.
    if inventario is None:
        assert not fallos, _reporte(
            fallos,
            _resumen(
                acciones_backend={},
                acciones_catalogo=set(),
                publicaciones={},
                workflows={},
                diagnosticos=fallos,
            ),
        )
        return

    fallos_esquema = _diagnosticar_esquema_inventario(inventario)
    fallos.extend(fallos_esquema)

    # No extraer acciones de un inventario mal formado.
    if fallos_esquema:
        assert not fallos, _reporte(
            fallos,
            _resumen(
                acciones_backend={},
                acciones_catalogo=set(),
                publicaciones={},
                workflows={},
                diagnosticos=fallos,
            ),
        )
        return

    acciones_backend = _acciones_backend(inventario)

    fallos.extend(
        _diagnosticar_backend_callable(acciones_backend)
    )

    acciones_catalogo: Set[str] = set()
    publicaciones: Dict[str, List[str]] = {}
    workflows_publicados: Set[str] = set()
    workflows: Dict[str, Dict[str, Any]] = {}

    if runtime.capa is not None:
        catalogo, fallos_catalogo = _catalogo(runtime.capa)
        fallos.extend(fallos_catalogo)

        if isinstance(catalogo, Mapping):
            acciones_catalogo = set(catalogo.keys())

    if runtime.vista is not None:
        (
            publicaciones,
            workflows_publicados,
            fallos_publicacion,
        ) = _publicaciones_vista(runtime.vista)

        fallos.extend(fallos_publicacion)

        workflows, fallos_workflows = _workflows_crudos(
            runtime.vista
        )

        fallos.extend(fallos_workflows)

        fallos.extend(
            _diagnosticar_workflows_no_publicados(
                workflows,
                workflows_publicados,
            )
        )

    if runtime.capa is not None:
        fallos.extend(
            _diagnosticar_cobertura_catalogo(
                set(acciones_backend),
                acciones_catalogo,
            )
        )

    if runtime.capa is not None and runtime.vista is not None:
        fallos.extend(
            _diagnosticar_vista(
                publicaciones,
                set(acciones_backend),
                acciones_catalogo,
                runtime.capa,
                runtime.vista,
            )
        )

        fallos.extend(
            _diagnosticar_firmas_workflow(
                workflows,
                runtime.vista,
                acciones_backend,
            )
        )

        fallos.extend(
            _diagnosticar_connection(
                workflows,
                runtime.vista,
            )
        )

    if runtime.ui is not None and runtime.capa is not None:
        fallos.extend(
            _diagnosticar_resolver_y_dispatcher(
                publicaciones,
                acciones_backend,
                runtime.capa,
                runtime.ui,
            )
        )

    assert not fallos, _reporte(
        fallos,
        _resumen(
            acciones_backend=acciones_backend,
            acciones_catalogo=acciones_catalogo,
            publicaciones=publicaciones,
            workflows=workflows,
            diagnosticos=fallos,
        ),
    )
