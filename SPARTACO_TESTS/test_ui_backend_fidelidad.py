from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


@dataclass(frozen=True)
class DiagnosticoAccion:
    accion_id: str
    estado: str
    origen: str
    falta: str
    correccion: str

    def texto(self) -> str:
        return (
            f"\n- accion: {self.accion_id}"
            f"\n  estado: {self.estado}"
            f"\n  origen: {self.origen}"
            f"\n  falta: {self.falta}"
            f"\n  correccion: {self.correccion}"
        )


def _texto_diagnosticos(
    titulo: str,
    diagnosticos: Iterable[DiagnosticoAccion],
    *,
    resumen: Optional[Dict[str, int]] = None,
) -> str:
    filas = list(diagnosticos)
    lineas = [f"\n{titulo}", "=" * len(titulo)]

    if resumen:
        lineas.extend(
            [
                "",
                "RESUMEN",
                "-------",
                *[
                    f"{clave}: {valor}"
                    for clave, valor in sorted(resumen.items())
                ],
            ]
        )

    if not filas:
        lineas.append("Sin diagnósticos.")
        return "\n".join(lineas)

    lineas.append("")
    lineas.extend(fila.texto().lstrip("\n") for fila in filas)

    return "\n".join(lineas)


def _normalizar_lista(valor: Any) -> List[str]:
    if isinstance(valor, str):
        return [valor] if valor.strip() else []

    if not isinstance(valor, (list, tuple, set)):
        return []

    return [
        item.strip()
        for item in valor
        if isinstance(item, str) and item.strip()
    ]


def _es_parametro_real(parametro: inspect.Parameter) -> bool:
    return (
        parametro.name != "self"
        and parametro.kind
        not in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        )
    )


def _ruta_origen_workflow(
    workflow_id: str,
    paso: Mapping[str, Any],
) -> str:
    return (
        "vista_user.USER_WORKFLOWS."
        f"{workflow_id}.{paso.get('id', '<paso-sin-id>')}"
    )


def _cargar_modulos() -> Tuple[Any, Any, Any, Any]:
    sc = importlib.import_module("modules.spartaco_seguridad")

    ui = importlib.import_module(
        "modules.interfaz.paquetes.spartaco_ui.Spartaco_UI"
    )

    vista = importlib.import_module(
        "modules.interfaz.paquetes.spartaco_ui.vista_user"
    )

    capa = getattr(ui, "CAPA", None)

    if capa is None:
        raise AssertionError(
            "Spartaco_UI no expone CAPA. "
            "La prueba no puede verificar la misma capa semántica "
            "que usa el runtime real."
        )

    return sc, capa, vista, ui


def _diagnosticar_inventario(
    inventario: Any,
) -> List[DiagnosticoAccion]:
    if isinstance(inventario, dict) and inventario.get("coherente") is True:
        return []

    if not isinstance(inventario, dict):
        return [
            DiagnosticoAccion(
                accion_id="SC.inventario",
                estado="INVENTARIO_SC_INVALIDO",
                origen="modules.spartaco_seguridad.inventario",
                falta=(
                    "inventario() no devolvió dict; la UI no puede "
                    "descubrir de forma contractual el backend."
                ),
                correccion=(
                    "Corregir inventario() para que devuelva el contrato "
                    "estructural esperado."
                ),
            )
        ]

    errores = inventario.get("errores", [])
    choques = inventario.get("choques", [])

    return [
        DiagnosticoAccion(
            accion_id="SC.inventario",
            estado="INVENTARIO_SC_INCOHERENTE",
            origen="modules.spartaco_seguridad.inventario",
            falta=(
                "SC no declaró un inventario coherente. "
                f"errores={errores!r}; choques={choques!r}"
            ),
            correccion=(
                "Resolver los errores y choques del inventario de SC "
                "antes de auditar conexión entre UI y backend."
            ),
        )
    ]


def _acciones_backend(
    inventario: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    salida: Dict[str, Dict[str, Any]] = {}

    recursos = inventario.get("recursos", {})

    if not isinstance(recursos, dict):
        return salida

    for recurso_id, entrada in recursos.items():
        if not isinstance(recurso_id, str) or not isinstance(entrada, dict):
            continue

        for capacidad in _normalizar_lista(
            entrada.get("capacidades_recurso")
        ):
            accion_id = f"{recurso_id}.{capacidad}"

            salida[accion_id] = {
                "accion_id": accion_id,
                "recurso_id": recurso_id,
                "capacidad": capacidad,
                "entrada": entrada,
            }

    return salida


def _modulo_backend(
    accion: Mapping[str, Any],
) -> Tuple[Optional[Any], str]:
    entrada = accion["entrada"]
    ruta = entrada.get("ruta")

    if not isinstance(ruta, str) or not ruta.strip():
        return None, "el inventario SC no entrega ruta del recurso"

    nombre_modulo = Path(ruta.replace("\\", "/")).stem

    if not nombre_modulo:
        return None, f"no se pudo derivar módulo desde ruta={ruta!r}"

    nombre_canonico = (
        "modules.spartaco_seguridad."
        f"{nombre_modulo}"
    )

    try:
        return importlib.import_module(nombre_canonico), ""
    except ModuleNotFoundError as exc:
        if exc.name == nombre_canonico:
            return None, (
                f"el módulo declarado no existe: {nombre_canonico}"
            )

        return None, (
            f"falló una dependencia interna al importar "
            f"{nombre_canonico}: {type(exc).__name__}: {exc}"
        )
    except Exception as exc:
        return None, (
            f"falló la importación de {nombre_canonico}: "
            f"{type(exc).__name__}: {exc}"
        )


def _acciones_vista(vista: Any) -> Set[str]:
    acciones: Set[str] = set()

    menu = vista.menu(idioma="es")

    for seccion in menu.get("secciones", []):
        if not isinstance(seccion, dict):
            continue

        for accion in seccion.get("acciones", []):
            if not isinstance(accion, dict):
                continue

            accion_id = accion.get("accion_id")

            if isinstance(accion_id, str) and accion_id:
                acciones.add(accion_id)

        for referencia in seccion.get("workflows", []):
            if not isinstance(referencia, dict):
                continue

            workflow_id = referencia.get("id")

            if not isinstance(workflow_id, str) or not workflow_id:
                continue

            detalle = vista.workflow(workflow_id, idioma="es")

            for paso in detalle.get("pasos", []):
                if not isinstance(paso, dict):
                    continue

                accion_id = paso.get("accion_id")

                if isinstance(accion_id, str) and accion_id:
                    acciones.add(accion_id)

    return acciones


def _workflows(vista: Any) -> Dict[str, Dict[str, Any]]:
    bruto = getattr(vista, "USER_WORKFLOWS", {})

    if not isinstance(bruto, dict):
        return {}

    return {
        workflow_id: workflow
        for workflow_id, workflow in bruto.items()
        if isinstance(workflow_id, str) and isinstance(workflow, dict)
    }


def _firma_real(
    accion: Mapping[str, Any],
) -> Tuple[Optional[Any], Optional[inspect.Signature], str]:
    modulo, error = _modulo_backend(accion)

    if modulo is None:
        return None, None, error

    capacidad = accion["capacidad"]
    funcion = getattr(modulo, capacidad, None)

    if not callable(funcion):
        return None, None, (
            f"{modulo.__name__}.{capacidad} está declarada, "
            "pero no es callable"
        )

    try:
        return funcion, inspect.signature(funcion), ""
    except (TypeError, ValueError) as exc:
        return funcion, None, (
            f"no se pudo inspeccionar firma de "
            f"{modulo.__name__}.{capacidad}: "
            f"{type(exc).__name__}: {exc}"
        )


def _diagnosticar_backend(
    acciones_backend: Dict[str, Dict[str, Any]],
) -> List[DiagnosticoAccion]:
    fallos: List[DiagnosticoAccion] = []

    for accion_id, accion in sorted(acciones_backend.items()):
        funcion, firma, error = _firma_real(accion)

        if funcion is None:
            estado = (
                "BACKEND_NO_IMPORTABLE"
                if "import" in error or "módulo" in error
                else "BACKEND_NO_CALLABLE"
            )

            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado=estado,
                    origen="SC.inventario → módulo backend",
                    falta=error,
                    correccion=(
                        "Corregir la ruta declarada por SC, el empaquetado "
                        "Python, imports internos o la capacidad declarada."
                    ),
                )
            )
            continue

        if firma is None:
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="BACKEND_FIRMA_NO_INSPECCIONABLE",
                    origen=funcion.__module__,
                    falta=error,
                    correccion=(
                        "Exponer una función Python con firma inspeccionable "
                        "o documentar un adaptador contractual explícito."
                    ),
                )
            )

    return fallos


def _diagnosticar_catalogo(
    *,
    acciones_backend: Set[str],
    acciones_catalogo: Set[str],
) -> List[DiagnosticoAccion]:
    fallos: List[DiagnosticoAccion] = []

    for accion_id in sorted(acciones_backend - acciones_catalogo):
        fallos.append(
            DiagnosticoAccion(
                accion_id=accion_id,
                estado="BACKEND_SIN_CATALOGO_UI",
                origen="capa_universal.ACCIONES_MAP",
                falta=(
                    "La capacidad pública declarada por SC no tiene "
                    "clasificación semántica en la capa UI."
                ),
                correccion=(
                    "Agregar una entrada contractual a ACCIONES_MAP con "
                    "clase, objeto, acción, campos, wire, fuentes y riesgo."
                ),
            )
        )

    for accion_id in sorted(acciones_catalogo - acciones_backend):
        fallos.append(
            DiagnosticoAccion(
                accion_id=accion_id,
                estado="CATALOGO_UI_SIN_BACKEND",
                origen="capa_universal.ACCIONES_MAP",
                falta=(
                    "La capa UI declara una acción que no figura como "
                    "capacidad pública en el inventario real de SC."
                ),
                correccion=(
                    "Corregir o retirar la entrada de ACCIONES_MAP; "
                    "no inventar una capacidad en la UI."
                ),
            )
        )

    return fallos


def _diagnosticar_vista(
    *,
    acciones_vista: Set[str],
    acciones_backend: Set[str],
    acciones_catalogo: Set[str],
    capa: Any,
    vista: Any,
) -> List[DiagnosticoAccion]:
    fallos: List[DiagnosticoAccion] = []

    for accion_id in sorted(acciones_vista):
        if accion_id not in acciones_catalogo:
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="VISTA_SIN_CATALOGO_UI",
                    origen="vista_user.menu/workflow",
                    falta=(
                        "La vista USER publica una acción que la capa "
                        "semántica no clasifica."
                    ),
                    correccion=(
                        "Agregar la acción a ACCIONES_MAP o retirarla "
                        "de la vista USER."
                    ),
                )
            )

        if accion_id not in acciones_backend:
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="VISTA_SIN_BACKEND",
                    origen="vista_user.menu/workflow",
                    falta=(
                        "La vista USER publica una acción que no existe "
                        "como capacidad pública real de SC."
                    ),
                    correccion=(
                        "Corregir accion_id en vista_user o declarar "
                        "la capacidad correspondiente en el backend."
                    ),
                )
            )

        accion_ui = getattr(capa, "ACCIONES_MAP", {}).get(accion_id)

        if accion_ui is None:
            continue

        clase = getattr(accion_ui, "clase", "")

        if clase == getattr(capa, "SYSTEM", "SYSTEM"):
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="SYSTEM_PUBLICADO_EN_USER",
                    origen="vista_user.menu/workflow",
                    falta=(
                        "Una acción clasificada como SYSTEM aparece en "
                        "la superficie USER."
                    ),
                    correccion=(
                        "Retirarla de vista_user; las acciones SYSTEM "
                        "no se exponen como operación de usuario."
                    ),
                )
            )

        renderizable = getattr(vista, "_renderizable", None)

        if callable(renderizable):
            try:
                salida = renderizable(accion_id)
            except Exception as exc:
                salida = {
                    "renderizable": False,
                    "missing_metadata": [
                        f"{type(exc).__name__}: {exc}"
                    ],
                }

            if isinstance(salida, dict) and not salida.get(
                "renderizable",
                False,
            ):
                fallos.append(
                    DiagnosticoAccion(
                        accion_id=accion_id,
                        estado="VISTA_NO_RENDERIZABLE",
                        origen="vista_user._renderizable",
                        falta=(
                            "La acción está publicada, pero no tiene "
                            "metadatos suficientes para renderizarse. "
                            f"missing_metadata="
                            f"{salida.get('missing_metadata', [])!r}"
                        ),
                        correccion=(
                            "Completar la metadata de campos y la "
                            "presentación declarativa de la acción."
                        ),
                    )
                )

    return fallos


def _diagnosticar_firmas_workflows(
    *,
    vista: Any,
    acciones_backend: Dict[str, Dict[str, Any]],
) -> List[DiagnosticoAccion]:
    fallos: List[DiagnosticoAccion] = []

    for workflow_id, workflow in sorted(_workflows(vista).items()):
        pasos = workflow.get("pasos", [])

        if not isinstance(pasos, list):
            fallos.append(
                DiagnosticoAccion(
                    accion_id=f"WORKFLOW.{workflow_id}",
                    estado="WORKFLOW_PASOS_INVALIDOS",
                    origen=f"vista_user.USER_WORKFLOWS.{workflow_id}",
                    falta="'pasos' no es una lista.",
                    correccion=(
                        "Declarar el workflow con una lista de pasos "
                        "estructurados."
                    ),
                )
            )
            continue

        for paso in pasos:
            if not isinstance(paso, dict):
                continue

            accion_id = paso.get("accion_id")

            if not isinstance(accion_id, str) or not accion_id:
                fallos.append(
                    DiagnosticoAccion(
                        accion_id=f"WORKFLOW.{workflow_id}",
                        estado="WORKFLOW_SIN_ACCION",
                        origen=_ruta_origen_workflow(workflow_id, paso),
                        falta="El paso no declara accion_id.",
                        correccion=(
                            "Declarar una acción pública real para el paso."
                        ),
                    )
                )
                continue

            accion = acciones_backend.get(accion_id)

            if accion is None:
                continue

            funcion, firma, error = _firma_real(accion)

            if funcion is None or firma is None:
                continue

            parametros = {
                nombre: parametro
                for nombre, parametro in firma.parameters.items()
                if _es_parametro_real(parametro)
            }

            inputs = paso.get("inputs", {})

            if not isinstance(inputs, dict):
                fallos.append(
                    DiagnosticoAccion(
                        accion_id=accion_id,
                        estado="WORKFLOW_INPUTS_INVALIDOS",
                        origen=_ruta_origen_workflow(workflow_id, paso),
                        falta="'inputs' debe ser dict.",
                        correccion=(
                            "Declarar inputs como mapa "
                            "parametro → especificación de fuente."
                        ),
                    )
                )
                continue

            for nombre in sorted(inputs):
                if nombre not in parametros:
                    fallos.append(
                        DiagnosticoAccion(
                            accion_id=accion_id,
                            estado="WORKFLOW_PARAMETRO_INEXISTENTE",
                            origen=_ruta_origen_workflow(workflow_id, paso),
                            falta=(
                                f"El workflow declara '{nombre}', pero "
                                f"la firma real es {firma}."
                            ),
                            correccion=(
                                "Corregir vista_user. No modificar el "
                                "backend para aceptar un parámetro "
                                "inventado por la UI."
                            ),
                        )
                    )

            for nombre, parametro in sorted(parametros.items()):
                if (
                    parametro.default is inspect.Parameter.empty
                    and nombre not in inputs
                ):
                    fallos.append(
                        DiagnosticoAccion(
                            accion_id=accion_id,
                            estado=(
                                "WORKFLOW_PARAMETRO_"
                                "OBLIGATORIO_SIN_FUENTE"
                            ),
                            origen=_ruta_origen_workflow(workflow_id, paso),
                            falta=(
                                f"'{nombre}' es obligatorio en {firma} y "
                                "el workflow no declara ninguna fuente."
                            ),
                            correccion=(
                                "Declarar una fuente real USER, CONTEXT, "
                                "PREVIOUS_RESULT, CONNECTION, FIXED o "
                                "SIGNATURE_DEFAULT si existe default real."
                            ),
                        )
                    )

            for nombre, spec in sorted(inputs.items()):
                if not isinstance(spec, dict):
                    fallos.append(
                        DiagnosticoAccion(
                            accion_id=accion_id,
                            estado="WORKFLOW_INPUT_SPEC_INVALIDA",
                            origen=_ruta_origen_workflow(workflow_id, paso),
                            falta=(
                                f"El input '{nombre}' no es una "
                                "especificación dict."
                            ),
                            correccion=(
                                "Declarar source, y cuando aplique slot, "
                                "terminal o value."
                            ),
                        )
                    )
                    continue

                if (
                    spec.get("source")
                    == getattr(vista, "SIGNATURE_DEFAULT", "")
                    and nombre in parametros
                    and parametros[nombre].default
                    is inspect.Parameter.empty
                ):
                    fallos.append(
                        DiagnosticoAccion(
                            accion_id=accion_id,
                            estado=(
                                "SIGNATURE_DEFAULT_"
                                "SIN_DEFAULT_REAL"
                            ),
                            origen=_ruta_origen_workflow(workflow_id, paso),
                            falta=(
                                f"'{nombre}' usa SIGNATURE_DEFAULT, pero "
                                f"la firma real {firma} no tiene default."
                            ),
                            correccion=(
                                "Sustituir SIGNATURE_DEFAULT por una "
                                "fuente real de entrada."
                            ),
                        )
                    )

    return fallos


def _diagnosticar_connection(
    *,
    vista: Any,
    ui: Any,
) -> List[DiagnosticoAccion]:
    fallos: List[DiagnosticoAccion] = []

    try:
        conexion = importlib.import_module(
            "modules.spartaco_seguridad.conexion"
        )
    except Exception as exc:
        return [
            DiagnosticoAccion(
                accion_id="CONEXION.ejecutar",
                estado="CONEXION_NO_IMPORTABLE",
                origen="Spartaco_UI.ejecutar_paso_usuario",
                falta=f"{type(exc).__name__}: {exc}",
                correccion=(
                    "Corregir el módulo CONEXION y su empaquetado antes "
                    "de publicar workflows con source=CONNECTION."
                ),
            )
        ]

    ejecutar = getattr(conexion, "ejecutar", None)

    if not callable(ejecutar):
        fallos.append(
            DiagnosticoAccion(
                accion_id="CONEXION.ejecutar",
                estado="CONEXION_EJECUTAR_NO_DISPONIBLE",
                origen="modules.spartaco_seguridad.conexion",
                falta=(
                    "El runtime USER requiere conexion.ejecutar(), pero "
                    "el módulo no expone un callable con ese nombre."
                ),
                correccion=(
                    "Exponer conexion.ejecutar() o alinear "
                    "Spartaco_UI.ejecutar_paso_usuario con la API real "
                    "del plano causal."
                ),
            )
        )

    panel = getattr(conexion, "panel", None)

    if not callable(panel):
        fallos.append(
            DiagnosticoAccion(
                accion_id="CONEXION.panel",
                estado="CONEXION_PANEL_NO_DISPONIBLE",
                origen="modules.spartaco_seguridad.conexion",
                falta=(
                    "No existe panel() para inspeccionar la topología "
                    "causal sin ejecutar secretos."
                ),
                correccion=(
                    "Exponer panel() de solo lectura o retirar la "
                    "pretensión de auditoría topológica desde CI."
                ),
            )
        )

    for workflow_id, workflow in sorted(_workflows(vista).items()):
        for paso in workflow.get("pasos", []):
            if not isinstance(paso, dict):
                continue

            accion_id = str(paso.get("accion_id") or "")
            origen = _ruta_origen_workflow(workflow_id, paso)
            inputs = paso.get("inputs", {})

            if not isinstance(inputs, dict):
                continue

            for parametro, spec in sorted(inputs.items()):
                if not isinstance(spec, dict):
                    continue

                if spec.get("source") != getattr(vista, "CONNECTION", ""):
                    continue

                slot = spec.get("slot")
                terminal = spec.get("terminal")

                if not isinstance(slot, str) or not slot.strip():
                    fallos.append(
                        DiagnosticoAccion(
                            accion_id=accion_id,
                            estado="CONNECTION_SIN_REFERENCIA",
                            origen=origen,
                            falta=(
                                f"'{parametro}' usa CONNECTION, pero no "
                                "declara slot de referencia."
                            ),
                            correccion=(
                                "Declarar el slot del contexto que "
                                "contiene la referencia del material."
                            ),
                        )
                    )

                if (
                    not isinstance(terminal, str)
                    or not terminal.strip()
                ):
                    fallos.append(
                        DiagnosticoAccion(
                            accion_id=accion_id,
                            estado="CONNECTION_SIN_TERMINAL",
                            origen=origen,
                            falta=(
                                f"'{parametro}' usa CONNECTION desde "
                                f"slot={slot!r}, pero no declara el "
                                "terminal causal requerido por el runtime."
                            ),
                            correccion=(
                                "Declarar terminal con el dominio causal "
                                "real autorizado por CONEXION. No resolver "
                                "el secreto directamente desde la UI."
                            ),
                        )
                    )

    return fallos


def _diagnosticar_despacho_user(
    *,
    vista: Any,
    capa: Any,
    ui: Any,
    acciones_vista: Set[str],
) -> List[DiagnosticoAccion]:
    fallos: List[DiagnosticoAccion] = []

    ejecutar_accion = getattr(ui, "ejecutar_accion_usuario", None)
    ejecutar_paso = getattr(ui, "ejecutar_paso_usuario", None)
    resolver = getattr(ui, "_resolver_capacidad", None)

    if not callable(ejecutar_accion):
        fallos.append(
            DiagnosticoAccion(
                accion_id="USER.ejecutar_accion_usuario",
                estado="RUNTIME_USER_DIRECTO_AUSENTE",
                origen="Spartaco_UI",
                falta=(
                    "La UI no expone ejecutar_accion_usuario(), que es "
                    "la ruta operacional directa."
                ),
                correccion=(
                    "Exponer el dispatcher directo o retirar las "
                    "acciones directas de la vista USER."
                ),
            )
        )

    if not callable(ejecutar_paso):
        fallos.append(
            DiagnosticoAccion(
                accion_id="USER.ejecutar_paso_usuario",
                estado="RUNTIME_USER_WORKFLOW_AUSENTE",
                origen="Spartaco_UI",
                falta=(
                    "La UI no expone ejecutar_paso_usuario(), que es "
                    "la ruta operacional de workflows."
                ),
                correccion=(
                    "Exponer el dispatcher de pasos o retirar los "
                    "workflows publicados."
                ),
            )
        )

    if not callable(resolver):
        fallos.append(
            DiagnosticoAccion(
                accion_id="USER._resolver_capacidad",
                estado="RUNTIME_USER_RESOLVER_AUSENTE",
                origen="Spartaco_UI",
                falta=(
                    "No existe el resolver que conecta recurso/capacidad "
                    "con el callable público del backend."
                ),
                correccion=(
                    "Restaurar _resolver_capacidad() o declarar otro "
                    "resolver contractual y actualizar el test."
                ),
            )
        )
        return fallos

    for accion_id in sorted(acciones_vista):
        accion_ui = getattr(capa, "ACCIONES_MAP", {}).get(accion_id)

        if accion_ui is None:
            continue

        recurso_id, separador, capacidad = accion_id.partition(".")

        if not separador or not recurso_id or not capacidad:
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="ACCION_ID_INVALIDO",
                    origen="vista_user/capa_universal",
                    falta=(
                        "accion_id debe tener el formato "
                        "RECURSO.capacidad."
                    ),
                    correccion=(
                        "Corregir el identificador de acción en la UI."
                    ),
                )
            )
            continue

        disponibilidad, motivos = accion_ui.disponibilidad()

        if disponibilidad == getattr(capa, "DISP_SISTEMA", "SYSTEM_ONLY"):
            continue

        funcion_ui, error_ui = resolver(recurso_id, capacidad)

        if not callable(funcion_ui):
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="UI_NO_CONECTADA_AL_BACKEND",
                    origen="Spartaco_UI._resolver_capacidad",
                    falta=(
                        "La UI publica la acción, pero no puede resolver "
                        f"el callable backend. detalle={error_ui!r}"
                    ),
                    correccion=(
                        "Corregir el inventario SC, recurso, capacidad, "
                        "ruta del módulo o capacidades_recurso."
                    ),
                )
            )

        if disponibilidad == getattr(capa, "DISP_CONEXION", ""):
            continue

        if disponibilidad not in (
            getattr(capa, "DISP_READY", "READY"),
            getattr(capa, "DISP_ADAPTER", "NEEDS_ADAPTER"),
        ):
            fallos.append(
                DiagnosticoAccion(
                    accion_id=accion_id,
                    estado="DISPONIBILIDAD_USER_DESCONOCIDA",
                    origen="capa_universal.Accion.disponibilidad",
                    falta=(
                        f"La acción USER devuelve disponibilidad no "
                        f"reconocida: {disponibilidad!r}; motivos={motivos!r}"
                    ),
                    correccion=(
                        "Usar una disponibilidad declarada por "
                        "capa_universal."
                    ),
                )
            )

    return fallos


def _resumen(
    *,
    acciones_backend: Dict[str, Dict[str, Any]],
    acciones_catalogo: Set[str],
    acciones_vista: Set[str],
    vista: Any,
) -> Dict[str, int]:
    workflows = _workflows(vista)
    pasos = sum(
        len(workflow.get("pasos", []))
        for workflow in workflows.values()
        if isinstance(workflow.get("pasos", []), list)
    )

    n_connection = 0

    for workflow in workflows.values():
        for paso in workflow.get("pasos", []):
            if not isinstance(paso, dict):
                continue

            inputs = paso.get("inputs", {})

            if not isinstance(inputs, dict):
                continue

            n_connection += sum(
                1
                for spec in inputs.values()
                if isinstance(spec, dict)
                and spec.get("source")
                == getattr(vista, "CONNECTION", "")
            )

    return {
        "backend_capacidades": len(acciones_backend),
        "catalogo_acciones": len(acciones_catalogo),
        "user_acciones": len(acciones_vista),
        "user_workflows": len(workflows),
        "workflow_pasos": pasos,
        "workflow_connection_inputs": n_connection,
    }


def test_ui_backend_fidelidad_operativa_total() -> None:
    sc, capa, vista, ui = _cargar_modulos()

    inventario = sc.inventario()
    diagnosticos: List[DiagnosticoAccion] = []

    diagnosticos.extend(_diagnosticar_inventario(inventario))

    if not isinstance(inventario, dict):
        assert not diagnosticos, _texto_diagnosticos(
            "UI_BACKEND_NO_FIEL",
            diagnosticos,
        )
        return

    acciones_backend = _acciones_backend(inventario)
    acciones_catalogo = set(getattr(capa, "ACCIONES_MAP", {}).keys())
    acciones_vista = _acciones_vista(vista)

    diagnosticos.extend(_diagnosticar_backend(acciones_backend))

    diagnosticos.extend(
        _diagnosticar_catalogo(
            acciones_backend=set(acciones_backend),
            acciones_catalogo=acciones_catalogo,
        )
    )

    diagnosticos.extend(
        _diagnosticar_vista(
            acciones_vista=acciones_vista,
            acciones_backend=set(acciones_backend),
            acciones_catalogo=acciones_catalogo,
            capa=capa,
            vista=vista,
        )
    )

    diagnosticos.extend(
        _diagnosticar_firmas_workflows(
            vista=vista,
            acciones_backend=acciones_backend,
        )
    )

    diagnosticos.extend(
        _diagnosticar_connection(
            vista=vista,
            ui=ui,
        )
    )

    diagnosticos.extend(
        _diagnosticar_despacho_user(
            vista=vista,
            capa=capa,
            ui=ui,
            acciones_vista=acciones_vista,
        )
    )

    assert not diagnosticos, _texto_diagnosticos(
        "UI_BACKEND_NO_FIEL",
        diagnosticos,
        resumen=_resumen(
            acciones_backend=acciones_backend,
            acciones_catalogo=acciones_catalogo,
            acciones_vista=acciones_vista,
            vista=vista,
        ),
    )
