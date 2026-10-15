# =========================================================================

# SPARTACO-SECURITY — tests/test_centinela.py

# =========================================================================

#

# Supervision of core.centinela.Centinela

# Public surface of the Engine: status, registration, start_errors,

# execute_capacity.

#

# =========================================================================

from __future__ import annotations

import copy
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.centinela import (
    Centinela,
    Veredicto,
    ESTADO_APROBADO,
    ESTADO_OBSERVADO,
    ESTADO_RETENIDO,
    ESTADO_ENGINE_OPERATIVO,
    ESTADO_ENGINE_DEGRADADO,
    ESTADO_ENGINE_RECHAZADO,
    MODO_RELEVO,
    ESTADO_CENTINELA_CONTENCION,
    ESTADO_CENTINELA_RELEVO,
    PERMISOS_CANONICOS,
)


APROBADO = ESTADO_APROBADO
OBSERVADO = ESTADO_OBSERVADO
RETENIDO = ESTADO_RETENIDO
OPERATIVO = ESTADO_ENGINE_OPERATIVO
DEGRADADO = ESTADO_ENGINE_DEGRADADO
RECHAZADO = ESTADO_ENGINE_RECHAZADO

PROBE_EXEC = "__centinela_capacidad_inexistente__"


# =====================================================================
# Parte 2 — ASSERTS
# =====================================================================

def assert_true(condicion: bool, mensaje: str) -> None:
    if not condicion:
        raise AssertionError(mensaje)


def assert_equal(actual: Any, esperado: Any, mensaje: str) -> None:
    if actual != esperado:
        raise AssertionError(
            "{0}\n  esperado: {1!r}\n  actual:   {2!r}".format(
                mensaje, esperado, actual
            )
        )


def snapshot(obj: Any) -> Any:
    try:
        return copy.deepcopy(obj)
    except Exception:
        return repr(obj)


def estado_centinela(centinela: Centinela) -> Dict[str, Any]:
    bruto = centinela.estado
    if isinstance(bruto, dict):
        return dict(bruto)
    if hasattr(bruto, "a_dict"):
        return dict(bruto.a_dict())
    return {}


# =====================================================================
# Parte 3 — RESULTADO DE ATAQUE
# =====================================================================

@dataclass
class ResultadoAtaque:
    nombre: str
    objetivo: str
    esperado: str
    detectado: bool = False
    contenido: bool = False
    aislado: bool = False
    relevado: bool = False
    recuperado: bool = False
    bloqueado: bool = False
    capacidades_declaradas: List[str] = field(default_factory=list)
    capacidades_observadas: List[str] = field(default_factory=list)
    estado_antes: Any = None
    estado_despues: Any = None
    veredicto: Any = None
    errores: List[str] = field(default_factory=list)
    evidencias: List[Any] = field(default_factory=list)

    @property
    def aprobado(self) -> bool:
        requisitos = {
            "DETECTAR": self.detectado,
            "CONTENER": self.detectado and self.contenido,
            "AISLAR": self.detectado and self.contenido and self.aislado,
            "RELEVAR": self.detectado and self.contenido and self.relevado,
            "RECUPERAR": self.detectado and self.recuperado,
            "BLOQUEAR": self.detectado and self.contenido and self.bloqueado,
        }
        return requisitos.get(self.esperado, False)


# =====================================================================
# Parte 4 — REGISTRO DE EVENTOS
# =====================================================================

class EventLog:
    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def add(self, evento: str, **datos: Any) -> None:
        self.events.append(
            {"evento": evento, "timestamp": time.monotonic(), **datos}
        )

    def count(self, evento: str) -> int:
        return sum(1 for e in self.events if e.get("evento") == evento)

    def dump(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.events)


# =====================================================================
# Parte 5 — ENGINE HOSTIL
# Misma superficie que core.engine.Engine
# =====================================================================

class HostileEngine:
    def __init__(
        self,
        *,
        state: str = OPERATIVO,
        registry: Optional[Any] = None,
        log: Optional[EventLog] = None,
    ) -> None:
        self.estado = state
        self.registro = registry
        self.errores_arranque: List[str] = []
        self.log = log or EventLog()
        self.ejecuciones = 0
        self.capability_calls: List[str] = []
        self._return_success_for_unknown = False
        self._throw_on_execution = False

    def ejecutar_capacidad(
        self,
        modulo: Any,
        capacidad: str,
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        self.ejecuciones += 1
        self.capability_calls.append(str(capacidad))
        self.log.add("ENGINE_EXECUTION", modulo=modulo, capacidad=capacidad)
        if self._throw_on_execution:
            raise RuntimeError("ENGINE_CONTROLLED_EXECUTION_FAILURE")
        if self._return_success_for_unknown and capacidad == PROBE_EXEC:
            return {
                "estado": "EXITO",
                "modulo": modulo,
                "capacidad": capacidad,
                "resultado": "ATAQUE_ACEPTADO",
            }
        return {
            "estado": "ERROR",
            "modulo": modulo,
            "capacidad": capacidad,
            "error": "capacidad no autorizada",
        }

    def attack_unknown_capability_success(self) -> None:
        self._return_success_for_unknown = True
        self.log.add("ATTACK", tipo="UNKNOWN_CAPABILITY_SUCCESS")

    def attack_execution_failure(self) -> None:
        self._throw_on_execution = True
        self.log.add("ATTACK", tipo="EXECUTION_FAILURE")

    def attack_state(self, estado: str) -> None:
        self.estado = estado
        self.log.add("ATTACK", tipo="STATE_CHANGE", estado=estado)


# =====================================================================
# Parte 6 — CONTENEDOR Y REGISTRO
# =====================================================================

class FakeContainer:
    def __init__(
        self,
        *,
        nombre: str,
        rol: str,
        capacidades: Optional[Dict[str, Any]] = None,
        requiere: Optional[List[str]] = None,
        autoriza_engine: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.nombre = nombre
        self.id = "TEST-{0}".format(nombre)
        self.rol = rol
        self.version = "1.0"
        self.requiere = requiere or []
        self.autoriza_engine = autoriza_engine or {
            permiso: False for permiso in PERMISOS_CANONICOS
        }
        self.capacidades = capacidades or {}

    def fn(self, clave: str) -> Any:
        ref = self.capacidades.get(clave)
        return ref if callable(ref) else None


class FakeRegistry:
    def __init__(self, containers: Optional[List[FakeContainer]] = None) -> None:
        self.contenedores: Dict[str, FakeContainer] = {}
        self.por_id: Dict[str, FakeContainer] = {}
        self.por_rol: Dict[str, List[FakeContainer]] = {}
        for cont in containers or []:
            self.add(cont)

    def add(self, cont: FakeContainer) -> None:
        self.contenedores[cont.nombre] = cont
        self.por_id[cont.id] = cont
        self.por_rol.setdefault(cont.rol, []).append(cont)

    def total(self) -> int:
        return len(self.contenedores)


def registry_operativo(
    *,
    incluir_sc: bool = True,
    incluir_ct: bool = True,
    incluir_ui: bool = True,
) -> FakeRegistry:
    containers: List[FakeContainer] = []
    if incluir_ct:
        containers.append(
            FakeContainer(
                nombre="constante",
                rol="CT",
                capacidades={"inventario": lambda: {}},
            )
        )
    if incluir_sc:
        containers.append(
            FakeContainer(
                nombre="seguridad",
                rol="SC",
                capacidades={
                    "inventario": lambda: {},
                    "evaluar_universal": lambda **_: {"hechos": {}},
                },
                autoriza_engine={"ejecutar": True, "evaluar_universal": True},
            )
        )
    if incluir_ui:
        containers.append(
            FakeContainer(
                nombre="interfaz",
                rol="UI",
                capacidades={"inventario": lambda: {}},
            )
        )
    return FakeRegistry(containers)


def make_engine(
    *,
    state: str = OPERATIVO,
    registry: Optional[Any] = None,
    log: Optional[EventLog] = None,
) -> HostileEngine:
    return HostileEngine(
        state=state,
        registry=registry or registry_operativo(),
        log=log,
    )


# =====================================================================
# Parte 7 — ORACLE
# =====================================================================

class Oracle:
    @staticmethod
    def retained(veredicto: Any) -> bool:
        return isinstance(veredicto, Veredicto) and veredicto.estado == RETENIDO

    @staticmethod
    def observed(veredicto: Any) -> bool:
        return isinstance(veredicto, Veredicto) and veredicto.estado == OBSERVADO

    @staticmethod
    def approved(veredicto: Any) -> bool:
        return isinstance(veredicto, Veredicto) and veredicto.estado == APROBADO

    @staticmethod
    def containment_state(centinela: Centinela) -> bool:
        return estado_centinela(centinela).get("estado") == ESTADO_CENTINELA_CONTENCION

    @staticmethod
    def handover_available(centinela: Centinela) -> bool:
        return bool(estado_centinela(centinela).get("relevo_disponible"))

    @staticmethod
    def external_isolation_required(centinela: Centinela) -> bool:
        return bool(
            estado_centinela(centinela).get("aislamiento_externo_requerido")
        )


# =====================================================================
# Parte 8 — RUNNER
# =====================================================================

class AttackRunner:
    def __init__(self) -> None:
        self.resultados: List[ResultadoAtaque] = []

    def ejecutar(
        self,
        nombre: str,
        objetivo: str,
        esperado: str,
        funcion: Callable[[ResultadoAtaque], None],
    ) -> ResultadoAtaque:
        resultado = ResultadoAtaque(nombre=nombre, objetivo=objetivo, esperado=esperado)
        try:
            funcion(resultado)
        except Exception as exc:
            resultado.errores.append("{0}: {1}".format(type(exc).__name__, exc))
        self.resultados.append(resultado)
        return resultado


# =====================================================================
# Parte 9 — ATAQUES
# =====================================================================

def attack_engine_absent(resultado: ResultadoAtaque) -> None:
    centinela = Centinela(invocador=None)
    veredicto = centinela.verificar({
        "ciclo_id": "ATTACK-001",
        "estado": OPERATIVO,
    })
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.estado_despues = snapshot(estado_centinela(centinela))
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.aislado = resultado.contenido and Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_engine_rejected(resultado: ResultadoAtaque) -> None:
    log = EventLog()
    engine = make_engine(state=RECHAZADO, log=log)
    centinela = Centinela(invocador=engine)
    resultado.estado_antes = engine.estado
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-002"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.estado_despues = snapshot(estado_centinela(centinela))
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.aislado = resultado.contenido and Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(log.dump())


def attack_engine_degraded(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=DEGRADADO)
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-003"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.observed(veredicto)
    resultado.estado_despues = snapshot(estado_centinela(centinela))
    resultado.contenido = Oracle.containment_state(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_empty_registry(resultado: ResultadoAtaque) -> None:
    engine = make_engine(registry=FakeRegistry())
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-004"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.aislado = resultado.contenido and Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_missing_required_role(resultado: ResultadoAtaque) -> None:
    engine = make_engine(registry=registry_operativo(incluir_sc=False))
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-005"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.aislado = resultado.contenido and Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_missing_product_role(resultado: ResultadoAtaque) -> None:
    engine = make_engine(registry=registry_operativo(incluir_ui=False))
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-006"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.observed(veredicto)
    resultado.evidencias.append(snapshot(veredicto))


def attack_non_callable_capability(resultado: ResultadoAtaque) -> None:
    registry = FakeRegistry(
        [
            FakeContainer(
                nombre="constante",
                rol="CT",
                capacidades={"inventario": lambda: {}},
            ),
            FakeContainer(
                nombre="hostil",
                rol="SC",
                capacidades={"evaluar_universal": "NO_CALLABLE"},
                autoriza_engine={"ejecutar": True, "evaluar_universal": True},
            ),
        ]
    )
    engine = make_engine(registry=registry)
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-007"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_fake_success_unknown_capability(resultado: ResultadoAtaque) -> None:
    engine = make_engine()
    engine.attack_unknown_capability_success()
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-008"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.aislado = resultado.contenido and Oracle.external_isolation_required(centinela)
    resultado.capacidades_observadas = list(engine.capability_calls)
    resultado.evidencias.append(
        {"calls": list(engine.capability_calls), "veredicto": snapshot(veredicto)}
    )


def attack_engine_lies_about_state(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=OPERATIVO)
    engine.errores_arranque.append(RECHAZADO)
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar()
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.evidencias.append(
        {
            "estado_expuesto": engine.estado,
            "errores_arranque": list(engine.errores_arranque),
            "veredicto": snapshot(veredicto),
        }
    )


def attack_runtime_state_failure(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=OPERATIVO)
    centinela = Centinela(invocador=engine)
    engine.attack_state(RECHAZADO)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-010"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.aislado = resultado.contenido and Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_execution_failure(resultado: ResultadoAtaque) -> None:
    engine = make_engine()
    engine.attack_execution_failure()
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-011"})
    resultado.veredicto = veredicto
    resultado.detectado = isinstance(veredicto, Veredicto)
    resultado.evidencias.append(snapshot(veredicto))


def attack_explicit_containment(resultado: ResultadoAtaque) -> None:
    engine = make_engine()
    centinela = Centinela(invocador=engine)
    veredicto = centinela.contener(motivo="ATAQUE_CONTENCION")
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = Oracle.containment_state(centinela)
    resultado.aislado = Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(snapshot(estado_centinela(centinela)))


def attack_handover(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=RECHAZADO)
    centinela = Centinela(invocador=engine)
    centinela.contener(motivo="ATAQUE_RELEVO")
    relevo = centinela.relevar()
    resultado.veredicto = relevo
    resultado.detectado = Oracle.containment_state(centinela) or (
        isinstance(relevo, dict) and relevo.get("modo") == MODO_RELEVO
    )
    resultado.contenido = Oracle.containment_state(centinela) or (
        estado_centinela(centinela).get("estado") == ESTADO_CENTINELA_RELEVO
    )
    resultado.relevado = isinstance(relevo, dict) and (
        relevo.get("ejecuta_engine") is False
        or relevo.get("ejecucion_engine_autorizada") is False
    )
    if isinstance(relevo, dict) and isinstance(relevo.get("plan"), dict):
        resultado.relevado = resultado.relevado or (
            relevo["plan"].get("ejecucion_engine_autorizada") is False
        )
    resultado.aislado = Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(snapshot(relevo))


def attack_recovery_from_rejected(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=RECHAZADO)
    centinela = Centinela(invocador=engine)
    centinela.contener(motivo="ATAQUE_RECUPERACION")
    salida = centinela.recuperar_supervision()
    resultado.veredicto = salida
    if isinstance(salida, Veredicto):
        resultado.detectado = salida.estado == RETENIDO
        resultado.recuperado = salida.estado == APROBADO
    elif isinstance(salida, dict):
        resultado.detectado = salida.get("estado") == RETENIDO
        resultado.recuperado = salida.get("estado") == APROBADO
    resultado.evidencias.append(snapshot(salida))


def attack_successful_recovery(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=RECHAZADO)
    centinela = Centinela(invocador=engine)
    centinela.contener(motivo="ATAQUE_RECUPERACION_EXITOSA")
    engine.estado = OPERATIVO
    salida = centinela.recuperar_supervision()
    resultado.veredicto = salida
    if isinstance(salida, Veredicto):
        resultado.detectado = salida.estado in (APROBADO, RETENIDO, OBSERVADO)
        resultado.recuperado = salida.estado == APROBADO
    elif isinstance(salida, dict):
        estado = salida.get("estado")
        resultado.detectado = estado in (APROBADO, RETENIDO, OBSERVADO)
        resultado.recuperado = estado == APROBADO
    resultado.evidencias.append(snapshot(salida))


def attack_package_retained(resultado: ResultadoAtaque) -> None:
    centinela = Centinela(invocador=None)
    veredicto = centinela.verificar(
        {
            "ciclo_id": "ATTACK-016",
            "estado": RETENIDO,
            "motivos": ["PAQUETE_MANIPULADO"],
        }
    )
    resultado.veredicto = veredicto
    resultado.detectado = isinstance(veredicto, Veredicto) and veredicto.estado == RETENIDO
    resultado.evidencias.append(snapshot(veredicto))


def attack_observed_package_cannot_promote(resultado: ResultadoAtaque) -> None:
    centinela = Centinela(invocador=None)
    veredicto = centinela.verificar(
        {
            "ciclo_id": "ATTACK-017",
            "estado": OBSERVADO,
            "motivos": ["CONDICION_ADVERSARIAL"],
        }
    )
    resultado.veredicto = veredicto
    resultado.detectado = isinstance(veredicto, Veredicto) and veredicto.estado != APROBADO
    resultado.evidencias.append(snapshot(veredicto))


def attack_repeatability(resultado: ResultadoAtaque) -> None:
    engine = make_engine()
    centinela = Centinela(invocador=engine)
    paquete = {"ciclo_id": "ATTACK-018"}
    v1 = centinela.verificar(paquete, depositar_salida=False)
    v2 = centinela.verificar(paquete, depositar_salida=False)
    resultado.veredicto = {"v1": snapshot(v1), "v2": snapshot(v2)}
    resultado.detectado = v1.estado == v2.estado
    resultado.evidencias.append({"estado_1": v1.estado, "estado_2": v2.estado})


def attack_execution_after_containment(resultado: ResultadoAtaque) -> None:
    log = EventLog()
    engine = make_engine(log=log)
    centinela = Centinela(invocador=engine)
    centinela.contener(motivo="ATAQUE_POST_CONTENCION")
    ejecuciones_antes = engine.ejecuciones
    try:
        engine.ejecutar_capacidad("seguridad", "inventario")
    except Exception:
        pass
    ejecuciones_despues = engine.ejecuciones
    resultado.detectado = True
    resultado.contenido = Oracle.containment_state(centinela)
    resultado.bloqueado = Oracle.external_isolation_required(centinela)
    resultado.evidencias.append(
        {
            "ejecuciones_antes": ejecuciones_antes,
            "ejecuciones_despues": ejecuciones_despues,
            "aislamiento_externo": Oracle.external_isolation_required(centinela),
            "eventos": log.dump(),
        }
    )


class SideEffectContainer(FakeContainer):
    def __init__(self, *, log: EventLog) -> None:
        self.side_effect_log = log
        super().__init__(
            nombre="hostil",
            rol="SC",
            capacidades={"evaluar_universal": self.evaluar},
            autoriza_engine={"ejecutar": True, "evaluar_universal": True},
        )

    def evaluar(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        self.side_effect_log.add("HOSTILE_CAPABILITY_EXECUTED")
        return {"hechos": {}}

    def fn(self, clave: str) -> Any:
        self.side_effect_log.add("HOSTILE_FN_RESOLUTION", capacidad=clave)
        return super().fn(clave)


def attack_hostile_capability_side_effect(resultado: ResultadoAtaque) -> None:
    log = EventLog()
    registry = FakeRegistry(
        [
            FakeContainer(
                nombre="constante",
                rol="CT",
                capacidades={"inventario": lambda: {}},
            ),
            SideEffectContainer(log=log),
        ]
    )
    engine = make_engine(registry=registry, log=log)
    centinela = Centinela(invocador=engine)
    before = log.count("HOSTILE_CAPABILITY_EXECUTED")
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-020"})
    after = log.count("HOSTILE_CAPABILITY_EXECUTED")
    resultado.veredicto = veredicto
    resultado.detectado = after == before
    resultado.evidencias.append(
        {
            "hostile_execution_before": before,
            "hostile_execution_after": after,
            "events": log.dump(),
            "veredicto": snapshot(veredicto),
        }
    )


def attack_missing_dependency(resultado: ResultadoAtaque) -> None:
    registry = FakeRegistry(
        [
            FakeContainer(
                nombre="constante",
                rol="CT",
                capacidades={"inventario": lambda: {}},
            ),
            FakeContainer(
                nombre="seguridad",
                rol="SC",
                capacidades={"inventario": lambda: {}},
                requiere=["MODULO_INEXISTENTE"],
                autoriza_engine={"ejecutar": True},
            ),
        ]
    )
    engine = make_engine(registry=registry)
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-021"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto) or Oracle.observed(veredicto)
    resultado.evidencias.append(snapshot(veredicto))


def attack_unknown_permission(resultado: ResultadoAtaque) -> None:
    registry = FakeRegistry(
        [
            FakeContainer(
                nombre="constante",
                rol="CT",
                capacidades={"inventario": lambda: {}},
            ),
            FakeContainer(
                nombre="hostil",
                rol="SC",
                capacidades={"evaluar_universal": lambda **_: {"hechos": {}}},
                autoriza_engine={"ejecutar": True, "PERMISO_INVENTADO": True},
            ),
        ]
    )
    engine = make_engine(registry=registry)
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-022"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto) or Oracle.observed(veredicto)
    resultado.evidencias.append(snapshot(veredicto))


def attack_unknown_engine_state(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state="ESTADO_QUE_NO_EXISTE")
    centinela = Centinela(invocador=engine)
    veredicto = centinela.verificar({"ciclo_id": "ATTACK-023"})
    resultado.veredicto = veredicto
    resultado.detectado = Oracle.retained(veredicto)
    resultado.contenido = resultado.detectado and Oracle.containment_state(centinela)
    resultado.evidencias.append(snapshot(veredicto))


def attack_recovery_cannot_force_authorization(resultado: ResultadoAtaque) -> None:
    engine = make_engine(state=RECHAZADO)
    centinela = Centinela(invocador=engine)
    centinela.contener(motivo="NO_AUTORIZAR_RECUPERACION")
    salida = centinela.preparar_recuperacion()
    resultado.veredicto = salida
    if isinstance(salida, dict):
        resultado.detectado = salida.get("autorizacion_automatica") is False
        resultado.recuperado = False
    resultado.evidencias.append(snapshot(salida))


# =====================================================================
# Parte 10 — BATERÍA
# =====================================================================

def run_all_attacks() -> AttackRunner:
    runner = AttackRunner()
    runner.ejecutar("engine_absent", "ausencia del Engine", "CONTENER", attack_engine_absent)
    runner.ejecutar("engine_rejected", "Engine RECHAZADO", "CONTENER", attack_engine_rejected)
    runner.ejecutar("engine_degraded", "Engine DEGRADADO", "DETECTAR", attack_engine_degraded)
    runner.ejecutar("empty_registry", "registro vacío", "CONTENER", attack_empty_registry)
    runner.ejecutar("missing_required_role", "rol obligatorio ausente", "CONTENER", attack_missing_required_role)
    runner.ejecutar("missing_product_role", "rol de producto ausente", "DETECTAR", attack_missing_product_role)
    runner.ejecutar("non_callable_capability", "capacidad no callable", "CONTENER", attack_non_callable_capability)
    runner.ejecutar("fake_success_unknown_capability", "capacidad inexistente aceptada", "CONTENER", attack_fake_success_unknown_capability)
    runner.ejecutar("engine_lies_about_state", "OPERATIVO con errores de arranque", "CONTENER", attack_engine_lies_about_state)
    runner.ejecutar("runtime_state_failure", "Engine pasa a RECHAZADO", "CONTENER", attack_runtime_state_failure)
    runner.ejecutar("execution_failure", "fallo durante sonda", "DETECTAR", attack_execution_failure)
    runner.ejecutar("explicit_containment", "contención explícita", "AISLAR", attack_explicit_containment)
    runner.ejecutar("handover", "preparación de relevo", "RELEVAR", attack_handover)
    runner.ejecutar("recovery_rejected_engine", "recuperación con Engine rechazado", "DETECTAR", attack_recovery_from_rejected)
    runner.ejecutar("successful_recovery", "recuperación tras restaurar", "RECUPERAR", attack_successful_recovery)
    runner.ejecutar("retained_package", "paquete RETENIDO", "DETECTAR", attack_package_retained)
    runner.ejecutar("observed_package_cannot_promote", "paquete OBSERVADO no promociona", "DETECTAR", attack_observed_package_cannot_promote)
    runner.ejecutar("repeatability", "repetibilidad del veredicto", "DETECTAR", attack_repeatability)
    runner.ejecutar("execution_after_containment", "ejecución tras contención", "BLOQUEAR", attack_execution_after_containment)
    runner.ejecutar("hostile_capability_side_effect", "side effect en inspección", "DETECTAR", attack_hostile_capability_side_effect)
    runner.ejecutar("missing_dependency", "dependencia inexistente", "DETECTAR", attack_missing_dependency)
    runner.ejecutar("unknown_permission", "permiso no canónico", "DETECTAR", attack_unknown_permission)
    runner.ejecutar("unknown_engine_state", "estado de Engine desconocido", "CONTENER", attack_unknown_engine_state)
    runner.ejecutar("recovery_cannot_force_authorization", "recuperación no autoautoriza", "DETECTAR", attack_recovery_cannot_force_authorization)
    return runner


# =====================================================================
# Parte 11 — INFORME
# =====================================================================

def build_report(runner: AttackRunner) -> Dict[str, Any]:
    total = len(runner.resultados)
    passed = sum(1 for r in runner.resultados if r.aprobado)
    failed = total - passed
    return {
        "test": "CENTINELA_SUPERVISION",
        "version": "2.0",
        "total_ataques": total,
        "pass": passed,
        "fail": failed,
        "porcentaje": round((passed / total) * 100, 2) if total else 0.0,
        "resultado_global": "PASS" if failed == 0 else "FAIL",
        "ataques": [
            {
                "nombre": r.nombre,
                "objetivo": r.objetivo,
                "esperado": r.esperado,
                "pass": r.aprobado,
                "detectado": r.detectado,
                "contenido": r.contenido,
                "aislado": r.aislado,
                "relevado": r.relevado,
                "recuperado": r.recuperado,
                "bloqueado": r.bloqueado,
                "estado_antes": r.estado_antes,
                "estado_despues": r.estado_despues,
                "veredicto": repr(r.veredicto),
                "errores": list(r.errores),
                "evidencias": snapshot(r.evidencias),
            }
            for r in runner.resultados
        ],
    }


def print_report(report: Dict[str, Any]) -> None:
    print()
    print("=" * 78)
    print("SPARTACO-SECURITY — CENTINELA")
    print("=" * 78)
    print("ATAQUES : {0}".format(report["total_ataques"]))
    print("PASS    : {0}".format(report["pass"]))
    print("FAIL    : {0}".format(report["fail"]))
    print("TOTAL   : {0}%".format(report["porcentaje"]))
    print("GLOBAL  : {0}".format(report["resultado_global"]))
    print("-" * 78)
    for ataque in report["ataques"]:
        marca = "PASS" if ataque["pass"] else "FAIL"
        print("[{0}] {1}".format(marca, ataque["nombre"]))
        print(
            "       esperado={0} detectado={1} contenido={2} aislado={3} "
            "relevado={4} recuperado={5} bloqueado={6}".format(
                ataque["esperado"],
                ataque["detectado"],
                ataque["contenido"],
                ataque["aislado"],
                ataque["relevado"],
                ataque["recuperado"],
                ataque["bloqueado"],
            )
        )
        for error in ataque["errores"]:
            print("       ERROR: {0}".format(error))
    print("=" * 78)
    print()


# =====================================================================
# Parte 12 — PYTEST
# =====================================================================

def test_centinela_supervision() -> None:
    runner = run_all_attacks()
    report = build_report(runner)
    print_report(report)
    assert_equal(
        report["resultado_global"],
        "PASS",
        "CENTINELA NO SUPERÓ LA BATERÍA. Revisar el informe de cada ataque.",
    )


def test_centinela_no_puede_autodeclararse_exitoso() -> None:
    runner = run_all_attacks()
    for resultado in runner.resultados:
        if resultado.veredicto is None:
            continue
        if (
            resultado.contenido
            and not resultado.bloqueado
            and resultado.esperado == "BLOQUEAR"
        ):
            raise AssertionError(
                "{0}: declaró contención y no hay aislamiento_externo_requerido".format(
                    resultado.nombre
                )
            )


def test_centinela_recovery_is_not_magic() -> None:
    engine = make_engine(state=RECHAZADO)
    centinela = Centinela(invocador=engine)
    centinela.contener(motivo="RECOVERY_NEGADO")
    salida = centinela.recuperar_supervision()
    if isinstance(salida, Veredicto):
        assert_true(
            salida.estado != APROBADO,
            "Centinela aprobó un Engine que seguía RECHAZADO.",
        )


# =====================================================================
# Parte 13 — EJECUCIÓN DIRECTA
# =====================================================================

if __name__ == "__main__":
    runner = run_all_attacks()
    report = build_report(runner)
    print_report(report)
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    raise SystemExit(0 if report["resultado_global"] == "PASS" else 1)
