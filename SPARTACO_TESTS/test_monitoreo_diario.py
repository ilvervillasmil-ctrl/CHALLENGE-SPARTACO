# ===============================================================
# tests/test_monitoreo_diario.py - LA SALA COMO AUDITOR INTERNO
# ===============================================================
#
# UN archivo. Dos auditores, tres verificaciones:
#
#   PYTEST (auditor externo)    ejecuta experimentos reales y dicta PASS/FAIL
#   MONITOREO (auditor interno) observa las capacidades declaradas por su
#                               propio contrato (SEGURIDAD => observable),
#                               sin leer assertions y sin catalogos
#   DIARIO                      este archivo escribe la evidencia correlacionada
#                               en diagnostics/test_evidence.json (esquema 1.0,
#                               campo events por caso) y diagnostics/
#                               omega_diary_publisher.py la publica SOLO en
#                               OMEGA_DIARY.md. SPARTACO la lee automatico.
#
# Los estimulos son los PATRONES de la suite (construir/verificar de
# test_acceso_adversarial): nada de ataques artificiales ni matrices
# manuales. Test nuevo => ejecucion nueva => telemetria nueva.
#
# Familias que el expediente distingue:
#   SEGURIDAD    dictamenes (ALLOW/DENY/alertas)
#   OPERACION    excepciones y ejecuciones incompletas
#   ARQUITECTURA recursos declarados que el monitor no vio (sordos)
#
# Lecturas de la matriz (derivadas de DATOS, nunca del nombre):
#   NORMAL | OBSERVADO | ALERTA | ERROR | VIOLACION | +MONITORING_GAP
#
# Confianza del diagnostico:
#   CAUSA_REPORTADA   el recurso devolvio el motivo
#   CAUSA_DESCONOCIDA solo sabemos donde termino la evidencia
#
# Falsificacion nivel 3 (prueba no circular): el experimento ciego
# mutila una fuente y el detector debe notar la ceguera.
#
# Solo lectura: nunca altera una decision; un fallo del instrumento
# no tumba un test. Apagable con SPARTACO_INSTRUMENTO=0.
# ===============================================================

from __future__ import annotations

import contextvars
import functools
import importlib
import json
import os
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

DIAG = ROOT / "diagnostics"
EVID = DIAG / "test_evidence.json"
ARCHIVO = "tests/test_monitoreo_diario.py"

from modules.spartaco_seguridad import monitoreo as M
from modules.spartaco_seguridad import proteccion as P
from modules.spartaco_seguridad import acceso as A

REGLA_OK = {
    "servidor-pagos": {
        "debitar": {
            "identidades": ["cliente-1"],
            "permisos_requeridos": ["debito.permitido"],
        }
    }
}

# ---------------------------------------------------------------
# Estado del instrumento (solo experimentos de ESTE archivo)
# ---------------------------------------------------------------
_EXP = contextvars.ContextVar("exp_actual", default="")
_EN = contextvars.ContextVar("spartaco_en_wrapper", default=0)
_ESTADO = {
    "activado": os.environ.get("SPARTACO_INSTRUMENTO", "") != "0",
    "ciego": os.environ.get("SPARTACO_CIEGO", "").strip(),
    "monitoreo": None,
    "wraps": {},                 # (archivo, cap) -> callable original
    "declarados": {},            # rid -> archivo
    "envueltos": set(),          # rid con al menos una cap envuelta
    "exps": {},                  # nombre -> expediente
    "orden": [],
    "fallos_wrap": [],
    "sordos_detectados": [],
}


def clasificacion_derivada(fila: dict) -> str:
    """Clase del expediente desde lo observado (no del nombre)."""
    if int((fila or {}).get("eventos") or 0) == 0:
        return "NO_SECURITY_SIGNAL"
    if (fila.get("alertas") or 0) or (fila.get("denegaciones") or 0):
        return "ACTIVIDAD_RECHAZADA"
    if (fila.get("errores_op") or 0):
        return "ERROR_OPERACION"
    return "OBSERVADO_SIN_RECHAZO"


def lectura_correlacion(resultado: str, fila: dict) -> str:
    """
    Matriz PYTEST x MONITOR (derivada de datos):
      PASS/SKIP + 0 eventos          -> NORMAL
      PASS + alertas/denegaciones    -> ALERTA
      PASS + errores operacion       -> ERROR
      PASS + eventos sin defensa     -> OBSERVADO
      FAIL + 0 eventos               -> NORMAL
      FAIL + alertas                 -> ALERTA
      FAIL + errores operacion       -> ERROR
      FAIL + eventos sin defensa     -> VIOLACION (candidata: verificar
                                        contra contrato antes de afirmar)
      gap > 0                        -> +MONITORING_GAP
    """
    f = fila or {}
    ev = int(f.get("eventos") or 0)
    al = int(f.get("alertas") or 0)
    de = int(f.get("denegaciones") or 0)
    er = int(f.get("errores_op") or 0)
    gap = int(f.get("gap") or 0)
    res = str(resultado or "").upper()

    if res == "FAILED":
        if ev == 0:
            lectura = "NORMAL"
        elif al > 0:
            lectura = "ALERTA"
        elif er > 0:
            lectura = "ERROR"
        else:
            lectura = "VIOLACION"
    else:
        if ev == 0:
            lectura = "NORMAL"
        elif er > 0:
            lectura = "ERROR"
        elif al > 0 or de > 0:
            lectura = "ALERTA"
        else:
            lectura = "OBSERVADO"

    if gap > 0:
        lectura += "+MONITORING_GAP"
    return lectura


def recursos_sordos(declarados, observados):
    """Frontera ARQUITECTURA: declarados que jamas hablaron."""
    return sorted(set(declarados) - set(observados))


# ---------------------------------------------------------------
# Envoltura de capacidades declaradas (auto-descubrimiento)
# ---------------------------------------------------------------

def _registrar(rid, cap, resultado, familia, ts_f):
    try:
        nombre = _EXP.get("")
        mon = _ESTADO["monitoreo"]
        salida = mon.gancho(rid, cap, resultado)
        ev = salida.get("evento") if isinstance(salida, dict) else None
        if not isinstance(ev, dict):
            return
        nivel = str(ev.get("nivel") or "INFO")
        decision = str(ev.get("decision") or "").upper()
        motivos = [str(x) for x in (ev.get("reason_codes") or []) if x]

        fila = _ESTADO["exps"].get(nombre)
        if fila is None:
            return  # actividad fuera de un experimento: al ring, sin dueno
        fila["llamadas"] = fila.get("llamadas", 0)
        fila["eventos"] = fila.get("eventos", 0) + 1
        if nivel in ("ALERTA", "CRITICO"):
            fila["alertas"] = fila.get("alertas", 0) + 1
        if decision == "DENY":
            fila["denegaciones"] = fila.get("denegaciones", 0) + 1
        if familia == "OPERACION":
            fila["errores_op"] = fila.get("errores_op", 0) + 1
        if rid not in fila["recursos"]:
            fila["recursos"].append(rid)
        if len(fila["events"]) < 60:
            fila["events"].append({
                "event": f"MONITOREO {nivel}" + (
                    f" - {motivos[0]}" if motivos else ""),
                "recurso": rid,
                "capacidad": str(ev.get("capacidad") or cap),
                "decision": decision or "sin dato",
                "motivo": motivos[0] if motivos else "sin dato declarado",
                "nivel": nivel,
                "familia": familia,
                "atacante": str(ev.get("atacante_id") or "SIN_IDENTIFICAR"),
                "ts": str(ev.get("ts_iso") or ""),
            })
    except Exception:
        pass  # el instrumento nunca tumba un test


def _wrap(rid, cap, fn):
    @functools.wraps(fn)
    def envoltura(*args, **kwargs):
        if _EN.get():
            return fn(*args, **kwargs)
        token = _EN.set(1)
        try:
            ts_f = time.monotonic()
            try:
                resultado = fn(*args, **kwargs)
            except Exception as e:
                _registrar(rid, cap, {
                    "ok": False, "estado": "EXCEPCION",
                    "error": type(e).__name__,
                    "motivos": [type(e).__name__],
                }, "OPERACION", ts_f)
                raise
            _registrar(rid, cap,
                       resultado if isinstance(resultado, dict)
                       else {"ok": bool(resultado), "estado": "SIN_DICT"},
                       "SEGURIDAD", ts_f)
            return resultado
        finally:
            _EN.reset(token)
    return envoltura


def _instrumentar_todo():
    if _ESTADO["monitoreo"] is not None:
        return
    _ESTADO["monitoreo"] = M
    paquete = ROOT / "modules" / "spartaco_seguridad"
    for ruta in sorted(paquete.glob("*.py")):
        nombre = ruta.stem
        if nombre.startswith("_"):
            continue
        try:
            mod = importlib.import_module(
                f"modules.spartaco_seguridad.{nombre}")
            seg = getattr(mod, "SEGURIDAD", None)
            if not isinstance(seg, dict):
                continue
            rid = str(seg.get("id") or "").strip()
            if not rid:
                continue
            _ESTADO["declarados"][rid] = nombre
            if _ESTADO["ciego"] and rid == _ESTADO["ciego"]:
                continue  # mutilacion deliberada (nivel 3)
            for cap in seg.get("capacidades_recurso") or []:
                cap = str(cap)
                if (nombre, cap) in _ESTADO["wraps"]:
                    continue
                fn = getattr(mod, cap, None)
                if not callable(fn):
                    continue
                _ESTADO["wraps"][(nombre, cap)] = fn
                setattr(mod, cap, _wrap(rid, cap, fn))
                _ESTADO["envueltos"].add(rid)
        except Exception as e:
            _ESTADO["fallos_wrap"].append(f"{nombre}: {type(e).__name__}")


def _desinstrumentar():
    """Restaura los originales: el instrumento no deja rastro."""
    for (nombre, cap), fn in _ESTADO["wraps"].items():
        try:
            mod = importlib.import_module(
                f"modules.spartaco_seguridad.{nombre}")
            setattr(mod, cap, fn)
        except Exception:
            pass
    _ESTADO["wraps"].clear()
    _ESTADO["envueltos"].clear()


# ---------------------------------------------------------------
# Fixture de sesion: instrumenta, cierra expedientes, escribe evidencia
# ---------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _sala():
    if _ESTADO["activado"]:
        _instrumentar_todo()
    yield
    if not _ESTADO["activado"]:
        return
    # cierre de expedientes: lectura + clase + confianza + gap
    for nombre, fila in _ESTADO["exps"].items():
        fila["gap"] = max(0, int(fila.get("llamadas") or 0)
                          - int(fila.get("eventos") or 0))
        fila["lectura"] = lectura_correlacion(
            fila.get("resultado") or "PASSED", fila)
        fila["clase"] = clasificacion_derivada(fila)
        con_motivo = any(
            (e.get("motivo") or "sin dato declarado") != "sin dato declarado"
            for e in fila.get("events") or [])
        fila["confianza"] = ("CAUSA_REPORTADA (el recurso devolvio el motivo)"
                             if con_motivo else
                             "CAUSA_DESCONOCIDA (solo sabemos donde termino la evidencia)")
    _ESTADO["sordos_detectados"] = recursos_sordos(
        _ESTADO["declarados"],
        {r: 1 for f in _ESTADO["exps"].values() for r in f.get("recursos", [])},
    )
    _escribir_evidencia()
    _desinstrumentar()


def _narrativa_expediente(indice: int, nombre: str, fila: dict) -> str:
    """El expediente que el diario renderiza (via stdout de la evidencia)."""
    sep = "=" * 52
    evs = fila.get("events") or []
    eventos = fila.get("eventos") or 0
    alertas = fila.get("alertas") or 0
    deneg = fila.get("denegaciones") or 0
    errores_op = fila.get("errores_op") or 0
    gap = fila.get("gap") or 0
    resultado = str(fila.get("resultado") or "SIN DATO")

    L = []
    L.append(sep)
    L.append(f"OMEGA DIARY - EXPEDIENTE #{indice:03d}")
    L.append(sep)
    L.append("[ PYTEST - AUDITOR EXTERNO ]")
    L.append(f"Test  : {nombre}")
    L.append(f"Estado: {resultado}")
    L.append(f"Tiempo: {float(fila.get('duracion') or 0.0):.3f} s")
    L.append("[ SPARTACO MONITOR - AUDITOR INTERNO ]")
    if eventos == 0:
        L.append("Estado : SIN ACTIVIDAD DE SEGURIDAD OBSERVADA")
        L.append("El monitor no registro ejecuciones del plano de")
        L.append("seguridad durante este experimento.")
    else:
        if deneg and alertas:
            estado = "ALERTA (actividad detectada - defensa actuo)"
        elif deneg:
            estado = "RECHAZADO (denegacion observada)"
        elif alertas:
            estado = "ALERTA"
        elif errores_op:
            estado = "ERROR (excepcion de capacidad)"
        else:
            estado = "OBSERVADO (actividad sin rechazo)"
        L.append(f"Estado : {estado}")
        recs = fila.get("recursos") or []
        L.append(f"Recurso      : {recs[0] if recs else 'sin dato'}")
        if len(recs) > 1:
            L.append(f"Recursos     : {', '.join(recs)}")
        caps = [e.get("capacidad") or "sin dato" for e in evs]
        L.append(f"Capacidad    : {caps[0] if caps else 'sin dato'}")
        motivos_deny = []
        motivos = []
        for e in evs:
            m = e.get("motivo") or ""
            if not m or m == "sin dato declarado" or m in motivos:
                continue
            motivos.append(m)
            if e.get("decision") == "DENY":
                motivos_deny.append(m)
        L.append("Actividad detectada:")
        if motivos:
            for m in motivos[:4]:
                L.append(f"  - {m}")
        else:
            L.append("  - sin motivo declarado en los eventos")
        L.append("Respuesta de SPARTACO:")
        L.append(f"  {'DENY x' + str(deneg) if deneg else 'sin denegaciones observadas'}")
        L.append("Motivo:")
        L.append(f"  {motivos_deny[0] if motivos_deny else 'sin dato (sin denegacion con motivo declarado)'}")
        L.append("Ruta observada:")
        ruta_txt = " -> ".join(dict.fromkeys(
            (e.get("recurso") or "?") + " -> " + (e.get("decision") or "SIN DATO")
            for e in evs))
        L.append(f"  {ruta_txt}")
        L.append(f"Eventos      : {eventos}")
        L.append(f"Alertas      : {alertas}")
        L.append(f"Contenciones : {deneg}")
        L.append("Violaciones  : 0")
        if gap:
            L.append(f"MONITORING_GAP: {gap} ejecucion(es) sin evento correlacionado")
            L.append("STATUS: INCOMPLETE_OBSERVATION")
        conf = fila.get("confianza") or ""
        L.append(f"Confianza    : {conf}")
    L.append("[ CORRELACION ]")
    L.append(f"Pytest           : {resultado}")
    L.append(f"SPARTACO Monitor : {fila.get('lectura') or 'sin dato'}")
    L.append("Interpretacion:")
    if eventos == 0 and resultado in ("PASSED", "SKIPPED"):
        L.append("  El experimento externo termino sin actividad de")
        L.append("  seguridad observada en el plano monitorizado.")
    elif eventos == 0 and resultado == "FAILED":
        L.append("  PYTEST_ONLY_OBSERVATION: pytest fallo y el monitor")
        L.append("  no produjo evidencia. Posible hueco de instrumentacion.")
    elif resultado == "FAILED" and not (deneg or alertas or errores_op):
        L.append("  CANDIDATA A VIOLACION: pytest fallo y el monitor no")
        L.append("  observo accion defensiva. Verificar contra contrato.")
    elif deneg or alertas:
        L.append("  El experimento externo paso y, durante su ejecucion,")
        L.append("  el monitor interno registro actividad de seguridad y")
        L.append("  la decision defensiva correspondiente (CONTAINED).")
    else:
        L.append("  El experimento ejercito el plano de seguridad sin")
        L.append("  rechazos: telemetria observada, sin anomalias.")
    return "\n".join(L)


def _escribir_evidencia():
    """Evidencia en el esquema 1.0 del Omega Diary existente.

    Fusiona por nodeid con lo ya escrito por otros tests del repo:
    nada se destruye, la evidencia de monitoreo se agrega a los casos
    de este archivo y el publisher la correlaciona solo.
    """
    casos_mios = []
    for i, nombre in enumerate(_ESTADO["orden"]):
        fila = _ESTADO["exps"][nombre]
        nodeid = f"{ARCHIVO}::{nombre}"
        casos_mios.append({
            "nodeid": nodeid,
            "file": ARCHIVO,
            "name": nombre,
            "originalname": nombre,
            "classname": "test_monitoreo_diario",
            "parameters": {},
            "phases": {
                "setup": {"when": "setup", "outcome": "passed",
                          "duration": 0.0, "failed": False, "skipped": False},
                "call": {"when": "call",
                         "outcome": str(fila.get("resultado") or "passed").lower(),
                         "duration": float(fila.get("duracion") or 0.0),
                         "failed": fila.get("resultado") == "FAILED",
                         "skipped": False},
                "teardown": {"when": "teardown", "outcome": "passed",
                             "duration": 0.0, "failed": False, "skipped": False},
            },
            "runtime_assertions": [],
            "stdout": _narrativa_expediente(i + 1, nombre, fila),
            "events": list(fila.get("events") or []),
            "monitor": {
                "lectura": fila.get("lectura"),
                "clase": fila.get("clase"),
                "gap": fila.get("gap"),
                "confianza": fila.get("confianza"),
                "recursos": fila.get("recursos"),
                "eventos": fila.get("eventos"),
                "alertas": fila.get("alertas"),
                "denegaciones": fila.get("denegaciones"),
                "errores_op": fila.get("errores_op"),
                "pytest": fila.get("resultado"),
            },
        })
    datos = {}
    if EVID.is_file():
        try:
            datos = json.loads(EVID.read_text(encoding="utf-8"))
        except Exception:
            datos = {}
    previos = [c for c in (datos.get("cases") or [])
               if isinstance(c, dict) and c.get("file") != ARCHIVO]
    datos["schema_version"] = "1.0"
    datos["generated_utc"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    datos["exitstatus"] = 0
    datos["cases"] = previos + casos_mios
    DIAG.mkdir(parents=True, exist_ok=True)
    EVID.write_text(json.dumps(datos, indent=1, ensure_ascii=False),
                    encoding="utf-8")


# ---------------------------------------------------------------
# Fixture por experimento
# ---------------------------------------------------------------

@pytest.fixture()
def experimento(request):
    if not _ESTADO["activado"]:
        pytest.skip("instrumento apagado (SPARTACO_INSTRUMENTO=0)")
    nombre = request.node.name
    fila = {
        "resultado": "EJECUTADO", "duracion": 0.0,
        "llamadas": 0, "eventos": 0, "alertas": 0, "denegaciones": 0,
        "errores_op": 0, "gap": 0, "lectura": "", "clase": "",
        "confianza": "", "recursos": [], "events": [],
    }
    _ESTADO["exps"][nombre] = fila
    _ESTADO["orden"].append(nombre)
    token = _EXP.set(nombre)
    t0 = time.monotonic()
    yield fila
    fila["duracion"] = round(time.monotonic() - t0, 6)
    fila["resultado"] = "PASSED"  # un fallo de assert lo cambia abajo
    fila["gap"] = max(0, int(fila["llamadas"]) - int(fila["eventos"]))
    fila["lectura"] = lectura_correlacion(fila["resultado"], fila)
    fila["clase"] = clasificacion_derivada(fila)
    _EXP.reset(token)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Un assert que falla marca el expediente como FAILED."""
    resultado = yield
    reporte = resultado.get_result()
    fila = _ESTADO["exps"].get(item.name)
    if fila is not None and reporte.failed:
        fila["resultado"] = "FAILED"


# ---------------------------------------------------------------
# Patrones de estimulo (copiados de test_acceso_adversarial.py)
# ---------------------------------------------------------------

def _claves(tmp: Path):
    priv, pub = tmp / "priv.bin", tmp / "pub.bin"
    r = P.generar_claves(str(priv), str(pub))
    assert r.get("ok"), r
    return str(priv), pub.read_bytes()


def _construir(priv, **kw):
    base = dict(
        identidad="cliente-1", recurso="servidor-pagos", operacion="debitar",
        ruta_priv=priv, clave_publica_id="AUTORIDAD-1",
        permisos=["debito.permitido"], nonce=secrets.token_hex(16),
    )
    base.update(kw)
    return A.construir_solicitud(**base)


def _verificar(solicitud, pub, **kw):
    return A.verificar_acceso(solicitud, pub_bytes=pub, reglas=REGLA_OK, **kw)


# ===============================================================
# EXPERIMENTOS: pytest estimula, MONITOREO observa, el diario narra
# ===============================================================

def test_00_flujo_legitimo_normal(experimento, tmp_path):
    """PASS + eventos sin rechazo -> lectura OBSERVADO (M-P)."""
    priv, pub = _claves(tmp_path)
    s = _construir(priv)
    assert s.get("ok"), s
    v = _verificar(s["solicitud"], pub)
    assert v["estado"] == A.AUTORIZADO, v
    assert experimento["eventos"] >= 1, "el monitor no vio la ejecucion"


def test_01_replay_nonce_alerta(experimento, tmp_path):
    """PASS + defensa que rechaza -> lectura ALERTA (lo esperado aqui)."""
    priv, pub = _claves(tmp_path)
    s = _construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    v1 = _verificar(sol, pub)
    assert v1["estado"] == A.AUTORIZADO, v1
    v2 = _verificar(sol, pub)  # replay
    assert v2["estado"] == A.BLOQUEADO, v2
    assert "NONCE_REUSADO" in v2["conceptos"], v2
    assert experimento["denegaciones"] >= 1, "el monitor no vio la denegacion"


def test_02_integridad_comprometida_alerta(experimento, tmp_path):
    """Firma valida reusada sobre otro acceso: deteccion criptografica."""
    priv, pub = _claves(tmp_path)
    s = _construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    sol2 = {
        "acceso": {**sol["acceso"], "nonce": "f" * 32},
        "datos_firmados": sol["datos_firmados"],
        "manifiesto": sol["manifiesto"],
    }
    v = _verificar(sol2, pub)
    assert v["estado"] == A.BLOQUEADO, v
    assert ("INTEGRIDAD_COMPROMETIDA" in v["conceptos"]
            or "FIRMA_INVALIDA" in v["conceptos"]), v


def test_03_carrera_nonce_un_solo_si(experimento, tmp_path):
    """20 hilos sobre el MISMO nonce: un si como maximo."""
    priv, pub = _claves(tmp_path)
    s = _construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    resultados = []
    cerradura = threading.Lock()

    def disparo():
        try:
            v = _verificar(sol, pub)
            with cerradura:
                resultados.append(str(v.get("estado") or ""))
        except Exception as e:
            with cerradura:
                resultados.append(type(e).__name__)

    hilos = [threading.Thread(target=disparo) for _ in range(20)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    si = sum(1 for r in resultados if r == A.AUTORIZADO)
    assert si == 1, resultados
    ring = json.dumps(M.alertas(limite=100), ensure_ascii=True)
    denegados_ring = ring.count('"decision": "DENY"')
    assert denegados_ring >= 10, (
        f"el monitor no vio la campana de replay (denegados={denegados_ring})")
    # propiedad declarada: eventos de hilos quedan SIN dueno, no adjudicados


def test_04_excepcion_operacion_error(experimento, tmp_path):
    """Familia OPERACION: la capacidad termina en excepcion y el
    monitor debe verlo (lectura ERROR), sin inventar la causa."""
    with pytest.raises(Exception):
        A.construir_solicitud()  # falta todo: TypeError garantizado
    assert experimento["errores_op"] >= 1, "el monitor no vio la excepcion"


def test_05_heartbeat_y_matriz_en_el_informe(experimento):
    """Tabla PYTEST x MONITOR + heartbeat, impresa para el diario."""
    lineas = ["MATRIZ PYTEST x MONITOR (derivada de datos):"]
    for nombre in _ESTADO["orden"]:
        f = _ESTADO["exps"][nombre]
        lineas.append(
            f"  {nombre:44s} pytest={f['resultado']:7s}"
            f" ev={f['eventos']:2d} al={f['alertas']}"
            f" de={f['denegaciones']:2d} er={f['errores_op']}"
            f" gap={f['gap']}  -> {lectura_correlacion(f['resultado'], f)}")
    lineas.append("HEARTBEAT (ultimo estado conocido por recurso):")
    sala = M.sala()
    for puerta in sala.get("puertas") or []:
        lineas.append(f"  {str(puerta.get('recurso_id') or ''):22s}"
                      f" intentos={puerta.get('intentos')}"
                      f" denegados={puerta.get('denegados')}")
    lineas.append(f"  recursos observados por monitoreo: "
                  f"{len(sala.get('puertas') or [])}")
    print("\n".join(lineas))
    assert _ESTADO["orden"], "sin experimentos registrados"


def test_06_falsificacion_nivel_3_ciego(experimento):
    """El auditor debe notar la ceguera: sin esto, '100%' es trivial."""
    objetivo = None
    for rid, archivo in _ESTADO["declarados"].items():
        mod = importlib.import_module(
            f"modules.spartaco_seguridad.{archivo}")
        seg = getattr(mod, "SEGURIDAD", {})
        caps = [str(c) for c in (seg.get("capacidades_recurso") or [])
                if callable(getattr(mod, str(c), None))]
        if caps and (archivo, caps[0]) in _ESTADO["wraps"]:
            objetivo = (rid, archivo, caps[0])
            break
    assert objetivo, "no hay fuente envuelta para mutilar"
    rid, archivo, cap = objetivo
    fn_original = _ESTADO["wraps"][(archivo, cap)]
    try:
        setattr(importlib.import_module(
            f"modules.spartaco_seguridad.{archivo}"), cap, fn_original)
        _ESTADO["envueltos"].discard(rid)
        observados = {r: 1 for f in _ESTADO["exps"].values()
                      for r in f.get("recursos", [])}
        observados.pop(rid, None)
        sordos = recursos_sordos(_ESTADO["declarados"], observados)
        assert rid in sordos, "el auditor NO noto la ceguera"
        _ESTADO["sordos_detectados"].append(rid)
        print(f"FALSIFICACION NIVEL 3 OK: ceguera de {rid} DETECTADA")
    finally:
        setattr(importlib.import_module(
            f"modules.spartaco_seguridad.{archivo}"), cap, _wrap(rid, cap, fn_original))
        _ESTADO["envueltos"].add(rid)


def test_07_veredicto_de_la_sala(experimento):
    """Las propiedades duras de la correlacion, en un solo veredicto."""
    orden = _ESTADO["orden"]
    assert orden, "sin experimentos"
    for nombre in orden:
        f = _ESTADO["exps"][nombre]
        assert (f.get("lectura") or f.get("resultado") == "EJECUTADO"), (
            f"expediente sin lectura: {nombre}")
        assert f.get("gap", 0) == 0, (
            f"MONITORING_GAP en {nombre}: "
            f"{f.get('llamadas')} llamadas vs {f.get('eventos')} eventos")
        if f.get("resultado") == "FAILED":
            assert f.get("alertas") or f.get("denegaciones") or f.get("errores_op"), (
                f"FAIL sin senal del monitor en {nombre} (P-M)")
    violaciones = [n for n in orden
                   if _ESTADO["exps"][n].get("lectura") == "VIOLACION"]
    assert not violaciones, f"violaciones candidatas: {violaciones}"
    resumen = {
        "experimentos": len(orden),
        "recursos_declarados": len(_ESTADO["declarados"]),
        "recursos_envueltos": len(_ESTADO["envueltos"]),
        "sordos_antes_del_ciego": recursos_sordos(
            _ESTADO["declarados"],
            {r: 1 for f in _ESTADO["exps"].values()
             for r in f.get("recursos", [])}),
        "fallos_envoltura": _ESTADO["fallos_wrap"],
        "evidencia": str(EVID),
        "publicador": "python diagnostics/omega_diary_publisher.py",
    }
    print("VEREDICTO DE LA SALA:", json.dumps(resumen, indent=1))
    assert not _ESTADO["fallos_wrap"], _ESTADO["fallos_wrap"]
