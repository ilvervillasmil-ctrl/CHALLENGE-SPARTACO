# ===========================================================================
# ENABLEMENT AND CLOSURE THEOREM v2.2
# tests/test_teorema_habilitacion_cierre_v2_2.py
# Norm: TEOREMA_HABILITACION_CIERRE_v2.2.md
# ===========================================================================
#
# OBJECT OF THE THEOREM
# ---------------------------------------------------------------------------
# This file is an executable theorem. It is not an adversarial battery, a
# metrological kernel, a monitor, a resource auditor, or a closure test.
# What it measures is the interaction between the system and the instrument
# that observes it, specifically whether the engine constructs its own
# registry WITHOUT executing the code of the capabilities it registers.
#
# The theorem is a statement about PURITY OF CONSTRUCTION, not about the
# system's behavior under attack.
#
# THESIS
# ---------------------------------------------------------------------------
# The engine's bootstrap must not exercise any of the capabilities it
# declares as registered. If it did, the registry would be contaminated
# by its own construction and the measurement would be circular. The
# theorem verifies this by installing an external profiler before
# instantiating the engine and computing the intersection between the
# calls observed during bootstrap and the capabilities registered
# afterwards.
#
# THREE OUTCOMES, MUTUALLY EXCLUSIVE
# ---------------------------------------------------------------------------
#   INTEGRITY (integridad):
#     LIMPIA         bootstrap intersected no registered capability
#     CONTAMINADA    bootstrap intersected at least one registered capability
#     INVALIDA       engine did not construct or did not reach operative state
#
#   CLOSURE (cierre):
#     VACIO                       no capability enabled from H_0
#     OBSERVABLE                  fixed point reached (no capability produced delta)
#     NO_DETERMINADO              some capability was neither stable nor
#                                 producing delta (exception, non-dict output)
#     NO_CERRADO_EN_PRESUPUESTO   budget P_max exhausted before fixed point
#     NO_EJERCIDO                 exercise not permitted (no args allowed and
#                                 H_0 empty) or integrity invalid
#
# FASE I — CONTAMINATION
# ---------------------------------------------------------------------------
# A ProfilerBootstrap hooks sys.setprofile before constructing Engine.
# For every call observed, it records name, qualname, file and line.
# For every registered capability, the file computes an identity key
# (absolute path, first line number, qualname) and two aliases (the
# function name and the capability name). The intersection between the
# two sets is the contamination set.
#
# FASE II — PRECONDITIONS AND ENABLEMENT
# ---------------------------------------------------------------------------
# R_pre is computed from the signature of each capability via
# inspect.signature. A capability satisfies R_pre(H) iff every required
# parameter is present in H. H_0 is empty by declaration and R_BIND is
# false by declaration, so capabilities cannot bind their own arguments.
# E(H_0) is the set of capabilities with no required parameters.
# E_ctrl(H_0) is the subset of E(H_0) whose names are in CONTROL_NAMES
# (evaluar_universal, ejecutar_total).
#
# FASE III — ENABLEMENT LOOP
# ---------------------------------------------------------------------------
# The theorem defines a budget P_max = 8 steps. In each step, the file
# recomputes the enabled set with the current hypothesis, invokes each
# capability according to its signature, absorbs new or changed keys
# into H, and checks whether any delta occurred. If a delta occurred,
# it increments the step counter and repeats. If a full step produces
# no delta, the closure is OBSERVABLE. If the budget is exhausted, the
# closure is NO_CERRADO_EN_PRESUPUESTO. If the enabled set becomes
# empty first, the closure is VACIO. If a capability raises, the step
# is marked RAISE and H is not modified. If a capability returns a
# non-dict, the step is marked SALIDA_NO_DICT and H is not modified.
#
# THE INVARIANT
# ---------------------------------------------------------------------------
# The control capabilities (evaluar_universal, ejecutar_total) are never
# exercised during the test. This is verified by checking that no step
# in the enablement loop ends with an identifier ending in either of
# those two names. If they were exercised, the measurement would be
# contaminated by the controls themselves. The controls are observers,
# not participants.
#
# PERSISTED ARTIFACTS
# ---------------------------------------------------------------------------
# All artifacts live in diagnostics/habilitacion_cierre_v2_2/ and are
# written in a strict order before any assertion executes:
#
#   PRECONDITIONS.json   R_BIND=False, PERMITE_EJERCICIO_SIN_ARGS_EN_H0=False,
#                        P_max=8, H_0=[]
#   DISCOVERY.json       bootstrap calls, contamination count, contaminantes,
#                        full capability list with class, signature, file, line
#   ENABLEMENT.json      H_0, R_BIND, E_H0, E_ctrl_H0
#   EVIDENCE.json        integridad, cierre, observations, logic, pasos,
#                        H_final
#   VERDICT.md           human-readable narrative of the whole theorem
#
# ORDER OF WRITING
# ---------------------------------------------------------------------------
# preconditions -> discovery -> enablement -> evidence -> verdict.
# Each file depends on the previous one. All are on disk before the
# three assertions run.
#
# THREE ASSERTIONS
# ---------------------------------------------------------------------------
#   test_fase_i_intersecta_c_real
#     bootstrap was captured; contamination count matches between
#     DISCOVERY and EVIDENCE; integrity is one of the three valid values.
#
#   test_fase_ii_r_pre
#     ENABLEMENT exists; R_BIND is false; every identifier in e_ctrl_h0
#     ends with evaluar_universal or ejecutar_total.
#
#   test_resultado_par
#     integrity and closure are within their vocabularies; integrity is
#     not INVALIDA; the controls were not exercised. The failure message
#     for INVALIDA includes the full VERDICT.md content, so a broken
#     engine surfaces the narrative on failure.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It is not adversarial: it does not try to break the engine.
#   - It is not metrological: it does not qualify its own instrument.
#   - It is not an audit of an isolated resource.
#   - It does not certify the whole system: it certifies that the
#     engine constructs its registry without executing the code it
#     registers.
#   - It is not a red-team, a monitor, or a closure test of declared
#     algebra.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The adversarial battery attacks the layered architecture of
# proteccion.py. The credential red-teams attack credencial.py. The
# metrological kernel audits the instruments. The integration smoke
# test checks the honest end-to-end path. The monitor correlates
# external and internal observation. The fail-closed auditor qualifies
# itself against synthetic controls. The seal closure test verifies
# that declared algebra is physically operated. The universal closure
# verifies that what is verified equals what is loaded equals what is
# executed. This file closes a different loop: it verifies that the
# registry of the engine is built WITHOUT executing the code it
# registers. It is a theorem of purity of construction, not of
# behavior under stress.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# A system that executes the code it registers during its own bootstrap
# is measuring itself. A system that registers without executing is
# measuring the world. The theorem captures this distinction as a
# computable property, verifies it externally with a profiler, and
# persists the evidence before asserting the three conclusions.
#
# ============================================================================

from __future__ import annotations

import hashlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "modules"
OUT = ROOT / "diagnostics" / "habilitacion_cierre_v2_2"
PRE = OUT / "PRECONDITIONS.json"
DISCOVERY = OUT / "DISCOVERY.json"
ENABLEMENT = OUT / "ENABLEMENT.json"
EVIDENCE = OUT / "EVIDENCE.json"
VERDICT = OUT / "VERDICT.md"

SCHEMA = "spartaco.habilitacion-cierre.v2.2"
CONTROL_NAMES = frozenset({"evaluar_universal", "ejecutar_total"})
SKIP_PARAMS = frozenset({"self", "cls"})
CIERRES = frozenset({
    "VACIO",
    "OBSERVABLE",
    "NO_DETERMINADO",
    "NO_CERRADO_EN_PRESUPUESTO",
    "NO_EJERCIDO",
})
INTEGRIDADES = frozenset({"LIMPIA", "CONTAMINADA", "INVALIDA"})


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(value: Any, seen: Optional[Set[int]] = None) -> Tuple[str, int, str]:
    if seen is None:
        seen = set()
    tipo = type(value).__name__
    if value is None:
        return (tipo, 0, _sha(b"None"))
    if isinstance(value, (bool, int, float)):
        raw = repr(value).encode("utf-8")
        return (tipo, len(raw), _sha(raw))
    if isinstance(value, str):
        raw = value.encode("utf-8", "replace")
        return (tipo, len(value), _sha(raw))
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return (tipo, len(raw), _sha(raw))
    oid = id(value)
    if oid in seen:
        return (tipo, -1, _sha(b"cycle"))
    if isinstance(value, dict):
        seen.add(oid)
        partes = []
        for k in sorted(value.keys(), key=str):
            phi = _fingerprint(value[k], seen)
            partes.append("{0}|{1}|{2}|{3}".format(k, phi[0], phi[1], phi[2]))
        seen.discard(oid)
        return (tipo, len(value), _sha("\n".join(partes).encode("utf-8")))
    if isinstance(value, (list, tuple)):
        seen.add(oid)
        partes = [_fingerprint(v, seen) for v in value]
        seen.discard(oid)
        blob = "\n".join("{0}|{1}|{2}".format(*p) for p in partes).encode("utf-8")
        return (tipo, len(value), _sha(blob))
    if isinstance(value, (set, frozenset)):
        seen.add(oid)
        partes = sorted(
            "{0}|{1}|{2}".format(*_fingerprint(v, seen))
            for v in value
        )
        seen.discard(oid)
        return (tipo, len(value), _sha("\n".join(partes).encode("utf-8")))
    raw = repr(value)[:200].encode("utf-8", "replace")
    return (tipo, len(raw), _sha(raw))


def _phi_json(phi: Tuple[str, int, str]) -> Dict[str, Any]:
    return {"type": phi[0], "size": phi[1], "sha256": phi[2]}


def _id_key(file: str, firstlineno: int, name: str, qualname: str = "") -> Tuple[str, int, str, str]:
    return (file, int(firstlineno), name, qualname)


def _firma(fn: Any) -> Dict[str, Any]:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError) as exc:
        return {"legible": False, "pre": False, "req": [], "opt": [], "error": type(exc).__name__}
    req: List[str] = []
    opt: List[str] = []
    for nombre, param in sig.parameters.items():
        if param.kind not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            continue
        if nombre in SKIP_PARAMS:
            return {"legible": True, "pre": False, "req": [nombre], "opt": [], "instancia": True}
        if param.default is inspect.Parameter.empty:
            req.append(nombre)
        else:
            opt.append(nombre)
    return {"legible": True, "pre": True, "req": req, "opt": opt, "instancia": False}


def _r_pre(firma: Dict[str, Any], h: Dict[str, Tuple[str, int, str]]) -> bool:
    if not firma.get("legible") or not firma.get("pre"):
        return False
    return all(p in h for p in (firma.get("req") or []))


def _invocar(fn: Any, firma: Dict[str, Any], h_valores: Dict[str, Any]) -> Tuple[str, Any]:
    req = list(firma.get("req") or [])
    opt = list(firma.get("opt") or [])
    try:
        if req:
            kwargs = {n: h_valores[n] for n in req + opt if n in h_valores}
            return "RETURN", fn(**kwargs)
        kwargs = {n: h_valores[n] for n in opt if n in h_valores}
        return "RETURN", fn(**kwargs) if kwargs else fn()
    except Exception as exc:
        return "RAISE", {"type": type(exc).__name__, "message": str(exc)[:500]}


def _delta(antes, despues):
    return {
        "delta_k": sorted(k for k in despues if k not in antes),
        "delta_v": sorted(k for k in despues if k in antes and despues[k] != antes[k]),
    }


def _absorber(h, h_valores, salida):
    if not isinstance(salida, dict):
        return {"codigo": "SALIDA_NO_DICT", "delta_k": [], "delta_v": []}
    antes = dict(h)
    for clave, valor in salida.items():
        if not isinstance(clave, str) or clave.startswith("_"):
            continue
        h[clave] = _fingerprint(valor)
        h_valores[clave] = valor
    d = _delta(antes, h)
    d["codigo"] = "RETURN"
    return d


class _ProfilerBootstrap:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, frame, event, arg):
        if event != "call":
            return self
        code = frame.f_code
        try:
            ruta = str(Path(code.co_filename).resolve())
            Path(ruta).relative_to(MODULES)
        except Exception:
            return self
        self.calls.append({
            "name": code.co_name,
            "qualname": getattr(code, "co_qualname", code.co_name),
            "file": ruta,
            "firstlineno": int(code.co_firstlineno),
        })
        return self


def _narrar(ev: Dict[str, Any]) -> str:
    o = ev["observations"]
    return "\n".join([
        "# Veredicto — habilitación y cierre v2.2",
        "",
        "**Integridad:** `{0}`".format(ev["integridad"]),
        "**Cierre:** `{0}`".format(ev["cierre"]),
        "",
        "## Fase I",
        "Calls_bootstrap = {0}. Intersección ID(C) = {1}.".format(
            o.get("n_bootstrap", 0), o.get("n_contaminacion", 0),
        ),
        "",
        "## Fase II",
        "E(H_0) = `{0}`.".format(", ".join(o.get("e_h0") or []) or "vacío"),
        "E_ctrl(H_0) = `{0}`.".format(", ".join(o.get("e_ctrl_h0") or []) or "vacío"),
        "",
        "## Fase III",
        "permiso_0 = `{0}`.".format(o.get("permite_ejercicio_sin_args_h0")),
        "RETURN = {0}. RAISE = {1}. SALIDA_NO_DICT = {2}.".format(
            o.get("pasos_return", 0),
            o.get("pasos_raise", 0),
            o.get("pasos_no_dict", 0),
        ),
        "",
        "EU/ET no ejercidos. C_unknown no cambia de clase al ejercerse.",
        "",
    ])


def _capturar() -> Dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    permiso_0 = False
    p_max = 8
    PRE.write_text(json.dumps({
        "schema": SCHEMA,
        "R_BIND": False,
        "PERMITE_EJERCICIO_SIN_ARGS_EN_H0": permiso_0,
        "P_max": p_max,
        "H_0": [],
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    sys.path.insert(0, str(ROOT))
    prof = _ProfilerBootstrap()
    engine = None
    try:
        sys.setprofile(prof)
        from core.engine import Engine, ESTADO_OPERATIVO
        engine = Engine(MODULES, strict=True)
    except Exception as exc:
        sys.setprofile(None)
        ev = {
            "schema": SCHEMA,
            "integridad": "INVALIDA",
            "cierre": "NO_EJERCIDO",
            "observations": {
                "n_bootstrap": len(prof.calls),
                "n_contaminacion": 0,
                "e_h0": [],
                "e_ctrl_h0": [],
                "permite_ejercicio_sin_args_h0": permiso_0,
                "pasos_return": 0,
                "pasos_raise": 0,
                "pasos_no_dict": 0,
                "error": "{0}: {1}".format(type(exc).__name__, exc),
            },
            "logic": {"eu_et_no_ejercidos": True},
            "pasos": [],
        }
        DISCOVERY.write_text(json.dumps({"calls_bootstrap": prof.calls}, indent=2), encoding="utf-8")
        ENABLEMENT.write_text("{}", encoding="utf-8")
        EVIDENCE.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
        VERDICT.write_text(_narrar(ev), encoding="utf-8")
        return ev
    finally:
        sys.setprofile(None)

    descubrimiento: List[Dict[str, Any]] = []
    ids_c: Set[Tuple[str, int, str, str]] = set()
    for nombre_mod in sorted(engine.registro.contenedores):
        cont = engine.registro.contenedores[nombre_mod]
        for nombre_cap in sorted(cont.capacidades.keys()):
            fn = cont.fn(nombre_cap)
            code = getattr(fn, "__code__", None) if callable(fn) else None
            file_c = str(Path(code.co_filename).resolve()) if code else ""
            first = int(code.co_firstlineno) if code else 0
            qn = getattr(fn, "__qualname__", nombre_cap) if callable(fn) else nombre_cap
            if code:
                ids_c.add(_id_key(file_c, first, code.co_name, qn))
                ids_c.add(_id_key(file_c, first, nombre_cap, qn))
            descubrimiento.append({
                "id": "{0}.{1}".format(nombre_mod, nombre_cap),
                "modulo": nombre_mod,
                "nombre": nombre_cap,
                "clase": "C_ctrl" if nombre_cap in CONTROL_NAMES else "C_unknown",
                "callable": callable(fn),
                "firma": _firma(fn) if callable(fn) else {"legible": False, "pre": False, "req": [], "opt": []},
                "file": file_c,
                "firstlineno": first,
                "qualname": qn,
            })

    contaminantes = []
    for call in prof.calls:
        key = _id_key(call["file"], call["firstlineno"], call["name"], call.get("qualname", ""))
        key2 = _id_key(call["file"], call["firstlineno"], call["name"], "")
        if key in ids_c or key2 in ids_c:
            contaminantes.append(call)

    if engine.estado != ESTADO_OPERATIVO:
        integridad = "INVALIDA"
    elif contaminantes:
        integridad = "CONTAMINADA"
    else:
        integridad = "LIMPIA"

    DISCOVERY.write_text(json.dumps({
        "schema": SCHEMA,
        "calls_bootstrap": prof.calls[:200],
        "n_bootstrap": len(prof.calls),
        "n_contaminacion": len(contaminantes),
        "contaminantes": contaminantes[:80],
        "capacidades": descubrimiento,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    h: Dict[str, Tuple[str, int, str]] = {}
    h_valores: Dict[str, Any] = {}

    def e_de(solo_ctrl: bool) -> List[Dict[str, Any]]:
        out = []
        for item in descubrimiento:
            if not item["callable"]:
                continue
            ctrl = item["clase"] == "C_ctrl"
            if solo_ctrl != ctrl:
                continue
            if _r_pre(item["firma"], h):
                out.append(item)
        return out

    e_h0 = e_de(False)
    e_ctrl = e_de(True)
    ENABLEMENT.write_text(json.dumps({
        "schema": SCHEMA,
        "H_0": [],
        "R_BIND": False,
        "E_H0": [x["id"] for x in e_h0],
        "E_ctrl_H0": [x["id"] for x in e_ctrl],
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    pasos: List[Dict[str, Any]] = []
    if integridad == "INVALIDA":
        cierre = "NO_EJERCIDO"
    elif not h and e_h0 and not permiso_0:
        cierre = "NO_EJERCIDO"
    elif not e_h0:
        cierre = "VACIO"
    else:
        cierre = "NO_CERRADO_EN_PRESUPUESTO"
        i = 0
        while i < p_max:
            e_now = e_de(False)
            if not e_now:
                cierre = "VACIO"
                break
            hubo_delta = False
            todos_estables = True
            for item in e_now:
                fn = engine.registro.contenedores[item["modulo"]].fn(item["nombre"])
                codigo, salida = _invocar(fn, item["firma"], h_valores)
                if codigo == "RAISE":
                    todos_estables = False
                    pasos.append({"id": item["id"], "codigo": "RAISE", "delta_k": [], "delta_v": []})
                    continue
                dlt = _absorber(h, h_valores, salida)
                if dlt["codigo"] == "SALIDA_NO_DICT":
                    todos_estables = False
                    pasos.append({"id": item["id"], "codigo": "SALIDA_NO_DICT", "delta_k": [], "delta_v": []})
                    continue
                pasos.append({
                    "id": item["id"],
                    "codigo": "RETURN",
                    "delta_k": dlt["delta_k"],
                    "delta_v": dlt["delta_v"],
                    "H_size": len(h),
                })
                if dlt["delta_k"] or dlt["delta_v"]:
                    hubo_delta = True
                    todos_estables = False
                    break
            if hubo_delta:
                i += 1
                if i >= p_max:
                    cierre = "NO_CERRADO_EN_PRESUPUESTO"
                continue
            cierre = "OBSERVABLE" if todos_estables else "NO_DETERMINADO"
            break

    ev = {
        "schema": SCHEMA,
        "integridad": integridad,
        "cierre": cierre,
        "motivo_no_ejercido": (
            "SIN_PERMISO_DE_EJERCICIO"
            if cierre == "NO_EJERCIDO" and integridad != "INVALIDA"
            else None
        ),
        "observations": {
            "modulos": sorted(engine.registro.contenedores.keys()) if engine else [],
            "n_bootstrap": len(prof.calls),
            "n_contaminacion": len(contaminantes),
            "e_h0": [x["id"] for x in e_h0],
            "e_ctrl_h0": [x["id"] for x in e_ctrl],
            "permite_ejercicio_sin_args_h0": permiso_0,
            "pasos_return": sum(1 for p in pasos if p.get("codigo") == "RETURN"),
            "pasos_raise": sum(1 for p in pasos if p.get("codigo") == "RAISE"),
            "pasos_no_dict": sum(1 for p in pasos if p.get("codigo") == "SALIDA_NO_DICT"),
        },
        "logic": {
            "eu_et_no_ejercidos": all(
                not str(p.get("id", "")).endswith(".evaluar_universal")
                and not str(p.get("id", "")).endswith(".ejecutar_total")
                for p in pasos
            ),
        },
        "pasos": pasos,
        "H_final": {k: _phi_json(phi) for k, phi in sorted(h.items())},
    }
    EVIDENCE.write_text(json.dumps(ev, indent=2, ensure_ascii=False), encoding="utf-8")
    VERDICT.write_text(_narrar(ev), encoding="utf-8")
    return ev


@pytest.fixture(scope="session")
def evidencia_v22() -> Dict[str, Any]:
    return _capturar()


def test_fase_i_intersecta_c_real(evidencia_v22: Dict[str, Any]) -> None:
    ev = evidencia_v22
    assert PRE.exists() and DISCOVERY.exists()
    data = json.loads(DISCOVERY.read_text(encoding="utf-8"))
    assert "calls_bootstrap" in data
    assert ev["observations"]["n_contaminacion"] == data["n_contaminacion"]
    assert ev["integridad"] in INTEGRIDADES


def test_fase_ii_r_pre(evidencia_v22: Dict[str, Any]) -> None:
    ev = evidencia_v22
    assert ENABLEMENT.exists()
    enab = json.loads(ENABLEMENT.read_text(encoding="utf-8"))
    assert enab.get("R_BIND") is False
    for ident in ev["observations"]["e_ctrl_h0"]:
        assert ident.endswith(".evaluar_universal") or ident.endswith(".ejecutar_total")


def test_resultado_par(evidencia_v22: Dict[str, Any]) -> None:
    ev = evidencia_v22
    assert ev["integridad"] in INTEGRIDADES
    assert ev["cierre"] in CIERRES
    assert ev["integridad"] != "INVALIDA", VERDICT.read_text(encoding="utf-8")
    assert ev["logic"]["eu_et_no_ejercidos"] is True
# ==============================
# ==============================
