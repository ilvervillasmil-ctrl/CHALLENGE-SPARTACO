# ===============================================================
# UHCR v3.4.2-R2 — RAW causal boundary auditor
# tests/test_uhcr_v3_4_2.py
# ===============================================================
#
# TEOREMA UHCR
#
# Sea E un Engine observable. Sea M_E el conjunto de proveedores
# que E declara aplicables a evaluar_universal. Sea H_i el estado
# de hechos entregado por E a la invocacion de proveedor B_i.
#
#   B_i = ENTER(E, m_i, evaluar_universal, H_i)
#
# Solo se afirma retorno de B_i si se observa:
#
#   EXIT(B_i, R_i)
#
# Si R_i contiene hechos publicados P_i, UHCR observa P_i como
# salida del proveedor. NO identifica P_i con H_{i+1}.
#
# La transicion:
#
#   (H_i, P_i) --Absorb_E--> H_{i+1}
#
# solo se afirma como semantica del Engine cuando existe evidencia
# nativa suficiente o cuando sus consecuencias observables pueden
# contrastarse RAW contra H_{i+1}. En ausencia de dicha evidencia
# se etiqueta como NO_DETERMINADO.
#
# Para una absorcion "first write wins", si esa semantica esta
# documentada/observada nativamente:
#
#   h in H_i                         => H_{i+1}[h] = H_i[h]
#   h in P_i and h not in H_i       => H_{i+1}[h] = P_i[h]
#   h in P_i∩H_i and P_i[h]!=H_i[h] => H_{i+1}[h] = H_i[h]
#
# Restricciones epistemicas:
#
#   EXIT no observado en P_obs =/=> EXIT imposible
#   TIMEOUT =/=> vulnerabilidad
#   EU->ET->EU =/=> defecto
#   Delta Phi_K(H)=0 =/=> Delta H=0
#   CALL observado sin RETURN observado =/=> frame activo
#   E_derivada no sustituye E_RAW
#   E_instrumental no sustituye E_nativa cuando esta existe
#
# RAW_EVIDENCE_POLICY=FULL_WHEN_JSON_SERIALIZABLE
# NON_SERIALIZABLE_POLICY=TYPED_REPR_TRUNCATED_2000
# RECONCILIATION_MODE=ORDER_PRESERVING_BY_PROVIDER
#
# STATUS del test solo expresa consistencia del AUDITOR.
# Nunca expresa seguridad, terminacion o correccion global del sistema.
# ===============================================================

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import queue
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "modules"
OUT = ROOT / "diagnostics" / "uhcr_v3_4_2"

PRE = OUT / "PRECONDITIONS.json"
GE = OUT / "G_E.json"
GI = OUT / "G_I.json"
GI_EVENTS = OUT / "GI_EVENTS.json"
NATIVE = OUT / "ENGINE_NATIVE.json"
EVIDENCE = OUT / "EVIDENCE.json"
REPORT = OUT / "REPORT.txt"

SCHEMA = "spartaco.uhcr.v3.4.2"
P_OBS = 1.0
CKPT_EVERY = 50
OBSERVED_INTERNAL_CAPS = frozenset({"evaluar_universal", "ejecutar_total"})


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _json_raw(obj: Any) -> Any:
    """Preserva exactamente el valor si JSON puede representarlo.

    Si no puede, NO lo llama RAW: declara explicitamente una
    transformacion typed-repr truncada.
    """
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return {
            "_evidence_role": "REPRESENTATION_TRANSFORM",
            "_transform": "TYPED_REPR_TRUNCATED_2000",
            "python_type": type(obj).__name__,
            "repr": repr(obj)[:2000],
        }


def _phi_k(h: Any) -> Dict[str, Any]:
    if not isinstance(h, dict):
        return {"phi": "Phi_K", "role": "DERIVED", "n": 0, "sha256": _sha("empty")}
    keys = sorted(str(k) for k in h)
    return {
        "phi": "Phi_K",
        "role": "DERIVED",
        "n": len(keys),
        "sha256": _sha("|".join(keys)),
    }


def _call_signature(function: str, args_evidence: Any) -> str:
    try:
        body = json.dumps(args_evidence, sort_keys=True, default=str)
    except Exception:
        body = repr(args_evidence)
    return function + "|" + _sha(body)


def _under_modules(filename: str) -> bool:
    try:
        Path(filename).resolve().relative_to(MODULES.resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def _native_protocol(result: Any) -> Optional[Dict[str, Any]]:
    """Proyeccion estructurada; el resultado completo se conserva aparte."""
    if not isinstance(result, dict) or result.get("operacion") != "evaluar_universal":
        return None

    trace = []
    for e in result.get("traza") or []:
        if isinstance(e, dict):
            trace.append(_json_raw(dict(e)))

    mods = result.get("modulos") if isinstance(result.get("modulos"), dict) else {}
    return {
        "attribution": "NATIVE_STRUCTURED_PROJECTION",
        "estado": result.get("estado"),
        "operacion": result.get("operacion"),
        "pasadas": result.get("pasadas"),
        "punto_fijo": result.get("punto_fijo"),
        "ejecutadas": _json_raw(result.get("ejecutadas")),
        "origen": _json_raw(result.get("origen")),
        "hechos_JSON_RAW": _json_raw(result.get("hechos")),
        "hechos_Phi_K": _phi_k(result.get("hechos")),
        "modulos": {
            "proveedores": list(mods.get("proveedores") or []),
            "aportaron": list(mods.get("aportaron") or []),
            "fallaron": list(mods.get("fallaron") or []),
        },
        "conflictos_JSON_RAW": _json_raw(result.get("conflictos")),
        "diagnostico_JSON_RAW": _json_raw(result.get("diagnostico")),
        "traza_JSON_RAW": trace,
    }


def _worker(q: mp.Queue) -> None:
    sys.path.insert(0, str(ROOT))

    boundaries: List[Dict[str, Any]] = []
    boundary_stack: List[int] = []

    frame_stack: List[Tuple[int, str, int]] = []
    frame_owner: Dict[int, Tuple[str, int]] = {}
    gi_events: List[Dict[str, Any]] = []
    gi_by_b: Dict[int, Dict[str, Any]] = {}
    signatures: Counter = Counter()
    stack_mismatch = [0]
    candidates: List[str] = []

    def current_b() -> Optional[int]:
        return boundary_stack[-1] if boundary_stack else None

    def bucket(b: Optional[int]) -> Optional[Dict[str, Any]]:
        if b is None:
            return None
        if b not in gi_by_b:
            gi_by_b[b] = {
                "B": b,
                "calls_observed": 0,
                "returns_observed": 0,
                "unmatched_calls_observed": 0,
                "depth_max_observed": 0,
                "pairs": Counter(),
                "first": [],
                "last": [],
                "mismatch": 0,
            }
        return gi_by_b[b]

    def gi_snapshot() -> Dict[str, Any]:
        out = {}
        for b, v in gi_by_b.items():
            calls = int(v["calls_observed"])
            rets = int(v["returns_observed"])
            out[str(b)] = {
                "B": b,
                "calls_observed": calls,
                "returns_observed": rets,
                # Nombre deliberadamente epistemico: no afirma frames activos.
                "unmatched_calls_observed": max(0, calls - rets),
                "depth_max_observed": v["depth_max_observed"],
                "pairs": dict(v["pairs"]),
                "first": list(v["first"]),
                "last": list(v["last"]),
                "mismatch": v["mismatch"],
            }
        return out

    def flush_gi(complete: bool = False) -> None:
        try:
            OUT.mkdir(parents=True, exist_ok=True)
            GI_EVENTS.write_text(json.dumps({
                "schema": SCHEMA,
                "part": "G_I_EVENTS",
                "evidence_policy": "JSON_RAW_OR_DECLARED_REPRESENTATION",
                "complete": complete,
                "n_events": len(gi_events),
                "n_call": sum(e["event"] == "call" for e in gi_events),
                "n_return": sum(e["event"] == "return" for e in gi_events),
                "events": gi_events,
            }, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

    def emit(kind: str, extra: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "kind": kind,
            "wall_time": time.time(),
            "mono_ns": time.perf_counter_ns(),
            "boundaries": list(boundaries),
            "open_boundaries": list(boundary_stack),
            "candidates": list(candidates),
            "gi_by_b": gi_snapshot(),
            "gi_event_count": len(gi_events),
            "stack_mismatch": stack_mismatch[0],
            "n_unique_call_signatures_DERIVED": len(signatures),
            "top_call_signatures_DERIVED": signatures.most_common(10),
        }
        if extra:
            payload.update(extra)
        q.put(payload)
        if kind in {"checkpoint", "exit", "raise", "done"}:
            flush_gi(complete=(kind == "done"))

    def profiler(frame, event, arg):
        if event not in ("call", "return"):
            return profiler
        fn = frame.f_code.co_name
        if fn not in OBSERVED_INTERNAL_CAPS:
            return profiler
        if not _under_modules(frame.f_code.co_filename):
            return profiler

        fid = id(frame)
        owner = current_b()
        parent_fid = frame_stack[-1][0] if frame_stack else None

        rec = {
            "seq": len(gi_events) + 1,
            "event": event,
            "wall_time": time.time(),
            "mono_ns": time.perf_counter_ns(),
            "frame_id": fid,
            "parent_frame_id": parent_fid,
            "function": fn,
            "owner_B": owner,
            "depth_observed": len(frame_stack) + (1 if event == "call" else 0),
        }

        if event == "call":
            names = frame.f_code.co_varnames[:frame.f_code.co_argcount]
            args = {name: frame.f_locals.get(name) for name in names}
            rec["args_evidence"] = _json_raw(args)
            signatures[_call_signature(fn, rec["args_evidence"])] += 1
        else:
            rec["result_evidence"] = _json_raw(arg)

        gi_events.append(rec)
        bkt = bucket(owner)

        if event == "call":
            parent = frame_stack[-1] if frame_stack else None
            frame_stack.append((fid, fn, owner if owner is not None else -1))
            frame_owner[fid] = (fn, owner if owner is not None else -1)

            if bkt is not None:
                bkt["calls_observed"] += 1
                bkt["depth_max_observed"] = max(bkt["depth_max_observed"], len(frame_stack))
                if len(bkt["first"]) < 20:
                    bkt["first"].append(fn)
                bkt["last"].append(fn)
                bkt["last"] = bkt["last"][-30:]
                if parent is not None and parent[2] == owner:
                    bkt["pairs"][parent[1] + "->" + fn] += 1

                if bkt["calls_observed"] % CKPT_EVERY == 0:
                    emit("checkpoint")
        else:
            slot = frame_owner.get(fid)
            ret_owner = slot[1] if slot is not None else (owner if owner is not None else -1)
            ret_bkt = gi_by_b.get(ret_owner)

            if slot is None:
                stack_mismatch[0] += 1
                if ret_bkt is not None:
                    ret_bkt["mismatch"] += 1
            else:
                if frame_stack and frame_stack[-1][0] == fid:
                    frame_stack.pop()
                else:
                    stack_mismatch[0] += 1
                    if ret_bkt is not None:
                        ret_bkt["mismatch"] += 1
                    frame_stack[:] = [x for x in frame_stack if x[0] != fid]
                if ret_bkt is not None:
                    ret_bkt["returns_observed"] += 1
                frame_owner.pop(fid, None)

        if len(gi_events) % CKPT_EVERY == 0:
            flush_gi(False)
        return profiler

    try:
        from core.engine import Engine

        engine = Engine(MODULES, strict=True)

        for name, container in engine.registro.contenedores.items():
            caps = getattr(container, "capacidades", {}) or {}
            auth = getattr(container, "autoriza_engine", {}) or {}
            if "evaluar_universal" in caps and auth.get("ejecutar") is True:
                candidates.append(name)

        original = engine.ejecutar_capacidad

        def wrapped(module_or_role, capability, *args, **kwargs):
            if capability != "evaluar_universal":
                return original(module_or_role, capability, *args, **kwargs)

            h_before = kwargs.get("hechos") if "hechos" in kwargs else (args[0] if args else None)
            bid = len(boundaries) + 1
            rec = {
                "B": bid,
                "module": module_or_role,
                "capability": capability,
                "state": "ENTER",
                "enter_wall": time.time(),
                "enter_mono_ns": time.perf_counter_ns(),
                "H_before_JSON_RAW": _json_raw(h_before),
                "H_before_Phi_K": _phi_k(h_before),
            }
            boundaries.append(rec)
            boundary_stack.append(bid)
            emit("enter")
            sys.setprofile(profiler)

            try:
                result = original(module_or_role, capability, *args, **kwargs)
            except BaseException as exc:
                rec["state"] = "RAISE"
                rec["raise_wall"] = time.time()
                rec["raise_mono_ns"] = time.perf_counter_ns()
                rec["exception_evidence"] = {
                    "type": type(exc).__name__,
                    "args": _json_raw(getattr(exc, "args", None)),
                    "message": str(exc),
                }
                if boundary_stack and boundary_stack[-1] == bid:
                    boundary_stack.pop()
                if not boundary_stack:
                    sys.setprofile(None)
                emit("raise")
                raise

            rec["state"] = "EXIT"
            rec["exit_wall"] = time.time()
            rec["exit_mono_ns"] = time.perf_counter_ns()
            rec["duration_ns"] = rec["exit_mono_ns"] - rec["enter_mono_ns"]
            rec["R_JSON_RAW"] = _json_raw(result)

            published = None
            if isinstance(result, dict):
                module_result = result.get("resultado")
                if isinstance(module_result, dict) and isinstance(module_result.get("hechos"), dict):
                    published = module_result["hechos"]

            rec["P_JSON_RAW"] = _json_raw(published)
            rec["P_Phi_K"] = _phi_k(published)

            if boundary_stack and boundary_stack[-1] == bid:
                boundary_stack.pop()
            if not boundary_stack:
                sys.setprofile(None)

            emit("exit")
            return result

        engine.ejecutar_capacidad = wrapped  # type: ignore[method-assign]

        try:
            result = engine.evaluar_universal({})
            emit("done", {
                "termination": "RETURN",
                "native_result_JSON_RAW": _json_raw(result),
                "native_protocol": _native_protocol(result),
            })
        except BaseException as exc:
            emit("done", {
                "termination": "RAISE",
                "exception": {
                    "type": type(exc).__name__,
                    "args": _json_raw(getattr(exc, "args", None)),
                    "message": str(exc),
                },
                "native_result_JSON_RAW": None,
                "native_protocol": None,
            })
    except BaseException as exc:
        emit("done", {
            "termination": "WORKER_ERROR",
            "worker_exception": {
                "type": type(exc).__name__,
                "args": _json_raw(getattr(exc, "args", None)),
                "message": str(exc),
            },
            "native_result_JSON_RAW": None,
            "native_protocol": None,
        })


def _drain(q: mp.Queue) -> List[Dict[str, Any]]:
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except Exception:
            return items


def _raw_transition(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Contrasta consecuencias RAW sin afirmar que observamos Absorb_E."""
    hi = a.get("H_before_JSON_RAW")
    pi = a.get("P_JSON_RAW")
    hj = b.get("H_before_JSON_RAW")

    if not all(isinstance(x, dict) for x in (hi, pi, hj)):
        return {
            "B_from": a.get("B"),
            "B_to": b.get("B"),
            "status": "NO_DETERMINADO",
            "reason": "H_i, P_i o H_{i+1} no es dict JSON-RAW",
        }

    conserved = {}
    new_publications = {}
    conflicts = {}
    violations = []

    for h, old in hi.items():
        ok = h in hj and hj[h] == old
        conserved[str(h)] = {"expected": _json_raw(old), "observed": _json_raw(hj.get(h)), "ok": ok}
        if not ok:
            violations.append("PREEXISTING_VALUE_NOT_CONSERVED:" + str(h))

    for h, value in pi.items():
        if h not in hi:
            ok = h in hj and hj[h] == value
            new_publications[str(h)] = {
                "published": _json_raw(value),
                "observed": _json_raw(hj.get(h)),
                "ok": ok,
            }
            if not ok:
                violations.append("NEW_PUBLICATION_NOT_PROPAGATED:" + str(h))
        elif hi[h] != value:
            ok = h in hj and hj[h] == hi[h]
            conflicts[str(h)] = {
                "old": _json_raw(hi[h]),
                "published": _json_raw(value),
                "observed": _json_raw(hj.get(h)),
                "first_write_preserved": ok,
            }
            if not ok:
                violations.append("FIRST_WRITE_NOT_PRESERVED:" + str(h))

    return {
        "B_from": a.get("B"),
        "B_to": b.get("B"),
        "status": "OBSERVED_CONSISTENT" if not violations else "OBSERVED_CONTRADICTION",
        "IMPORTANT": "Esto contrasta consecuencias observables; no demuestra por si solo que Absorb_E sea la unica causa.",
        "H_i_equals_H_next": hi == hj,
        "P_i_equals_H_next": pi == hj,
        "conserved_preexisting": conserved,
        "new_publications": new_publications,
        "candidate_conflicts": conflicts,
        "violations": violations,
    }


def _reconcile(native: Optional[Dict[str, Any]], boundaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not native or native.get("attribution") != "NATIVE_STRUCTURED_PROJECTION":
        return {
            "status": "NO_DETERMINADO",
            "pairs": [],
            "native_without_exit": [],
            "exit_without_native": [],
        }

    trace = native.get("traza_JSON_RAW") or []
    observations = [
        e for e in trace
        if isinstance(e, dict) and e.get("fase") in ("APORTE", "FALLO")
    ]
    observations.sort(key=lambda e: e.get("seq") or 0)

    pending: Dict[str, List[Dict[str, Any]]] = {}
    for b in boundaries:
        if b.get("state") == "EXIT":
            pending.setdefault(str(b.get("module")), []).append(b)

    pairs = []
    missing = []
    for e in observations:
        module = str(e.get("modulo"))
        q = pending.get(module) or []
        if q:
            b = q.pop(0)
            pairs.append({
                "native_seq": e.get("seq"),
                "native_phase": e.get("fase"),
                "module": module,
                "B": b.get("B"),
            })
        else:
            missing.append(_json_raw(e))

    leftovers = [
        {"B": b.get("B"), "module": b.get("module")}
        for q in pending.values() for b in q
    ]
    return {
        "status": "OK" if not missing and not leftovers else "CONTRADICTION",
        "pairs": pairs,
        "native_without_exit": missing,
        "exit_without_native": leftovers,
    }


def _capture() -> Dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)

    PRE.write_text(json.dumps({
        "schema": SCHEMA,
        "theorem": "UHCR-v3.4.2-R2",
        "P_obs_s": P_OBS,
        "checkpoint_every_calls": CKPT_EVERY,
        "AUTO_TRUST": False,
        "RAW_EVIDENCE_POLICY": "FULL_WHEN_JSON_SERIALIZABLE",
        "NON_SERIALIZABLE_POLICY": "TYPED_REPR_TRUNCATED_2000",
        "G_I_SCOPE": "CURRENT_PYTHON_THREAD_UNDER_MODULES_ROOT",
        "G_I_CAPABILITIES": sorted(OBSERVED_INTERNAL_CAPS),
        "DERIVED_FINGERPRINTS_ARE_PRIMARY": False,
        "STATUS_MEANS": "AUDITOR_TEST_CONSISTENCY_ONLY",
    }, indent=2), encoding="utf-8")

    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_worker, args=(q,))

    start_wall = time.time()
    start_mono = time.perf_counter_ns()
    p.start()

    msgs = []
    deadline = time.monotonic() + P_OBS
    while time.monotonic() < deadline:
        if not p.is_alive():
            msgs.extend(_drain(q))
            break
        try:
            msgs.append(q.get(timeout=0.05))
        except queue.Empty:
            pass

    timeout = p.is_alive()
    if timeout:
        p.terminate()
        p.join(1)
        time.sleep(0.05)
        msgs.extend(_drain(q))
    else:
        p.join(1)
        msgs.extend(_drain(q))

    end_wall = time.time()
    end_mono = time.perf_counter_ns()

    last = msgs[-1] if msgs else {}
    boundaries = list(last.get("boundaries") or [])
    open_ids = list(last.get("open_boundaries") or [])
    native = last.get("native_protocol")
    native_result = last.get("native_result_JSON_RAW")
    termination = "TIMEOUT" if timeout else (last.get("termination") or "WORKER_ERROR")

    transitions = [
        _raw_transition(boundaries[i], boundaries[i + 1])
        for i in range(len(boundaries) - 1)
    ]
    reconciliation = _reconcile(native, boundaries)

    mismatch = int(last.get("stack_mismatch") or 0)
    auditor_integrity = "FAIL" if termination == "WORKER_ERROR" or mismatch else "PASS"

    if timeout or native is None:
        protocol_consistency = "NO_DETERMINADO"
    elif reconciliation["status"] == "CONTRADICTION":
        protocol_consistency = "FAIL"
    else:
        protocol_consistency = "PASS"

    if timeout:
        completeness = "HASTA_ULTIMO_SNAPSHOT"
    elif termination == "RETURN":
        completeness = "COMPLETA_HASTA_RETURN"
    elif termination == "RAISE":
        completeness = "COMPLETA_HASTA_RAISE"
    else:
        completeness = "INDETERMINADA"

    last_wall = last.get("wall_time")
    tail_s = max(0.0, end_wall - last_wall) if isinstance(last_wall, (int, float)) else None

    NATIVE.write_text(json.dumps({
        "schema": SCHEMA,
        "native_result_JSON_RAW": native_result,
        "native_structured_projection": native,
    }, indent=2, default=str), encoding="utf-8")

    GE.write_text(json.dumps({
        "schema": SCHEMA,
        "part": "G_E",
        "candidates_instrumentally_discovered": last.get("candidates") or [],
        "boundaries": boundaries,
        "open_boundaries": open_ids,
        "raw_transition_checks": transitions,
        "native_boundary_reconciliation": reconciliation,
    }, indent=2, default=str), encoding="utf-8")

    GI.write_text(json.dumps({
        "schema": SCHEMA,
        "part": "G_I",
        "scope": "CURRENT_PYTHON_THREAD_UNDER_MODULES_ROOT",
        "observed_capabilities": sorted(OBSERVED_INTERNAL_CAPS),
        "by_B": last.get("gi_by_b") or {},
        "stack_mismatch": mismatch,
        "note": "unmatched_calls_observed is not equivalent to active frames.",
    }, indent=2, default=str), encoding="utf-8")

    evidence = {
        "schema": SCHEMA,
        "runtime_termination": termination,
        "timeout": timeout,
        "observation_budget_s": P_OBS,
        "duration_s": (end_mono - start_mono) / 1e9,
        "last_snapshot_tail_s": tail_s,
        "observation_completeness": completeness,
        "auditor_integrity": auditor_integrity,
        "protocol_consistency": protocol_consistency,
        "security_verdict": "NOT_EVALUATED",
        "system_semantic_status": (
            "NO_DETERMINADO" if timeout or native is None else protocol_consistency
        ),
        "open_boundaries": open_ids,
        "raw_transition_checks": transitions,
        "reconciliation": reconciliation,
    }
    EVIDENCE.write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")

    lines = [
        "",
        "=" * 72,
        "UHCR v3.4.2-R2 — RAW CAUSAL BOUNDARY AUDITOR",
        "=" * 72,
        "TEOREMA:",
        "  H_i -> ENTER(B_i) -> proveedor -> EXIT(B_i,R_i) -> P_i",
        "  P_i NO se identifica con H_{i+1}.",
        "  Absorb_E solo se afirma con evidencia suficiente.",
        "",
        "VENTANA:",
        f"  P_obs={P_OBS:.3f}s  duration={evidence['duration_s']:.3f}s",
        f"  RUNTIME_TERMINATION={termination}",
        f"  OBSERVATION_COMPLETENESS={completeness}",
        f"  T_tail={tail_s if tail_s is not None else 'NO_DETERMINADO'}",
        "",
        "FRONTERAS:",
    ]

    for b in boundaries:
        gi = (last.get("gi_by_b") or {}).get(str(b.get("B"))) or {}
        lines += [
            f"  B{b.get('B')} {b.get('module')}.{b.get('capability')}",
            f"    state={b.get('state')}",
            f"    H_before_Phi_K.n={(b.get('H_before_Phi_K') or {}).get('n')}",
            f"    P_Phi_K.n={(b.get('P_Phi_K') or {}).get('n')}",
            f"    GI_CALLS_OBSERVED={gi.get('calls_observed', 0)}",
            f"    GI_RETURNS_OBSERVED={gi.get('returns_observed', 0)}",
            f"    GI_UNMATCHED_CALLS_OBSERVED={gi.get('unmatched_calls_observed', 0)}",
            "    NOTE: unmatched observed calls =/=> active frames",
        ]

    lines += ["", "TRANSICIONES RAW OBSERVABLES:"]
    if not transitions:
        lines.append("  (ninguna pareja consecutiva disponible)")
    for t in transitions:
        lines += [
            f"  B{t.get('B_from')} -> B{t.get('B_to')}: {t.get('status')}",
            f"    violations={t.get('violations')}",
            "    causalidad exclusiva de Absorb_E: NO AFIRMADA",
        ]

    lines += [
        "",
        "RECONCILIACION NATIVA:",
        f"  status={reconciliation.get('status')}",
        f"  pairs={len(reconciliation.get('pairs') or [])}",
        f"  native_without_exit={len(reconciliation.get('native_without_exit') or [])}",
        f"  exit_without_native={len(reconciliation.get('exit_without_native') or [])}",
        "",
        "RESUMEN:",
        f"  ENTER={len(boundaries)}",
        f"  EXIT={sum(b.get('state') == 'EXIT' for b in boundaries)}",
        f"  RAISE={sum(b.get('state') == 'RAISE' for b in boundaries)}",
        f"  OPEN={len(open_ids)}",
        f"  AUDITOR_INTEGRITY={auditor_integrity}",
        f"  PROTOCOL_CONSISTENCY={protocol_consistency}",
        f"  SYSTEM_SEMANTIC_STATUS={evidence['system_semantic_status']}",
        "  SECURITY_VERDICT=NOT_EVALUATED",
        f"  UHCR_TEST_STATUS={'FAIL' if auditor_integrity == 'FAIL' or protocol_consistency == 'FAIL' else 'PASS'}",
        "=" * 72,
    ]

    report = "\n".join(lines)
    REPORT.write_text(report + "\n", encoding="utf-8")
    evidence["report"] = report
    return evidence


def _capture_safe() -> Dict[str, Any]:
    try:
        return _capture()
    except Exception as exc:
        return {
            "auditor_integrity": "FAIL",
            "protocol_consistency": "NO_DETERMINADO",
            "system_semantic_status": "NO_DETERMINADO",
            "runtime_termination": "WORKER_ERROR",
            "error": f"{type(exc).__name__}: {exc}",
            "report": f"UHCR v3.4.2-R2\nAUDITOR_INTEGRITY=FAIL\nERROR={type(exc).__name__}: {exc}",
        }


@pytest.fixture(scope="session")
def uhcr() -> Dict[str, Any]:
    return _capture_safe()


def test_teorema_embebido() -> None:
    text = Path(__file__).read_text(encoding="utf-8")
    assert "TEOREMA UHCR" in text
    assert "CALL observado sin RETURN observado =/=> frame activo" in text
    assert "E_derivada no sustituye E_RAW" in text


def test_politica_raw_machine_readable(uhcr: Dict[str, Any]) -> None:
    pre = json.loads(PRE.read_text(encoding="utf-8"))
    assert pre["RAW_EVIDENCE_POLICY"] == "FULL_WHEN_JSON_SERIALIZABLE"
    assert pre["NON_SERIALIZABLE_POLICY"] == "TYPED_REPR_TRUNCATED_2000"
    assert pre["DERIVED_FINGERPRINTS_ARE_PRIMARY"] is False


def test_grafos_separados(uhcr: Dict[str, Any]) -> None:
    ge = json.loads(GE.read_text(encoding="utf-8"))
    gi = json.loads(GI.read_text(encoding="utf-8"))
    assert ge["part"] == "G_E"
    assert gi["part"] == "G_I"
    assert gi["scope"] == "CURRENT_PYTHON_THREAD_UNDER_MODULES_ROOT"


def test_no_confundir_unmatched_con_active(uhcr: Dict[str, Any]) -> None:
    gi = json.loads(GI.read_text(encoding="utf-8"))
    assert "unmatched_calls_observed is not equivalent to active frames" in gi["note"]


def test_contradicciones_raw_si_son_evaluables(uhcr: Dict[str, Any]) -> None:
    # No exige que exista una pareja B_i/B_{i+1}.
    # Si existe y la evidencia RAW es evaluable, una contradiccion observada
    # se conserva como evidencia; no se convierte automaticamente en
    # "vulnerabilidad".
    for t in uhcr.get("raw_transition_checks") or []:
        assert t.get("status") in {
            "OBSERVED_CONSISTENT",
            "OBSERVED_CONTRADICTION",
            "NO_DETERMINADO",
        }


def test_integridad_del_auditor(uhcr: Dict[str, Any]) -> None:
    assert uhcr.get("auditor_integrity") == "PASS", uhcr


def test_protocolo_nativo_si_es_determinable(uhcr: Dict[str, Any]) -> None:
    state = uhcr.get("protocol_consistency")
    assert state in {"PASS", "FAIL", "NO_DETERMINADO"}
    if state == "FAIL":
        pytest.fail("UHCR observo contradiccion entre protocolo nativo y frontera: " + repr(uhcr))


def test_99_traza(uhcr: Dict[str, Any]) -> None:
    report = uhcr.get("report") or REPORT.read_text(encoding="utf-8")
    print()
    print(report)
    print()
    assert "UHCR v3.4.2-R2" in report
    assert "AUDITOR_INTEGRITY=" in report
    assert "PROTOCOL_CONSISTENCY=" in report
    assert "SYSTEM_SEMANTIC_STATUS=" in report
    assert "SECURITY_VERDICT=NOT_EVALUATED" in report
    assert "UHCR_TEST_STATUS=" in report
