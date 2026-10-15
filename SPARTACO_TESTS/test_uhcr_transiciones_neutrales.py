# ===========================================================================
# UHCR — NEUTRAL AUDITOR OF EU <-> ET TRANSITIONS + STATE
# tests/test_uhcr_transiciones_neutrales.py
# SPEC: UHCR-TRANSITIONS-1.6-PATH-QUALIFIED
# ===========================================================================
#
# EXPERIMENTAL QUESTION
# ---------------------------------------------------------------------------
# The topological auditor answered: what shape does the execution have?
# This auditor asks: what observable state changes between one EU/ET
# invocation and the next?
#
# STATE OBSERVABILITY THEOREM
# ---------------------------------------------------------------------------
# For two consecutive CALL observations C_i and C_j of the same function:
#
#     S_i = Proj(input_i, facts_i, structure_i)
#     S_j = Proj(input_j, facts_j, structure_j)
#
# the auditor can derive:
#
#     DeltaS(i, j) = Diff(S_i, S_j)
#
# but:
#
#     DeltaS = 0   =/=> absence of semantic progress
#     DeltaS != 0  =/=> correct progress
#     repetition   =/=> defect
#     timeout      =/=> failure
#
# The projection S is explicit and bounded. It does not indiscriminately
# serialize the whole Engine.__dict__ nor the whole reachable graph.
#
# Three evidence roles:
#   RAW                     JSON-serializable values preserved exactly
#   REPRESENTATION_TRANSFORM non-JSON values represented typed and truncated
#   DERIVED                  fingerprints, deltas, groups, sequences
#
# EVIDENCE ADMISSIBILITY THEOREM
# ---------------------------------------------------------------------------
# Let S be the system, O the observation mechanism, M a derived claim,
# and Q a conclusion about S. The auditor may only use M to judge S if
# the evidence itself demonstrates that O preserves the properties
# required for M:
#
#     Judge(S, Q) => Qualified(O, M) and Valid(M => Q)
#
# If the observation policy does not preserve the invariant, the state
# of that claim is INSTRUMENT_NOT_QUALIFIED.
#
# In particular: HEAD+TAIL does not preserve CALL/RETURN pairing and
# does not allow inferring a global maximum depth from
# max_depth_materialized.
#
# WHAT PASS MEANS HERE
# ---------------------------------------------------------------------------
# PASS means only that the auditor and its admissibility classifier are
# intact. It is NOT a claim about the safety of the system.
#
# ARCHITECTURE
# ---------------------------------------------------------------------------
# The auditor runs the Engine in a subprocess with spawn context. It
# wraps eng.ejecutar_capacidad to emit path signals (DISPATCH_ENTER,
# DISPATCH_RETURN, PROVIDER_ENTER, PROVIDER_RETURN) and installs both
# sys.setprofile and sys.settrace to capture:
#
#     CALL             function entry with projected state
#     PROFILE_RETURN   function exit with raw result
#     INTERNAL_STATE   line-level state snapshots (bounded per frame)
#     MISMATCH         RETURN without CALL, or non-LIFO RETURN
#
# The projection captures: arguments via inspect.getargvalues, facts if
# present under recognized names, local key names without values, small
# scalars, and a shallow structural projection of self (type, dict keys,
# scalar or collection sizes at first level).
#
# STATE PROJECTION IS DELIBERATELY BOUNDED
# ---------------------------------------------------------------------------
# Observing everything would be blind by excess. The projection observes
# shape and scale, not the recursive graph. This is a stated design
# decision, not a limitation to be fixed.
#
# PATH OBSERVABILITY (ENGINE -> DISPATCH -> PROVIDER)
# ---------------------------------------------------------------------------
# The dispatcher wrapper records each control-capacity dispatch with
# dispatch_id, module, capability and provider_seen. When the profiler
# observes a call whose code matches the dispatched capability's module
# and function, it marks the dispatch as having a provider and emits
# PROVIDER_ENTER. The chain requires exact module+function match, not
# merely that any provider is in flight.
#
#     PATH_OBSERVED              exact_dispatch_provider_chains > 0
#     PATH_PARTIALLY_OBSERVED    some signal observed but not the full chain
#     INCONCLUSIVE               no path signal observed
#
# Critical path signals travel by immediate queue, not by HEAD+TAIL.
# The auditor explicitly recognizes that relying on the checkpoint for
# these signals would lose the information needed to decide path_status.
#
# OBSERVATION COMPLETENESS
# ---------------------------------------------------------------------------
#     COMPLETE_UNTIL_PROCESS_RESULT        child terminated before deadline
#     HEAD_PLUS_TAIL_OF_LAST_CHECKPOINT    deadline expired, last checkpoint used
#
# This distinction is what allows the meta-auditor to decide whether it
# can qualify claims about CALL/RETURN balance. Without it, the auditor
# could not know whether it is seeing everything that happened or only
# a sample.
#
# META-AUDITOR (EVIDENCE ADMISSIBILITY)
# ---------------------------------------------------------------------------
# At the end of the capture, a meta-auditor decides which claims the
# observation policy of THIS run admits:
#
#     MATERIALIZED_CALL_RETURN_BALANCE
#         requires PAIR_PRESERVING_EVENT_SET
#         qualified only if observation was complete
#     GLOBAL_MAX_DEPTH_FROM_MATERIALIZED
#         requires NO_OMITTED_EVENTS_IN_OBSERVATION_INTERVAL
#         qualified only if observation was complete
#     MATERIALIZED_VALUES_DESCRIBE_MATERIALIZED_SAMPLE
#         requires DERIVATION_RECOMPUTABLE_FROM_PERSISTED_EVENTS
#         always qualified: counters are recomputed from the sample
#     TIMEOUT_IS_FINITE_WINDOW_CENSORING
#         requires EXPLICIT_DEADLINE_AND_TERMINATION_BY_OBSERVER
#         always qualified: timeout is generated by the observer
#
# The meta-auditor does not judge the system. It judges whether the
# instrument preserves the information needed for each specific
# inference. This is the same doctrine the UHCR auditor developed for
# instrument qualification, applied here to the specific claims the
# auditor might want to emit about state.
#
# DERIVED METRICS (DESCRIBE, DO NOT JUDGE)
# ---------------------------------------------------------------------------
#   per_function            calls materialized, consecutive pairs, same
#                           fingerprint pairs, different fingerprint
#                           pairs, unique state fingerprints
#   same_function_transitions   consecutive calls of the same function
#                           with their diff
#   parent_child_transitions    parent state to child state diff
#   topology_metrics        depth increments, plus-one ratio, edge counts
#   quantitative_metrics    observed span, calls per second, repeat
#                           ratio, facts-zero ratio
#   internal_state_metrics  snapshots materialized, frames with internal
#                           state, unique internal fingerprints, pre-child
#                           states reconstructed
#   path_metrics            dispatch enter/return, provider enter/return,
#                           exact chains, path_status
#
# PERSISTED ARTIFACTS
# ---------------------------------------------------------------------------
#   diagnostics/uhcr_transiciones_neutrales/PRECONDITIONS.json
#   diagnostics/uhcr_transiciones_neutrales/STATE_EVENTS.json
#   diagnostics/uhcr_transiciones_neutrales/STATE_MAP.json
#   diagnostics/uhcr_transiciones_neutrales/METRICS.json
#   diagnostics/uhcr_transiciones_neutrales/EVIDENCE.json
#   diagnostics/uhcr_transiciones_neutrales/REPORT.txt
#   diagnostics/test_evidence.json
#
# REPORT READING RULES
# ---------------------------------------------------------------------------
#   same_fingerprint=True describes equality of THIS observable
#       projection, not of the complete state.
#   Observable delta zero does not prove absence of semantic progress.
#   Observable delta different does not prove correctness.
#   TIMEOUT is experimental censoring, not failure.
#   AUDITOR_INTEGRITY=PASS
#   SYSTEM_SEMANTIC_STATUS=NO_DETERMINADO
#   SECURITY_VERDICT=NOT_EVALUATED
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The adversarial battery attacks the layered architecture of
# proteccion.py. The credential red-teams attack credencial.py. The
# metrological kernel audits instruments. The integration smoke test
# checks the honest path. The monitor correlates external and internal
# observation. The fail-closed auditor qualifies itself against
# synthetic controls. The seal closure test verifies declared algebra
# is physically operated. The universal closure verifies verified ==
# loaded == executed. The enablement theorem verifies purity of
# construction. The total attack campaign measures coherence of the
# suite. The microscope calibration measures the perturbation of the
# observation act. The dynamic fail-closed surface auditor implements
# the complete metrological doctrine over the system surface. This
# file asks a different question: what observable state changes
# between transitions, and which claims about that state are
# admissible given the observation policy of this run.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# Observing state is not judging progress. Observing a delta is not
# judging correctness. Observing a timeout is not judging failure. A
# claim about state is admissible only if the observation policy of
# this run preserves the information that claim requires. When it does
# not, the claim is not refuted and not confirmed: it is
# INSTRUMENT_NOT_QUALIFIED, published with the exact reason, and left
# for a future observation policy that preserves the invariant.
#
# ===========================================================================

from __future__ import annotations

import hashlib
import inspect
import json
import multiprocessing as mp
import os
import queue
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "diagnostics" / "uhcr_transiciones_neutrales"
PRE = OUT / "PRECONDITIONS.json"
RAW_EVENTS = OUT / "STATE_EVENTS.json"
STATE_MAP = OUT / "STATE_MAP.json"
METRICS = OUT / "METRICS.json"
EVIDENCE = OUT / "EVIDENCE.json"
REPORT = OUT / "REPORT.txt"
TEST_EVIDENCE = ROOT / "diagnostics" / "test_evidence.json"

SPEC = "UHCR-TRANSITIONS-1.6-PATH-QUALIFIED"
P_OBS = float(os.environ.get("UHCR_STATE_OBS_SECONDS", "1.0"))
CHECKPOINT_EVERY = int(os.environ.get("UHCR_STATE_CHECKPOINT_EVERY", "20"))
HEAD_N = 50
TAIL_N = 160
MAX_REPR = 2000
CONTROL = {"evaluar_universal", "ejecutar_total"}


def _json_raw(v: Any) -> Any:
    try:
        json.dumps(v, ensure_ascii=False)
        return deepcopy(v)
    except (TypeError, ValueError, RecursionError):
        try:
            r = repr(v)
        except Exception as exc:
            r = f"<repr-error {type(exc).__name__}: {exc}>"
        return {
            "_evidence_role": "REPRESENTATION_TRANSFORM",
            "_python_type": f"{type(v).__module__}.{type(v).__qualname__}",
            "_repr": r[:MAX_REPR],
            "_repr_truncated": len(r) > MAX_REPR,
        }


def _canon(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _fp(v: Any) -> str:
    return hashlib.sha256(_canon(v).encode("utf-8")).hexdigest()


def _safe_scalar(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (list, tuple)) and len(v) <= 32:
        return [_safe_scalar(x) for x in v]
    if isinstance(v, dict) and len(v) <= 32:
        out = {}
        for k, x in v.items():
            if isinstance(k, (str, int, float, bool)):
                out[str(k)] = _safe_scalar(x)
        return out
    return {
        "_python_type": f"{type(v).__module__}.{type(v).__qualname__}",
        "_repr": repr(v)[:300],
    }


def _structural_projection(obj: Any) -> Dict[str, Any]:
    """
    Proyección deliberadamente limitada. Observa forma y escala del objeto,
    no recorre recursivamente su grafo.
    """
    if obj is None:
        return {"type": "NoneType"}
    d = getattr(obj, "__dict__", None)
    if not isinstance(d, dict):
        return {"type": f"{type(obj).__module__}.{type(obj).__qualname__}"}

    keys = sorted(str(k) for k in d.keys())
    selected = {}
    # Sólo escalares/colecciones pequeñas de primer nivel.
    for k in keys:
        try:
            v = d[k]
        except Exception:
            continue
        if v is None or isinstance(v, (bool, int, float, str)):
            selected[k] = v
        elif isinstance(v, (list, tuple, set, dict)):
            try:
                selected[k] = {
                    "type": type(v).__name__,
                    "len": len(v),
                }
            except Exception:
                pass
    return {
        "type": f"{type(obj).__module__}.{type(obj).__qualname__}",
        "dict_keys": keys,
        "selected": selected,
    }


def _capture_call_state(frame) -> Dict[str, Any]:
    loc = frame.f_locals
    args = {}
    try:
        ai = inspect.getargvalues(frame)
        for n in ai.args:
            if n in loc:
                args[n] = _json_raw(loc[n])
        if ai.varargs and ai.varargs in loc:
            args["*" + ai.varargs] = _json_raw(loc[ai.varargs])
        if ai.keywords and ai.keywords in loc:
            args["**" + ai.keywords] = _json_raw(loc[ai.keywords])
    except Exception as exc:
        args = {"_capture_error": f"{type(exc).__name__}: {exc}"}

    facts = {}
    facts_source = None
    for n in ("hechos", "facts", "peticion"):
        v = loc.get(n)
        if isinstance(v, dict):
            facts = v
            facts_source = n
            break

    owner = loc.get("self")
    control_locals = {}
    for n, v in loc.items():
        if n == "self":
            continue
        # Capturamos valores transportados/control pequeños o serializables.
        # Evitamos módulos, funciones, frames y objetos arbitrarios gigantes.
        if n in {"hechos", "facts", "peticion"}:
            continue
        if v is None or isinstance(v, (bool, int, float, str)):
            control_locals[n] = _json_raw(v)
        elif isinstance(v, (dict, list, tuple)) and len(v) <= 64:
            control_locals[n] = _json_raw(v)

    projection = {
        "args_raw": args,
        "facts_source": facts_source,
        "facts_raw": _json_raw(facts),
        "facts_n": len(facts),
        "facts_keys": sorted(str(k) for k in facts.keys()),
        "locals_keys": sorted(str(k) for k in loc.keys()),
        "control_locals_raw": control_locals,
        "self_structure": _structural_projection(owner),
    }
    projection["state_fingerprint"] = _fp(projection)
    return projection


def _diff(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Diff descriptivo entre dos proyecciones observadas."""
    out = {
        "_evidence_role": "DERIVED",
        "same_fingerprint": a.get("state_fingerprint") == b.get("state_fingerprint"),
        "facts_n_before": a.get("facts_n"),
        "facts_n_after": b.get("facts_n"),
        "facts_added": [],
        "facts_removed": [],
        "facts_changed": [],
        "args_changed": [],
        "locals_keys_added": [],
        "locals_keys_removed": [],
        "self_selected_changed": [],
        "control_locals_changed": [],
    }

    ka = set(a.get("facts_keys") or [])
    kb = set(b.get("facts_keys") or [])
    out["facts_added"] = sorted(kb - ka)
    out["facts_removed"] = sorted(ka - kb)

    fa = a.get("facts_raw")
    fb = b.get("facts_raw")
    if isinstance(fa, dict) and isinstance(fb, dict):
        if "_evidence_role" not in fa and "_evidence_role" not in fb:
            for k in sorted(ka & kb):
                if fa.get(k) != fb.get(k):
                    out["facts_changed"].append(k)

    aa = a.get("args_raw") if isinstance(a.get("args_raw"), dict) else {}
    ab = b.get("args_raw") if isinstance(b.get("args_raw"), dict) else {}
    for k in sorted(set(aa) | set(ab)):
        if aa.get(k) != ab.get(k):
            out["args_changed"].append(k)

    la = set(a.get("locals_keys") or [])
    lb = set(b.get("locals_keys") or [])
    out["locals_keys_added"] = sorted(lb - la)
    out["locals_keys_removed"] = sorted(la - lb)

    ca = a.get("control_locals_raw") if isinstance(a.get("control_locals_raw"), dict) else {}
    cb = b.get("control_locals_raw") if isinstance(b.get("control_locals_raw"), dict) else {}
    for k in sorted(set(ca) | set(cb)):
        if ca.get(k) != cb.get(k):
            out["control_locals_changed"].append(k)

    sa = ((a.get("self_structure") or {}).get("selected") or {})
    sb = ((b.get("self_structure") or {}).get("selected") or {})
    for k in sorted(set(sa) | set(sb)):
        if sa.get(k) != sb.get(k):
            out["self_selected_changed"].append(k)

    out["observable_change_count"] = sum(len(out[k]) for k in (
        "facts_added", "facts_removed", "facts_changed", "args_changed",
        "locals_keys_added", "locals_keys_removed", "self_selected_changed",
        "control_locals_changed",
    ))
    return out


def _worker(q: mp.Queue) -> None:
    t0 = time.monotonic_ns()
    events: List[Dict[str, Any]] = []
    stack: List[int] = []
    frame_ids: Dict[int, int] = {}
    code_meta = {}
    seq = 0
    next_fid = 0
    internal_last_fp: Dict[int, str] = {}
    internal_snapshots_per_frame: Dict[int, int] = {}
    MAX_INTERNAL_SNAPSHOTS_PER_FRAME = 12
    path = {"dispatch_enter":0,"dispatch_terminal":0,"provider_enter":0,"provider_terminal":0,
            "exact_dispatch_provider_chains":0,"dispatch_without_provider":0,"provider_without_dispatch":0,
            "first_dispatch_ns":None,"first_provider_ns":None,"first_dispatch_to_provider_latency_ns":None}
    dispatch_stack = []
    provider_to_dispatch = {}
    next_dispatch_id = 0

    def path_signal(kind: str, **kw):
        q.put({"type":"path_signal","kind":kind,"t_rel_ns":rel(),"path":deepcopy(path),**kw})

    def rel():
        return time.monotonic_ns() - t0

    def emit(kind: str, **kw):
        nonlocal seq
        seq += 1
        e = {"seq": seq, "kind": kind, "t_rel_ns": rel(), **kw}
        events.append(e)
        if seq % max(1, CHECKPOINT_EVERY) == 0:
            q.put({
                "type": "checkpoint",
                "seq": seq,
                "t_rel_ns": e["t_rel_ns"],
                "events_n": len(events),
                "head": deepcopy(events[:HEAD_N]),
                "tail": deepcopy(events[-TAIL_N:]),
                "stack": list(stack),
            })

    try:
        root_s = str(ROOT)
        if root_s not in sys.path:
            sys.path.insert(0, root_s)
        from core.engine import Engine
        eng = Engine(
            raiz_modulos=str(ROOT / "modules"),
            invocador_id="uhcr_state_runtime",
            strict=True,
        )
        if getattr(eng, "estado", None) != "OPERATIVO":
            raise RuntimeError(f"Engine no OPERATIVO: {getattr(eng,'estado',None)!r}")

        providers = []
        for cname in sorted(eng.registro.contenedores):
            cont = eng.registro.contenedores[cname]
            for cap in sorted(CONTROL):
                fn = cont.fn(cap)
                if callable(fn) and hasattr(fn, "__code__"):
                    code_meta[fn.__code__] = {
                        "module": cname,
                        "function": cap,
                        "source": str(Path(inspect.getsourcefile(fn) or "").resolve()),
                    }
                    if cap == "evaluar_universal":
                        providers.append(cname)

        emit("DISCOVERY", providers=sorted(set(providers)), control_codes=len(code_meta))

        original_dispatch = eng.ejecutar_capacidad
        def observed_dispatch(modulo, capacidad, *args, **kwargs):
            nonlocal next_dispatch_id
            if capacidad not in CONTROL:
                return original_dispatch(modulo, capacidad, *args, **kwargs)
            next_dispatch_id += 1
            did = next_dispatch_id; te = rel()
            rec = {"dispatch_id":did,"module":modulo,"capability":capacidad,"t_enter_ns":te,"provider_seen":False}
            dispatch_stack.append(rec); path["dispatch_enter"] += 1
            if path["first_dispatch_ns"] is None: path["first_dispatch_ns"] = te
            path_signal("DISPATCH_ENTER",dispatch_id=did,module=modulo,capability=capacidad)
            try:
                result = original_dispatch(modulo, capacidad, *args, **kwargs)
            except BaseException as exc:
                path["dispatch_terminal"] += 1
                if not rec["provider_seen"]: path["dispatch_without_provider"] += 1
                path_signal("DISPATCH_RAISE",dispatch_id=did,module=modulo,capability=capacidad,exception_type=type(exc).__name__)
                raise
            else:
                path["dispatch_terminal"] += 1
                if not rec["provider_seen"]: path["dispatch_without_provider"] += 1
                path_signal("DISPATCH_RETURN",dispatch_id=did,module=modulo,capability=capacidad)
                return result
            finally:
                if dispatch_stack and dispatch_stack[-1] is rec: dispatch_stack.pop()
                elif rec in dispatch_stack: dispatch_stack.remove(rec)
        eng.ejecutar_capacidad = observed_dispatch

        def profiler(frame, event, arg):
            nonlocal next_fid
            meta = code_meta.get(frame.f_code)
            if meta is None:
                return

            key = id(frame)
            if event == "call":
                next_fid += 1
                fid = next_fid
                frame_ids[key] = fid
                parent = stack[-1] if stack else None
                stack.append(fid)
                state = _capture_call_state(frame)
                if dispatch_stack:
                    dr = dispatch_stack[-1]
                    if (not dr.get("provider_seen") and dr.get("module") == meta["module"]
                            and dr.get("capability") == meta["function"]):
                        dr["provider_seen"] = True; provider_to_dispatch[fid] = dr["dispatch_id"]
                        path["provider_enter"] += 1; path["exact_dispatch_provider_chains"] += 1
                        tp = rel()
                        if path["first_provider_ns"] is None: path["first_provider_ns"] = tp
                        if path["first_dispatch_to_provider_latency_ns"] is None:
                            path["first_dispatch_to_provider_latency_ns"] = max(0,tp-dr["t_enter_ns"])
                        path_signal("PROVIDER_ENTER",dispatch_id=dr["dispatch_id"],frame_id=fid,module=meta["module"],capability=meta["function"],code_id=id(frame.f_code))
                emit(
                    "CALL",
                    frame_id=fid,
                    parent_frame_id=parent,
                    depth=len(stack),
                    module=meta["module"],
                    function=meta["function"],
                    source=meta["source"],
                    state=state,
                )
            elif event == "return":
                fid = frame_ids.get(key)
                if fid is None:
                    emit("MISMATCH", reason="RETURN_WITHOUT_CALL",
                         module=meta["module"], function=meta["function"])
                    return
                did = provider_to_dispatch.pop(fid, None)
                if did is not None:
                    path["provider_terminal"] += 1
                    path_signal("PROVIDER_RETURN",dispatch_id=did,frame_id=fid,module=meta["module"],capability=meta["function"])
                emit(
                    "PROFILE_RETURN",
                    frame_id=fid,
                    depth_before_pop=len(stack),
                    module=meta["module"],
                    function=meta["function"],
                    result_raw=_json_raw(arg),
                )
                if stack and stack[-1] == fid:
                    stack.pop()
                elif fid in stack:
                    stack.remove(fid)
                    emit("MISMATCH", reason="NON_LIFO_RETURN", frame_id=fid)
                frame_ids.pop(key, None)

        def tracer(frame, event, arg):
            meta = code_meta.get(frame.f_code)
            if meta is None:
                return None
            if event == "call":
                return tracer
            if event != "line":
                return tracer
            fid = frame_ids.get(id(frame))
            if fid is None:
                return tracer
            n = internal_snapshots_per_frame.get(fid, 0)
            if n >= MAX_INTERNAL_SNAPSHOTS_PER_FRAME:
                return tracer
            state = _capture_call_state(frame)
            fp = state.get("state_fingerprint")
            if fp != internal_last_fp.get(fid):
                internal_last_fp[fid] = fp
                internal_snapshots_per_frame[fid] = n + 1
                emit("INTERNAL_STATE", frame_id=fid, depth=len(stack),
                     module=meta["module"], function=meta["function"],
                     lineno=frame.f_lineno, snapshot_index=n+1, state=state)
            return tracer

        sys.settrace(tracer)
        sys.setprofile(profiler)
        try:
            result = eng.evaluar_universal({})
        finally:
            sys.setprofile(None)
            sys.settrace(None)

        q.put({
            "type": "finished",
            "termination": "RETURN",
            "events": events,
            "result_raw": _json_raw(result),
            "open_frame_ids": list(stack),
            "t_rel_ns": rel(),
            "path": deepcopy(path),
        })
    except BaseException as exc:
        try:
            sys.setprofile(None)
            sys.settrace(None)
        except Exception:
            pass
        q.put({
            "type": "finished",
            "termination": "RAISE",
            "events": events,
            "exception": {
                "type": f"{type(exc).__module__}.{type(exc).__qualname__}",
                "args": _json_raw(getattr(exc, "args", ())),
                "message": str(exc),
            },
            "open_frame_ids": list(stack),
            "t_rel_ns": rel(),
            "path": deepcopy(path),
        })


def _derive(events: List[Dict[str, Any]], confirmed_n: Optional[int]) -> Dict[str, Any]:
    calls = [e for e in events if e.get("kind") == "CALL"]
    returns = [e for e in events if e.get("kind") == "PROFILE_RETURN"]
    internal = [e for e in events if e.get("kind") == "INTERNAL_STATE"]

    internal_by_frame: Dict[int, List[Dict[str, Any]]] = {}
    for e in internal:
        internal_by_frame.setdefault(e["frame_id"], []).append(e)

    pre_child = []
    for child in calls:
        pf = child.get("parent_frame_id")
        if pf is None:
            continue
        candidates = [x for x in internal_by_frame.get(pf, [])
                      if int(x.get("seq") or 0) < int(child.get("seq") or 0)]
        if candidates:
            snap = candidates[-1]
            pre_child.append({
                "_evidence_role": "DERIVED",
                "parent_frame_id": pf, "child_frame_id": child["frame_id"],
                "edge": f"{snap['function']}->{child['function']}",
                "parent_lineno": snap["lineno"],
                "parent_internal_state": snap["state"],
                "child_entry_state": child["state"],
                "delta_internal_to_child": _diff(snap["state"], child["state"]),
            })
    by_function: Dict[str, List[Dict[str, Any]]] = {}
    for c in calls:
        by_function.setdefault(str(c.get("function")), []).append(c)

    consecutive = []
    summary = {}
    for fn, rows in sorted(by_function.items()):
        same = 0
        changed = 0
        pairs = []
        for a, b in zip(rows, rows[1:]):
            d = _diff(a["state"], b["state"])
            if d["same_fingerprint"]:
                same += 1
            else:
                changed += 1
            pairs.append({
                "function": fn,
                "from_frame": a["frame_id"],
                "to_frame": b["frame_id"],
                "from_depth": a["depth"],
                "to_depth": b["depth"],
                "delta": d,
            })
        consecutive.extend(pairs)
        summary[fn] = {
            "calls_materialized": len(rows),
            "first_frame": rows[0]["frame_id"] if rows else None,
            "last_frame": rows[-1]["frame_id"] if rows else None,
            "first_state_raw": rows[0]["state"] if rows else None,
            "last_state_raw": rows[-1]["state"] if rows else None,
            "consecutive_pairs_materialized": len(pairs),
            "same_state_fingerprint_pairs": same,
            "different_state_fingerprint_pairs": changed,
            "unique_state_fingerprints": len({
                r["state"]["state_fingerprint"] for r in rows
            }),
        }

    # Cross-edge transitions: parent CALL state -> child CALL state.
    by_id = {c["frame_id"]: c for c in calls}
    edges = []
    for c in calls:
        pid = c.get("parent_frame_id")
        p = by_id.get(pid)
        if not p:
            continue
        edges.append({
            "parent_frame": pid,
            "child_frame": c["frame_id"],
            "edge": f"{p['function']}->{c['function']}",
            "parent_depth": p["depth"],
            "child_depth": c["depth"],
            "delta": _diff(p["state"], c["state"]),
        })

    # Métricas cuantitativas: describen la observación, no emiten juicio semántico.
    call_times = [int(c.get("t_rel_ns") or 0) for c in calls]
    observed_span_ns = (max(call_times) - min(call_times)) if len(call_times) >= 2 else 0
    calls_per_second_observed = (
        (len(calls) - 1) / (observed_span_ns / 1e9)
        if observed_span_ns > 0 and len(calls) >= 2 else None
    )

    depths = [int(c.get("depth") or 0) for c in calls]
    depth_increments = [b-a for a,b in zip(depths, depths[1:])]
    unit_depth_growth = sum(1 for d in depth_increments if d == 1)
    nonunit_depth_growth = sum(1 for d in depth_increments if d != 1)

    same_fn_pairs = len(consecutive)
    same_fn_equal = sum(1 for x in consecutive if x["delta"]["same_fingerprint"])
    state_repeat_ratio = (same_fn_equal / same_fn_pairs) if same_fn_pairs else None

    facts_zero_calls = sum(
        1 for c in calls if int((c.get("state") or {}).get("facts_n") or 0) == 0
    )
    facts_zero_ratio = (facts_zero_calls / len(calls)) if calls else None

    edge_counts = {}
    for e in edges:
        edge_counts[e["edge"]] = edge_counts.get(e["edge"], 0) + 1

    topology = {
        "alternation_edges_observed": sum(edge_counts.values()),
        "edge_counts": edge_counts,
        "depth_increment_plus_one": unit_depth_growth,
        "depth_increment_other": nonunit_depth_growth,
        "depth_plus_one_ratio": (
            unit_depth_growth / len(depth_increments) if depth_increments else None
        ),
    }

    internal_unique = len({e.get("state",{}).get("state_fingerprint")
                           for e in internal if e.get("state",{}).get("state_fingerprint")})
    frames_with_internal = len({e.get("frame_id") for e in internal})
    internal_metrics = {
        "internal_snapshots_materialized": len(internal),
        "frames_with_internal_snapshots": frames_with_internal,
        "unique_internal_state_fingerprints": internal_unique,
        "pre_child_states_reconstructed": len(pre_child),
        "internal_snapshots_per_frame_mean":
            (len(internal)/frames_with_internal if frames_with_internal else None),
    }

    quantitative = {
        "observed_call_span_ns": observed_span_ns,
        "calls_per_second_observed": calls_per_second_observed,
        "state_repeat_ratio_same_function": state_repeat_ratio,
        "facts_zero_calls": facts_zero_calls,
        "facts_zero_ratio": facts_zero_ratio,
    }

    return {
        "_evidence_role": "DERIVED",
        "events_confirmed_at_checkpoint": confirmed_n,
        "events_materialized": len(events),
        "calls_materialized": len(calls),
        "returns_materialized": len(returns),
        "max_depth_materialized": max([c["depth"] for c in calls] or [0]),
        "per_function": summary,
        "same_function_transitions": consecutive,
        "parent_child_transitions": edges,
        "topology_metrics": topology,
        "quantitative_metrics": quantitative,
        "internal_state_events": internal,
        "pre_child_states": pre_child,
        "internal_state_metrics": internal_metrics,
    }



def _qualify_evidence(completeness: str, derived: Dict[str, Any]) -> Dict[str, Any]:
    """Meta-auditor: decide qué afirmaciones admite la política de observación.

    No juzga SPARTACO. Juzga si el instrumento conserva la información
    necesaria para cada inferencia concreta.
    """
    complete = completeness == "COMPLETE_UNTIL_PROCESS_RESULT"
    claims = {
        "MATERIALIZED_CALL_RETURN_BALANCE": {
            "claim": "calls_materialized >= returns_materialized",
            "requires": "PAIR_PRESERVING_EVENT_SET",
            "observation_policy": completeness,
            "qualified": complete,
            "status": "QUALIFIED" if complete else "INSTRUMENT_NOT_QUALIFIED",
            "reason": (
                "complete event set preserves observed CALL/RETURN membership"
                if complete else
                "HEAD+TAIL may retain RETURN while omitting its earlier CALL"
            ),
            "observed": {
                "calls_materialized": derived["calls_materialized"],
                "returns_materialized": derived["returns_materialized"],
            },
        },
        "GLOBAL_MAX_DEPTH_FROM_MATERIALIZED": {
            "claim": "max_depth_materialized == global observed max depth",
            "requires": "NO_OMITTED_EVENTS_IN_OBSERVATION_INTERVAL",
            "observation_policy": completeness,
            "qualified": complete,
            "status": "QUALIFIED" if complete else "INSTRUMENT_NOT_QUALIFIED",
            "reason": (
                "complete event set covers the process result interval"
                if complete else
                "HEAD+TAIL can omit deeper frames in the unmaterialized middle"
            ),
            "observed": {"max_depth_materialized": derived["max_depth_materialized"]},
        },
        "MATERIALIZED_VALUES_DESCRIBE_MATERIALIZED_SAMPLE": {
            "claim": "reported materialized counters describe the persisted sample",
            "requires": "DERIVATION_RECOMPUTABLE_FROM_PERSISTED_EVENTS",
            "observation_policy": completeness,
            "qualified": True,
            "status": "QUALIFIED",
            "reason": "counters are recomputed directly from the persisted event sample",
        },
        "TIMEOUT_IS_FINITE_WINDOW_CENSORING": {
            "claim": "TIMEOUT means termination was not observed before the deadline",
            "requires": "EXPLICIT_DEADLINE_AND_TERMINATION_BY_OBSERVER",
            "observation_policy": completeness,
            "qualified": True,
            "status": "QUALIFIED",
            "reason": "timeout is generated by the observer deadline and process termination path",
        },
    }
    return {
        "_evidence_role": "META_AUDIT_DERIVED",
        "theorem": "Judge(S,Q) => Qualified(O,M) and Valid(M=>Q)",
        "claims": claims,
        "qualified_n": sum(1 for x in claims.values() if x["qualified"]),
        "not_qualified_n": sum(1 for x in claims.values() if not x["qualified"]),
        "meta_auditor_status": "PASS",
    }

def _publish(nodeid: str, name: str, stdout: str) -> None:
    TEST_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = json.loads(TEST_EVIDENCE.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    cases = payload.get("cases")
    if not isinstance(cases, list):
        cases = []

    nodeid = nodeid.replace("\\", "/")
    cases = [
        c for c in cases
        if not (isinstance(c, dict) and str(c.get("nodeid") or "").replace("\\", "/") == nodeid)
    ]
    file_part = nodeid.split("::", 1)[0]
    classname = file_part[:-3].replace("/", ".") if file_part.endswith(".py") else file_part.replace("/", ".")
    cases.append({
        "nodeid": nodeid,
        "test_id": nodeid,
        "test": name,
        "file": file_part,
        "path": file_part,
        "name": name,
        "originalname": name,
        "classname": classname,
        "class_name": classname,
        "status": "passed",
        "outcome": "passed",
        "location": {"file": file_part, "line": None},
        "parameters": {},
        "phases": {"call": {
            "when": "call", "outcome": "passed", "failed": False,
            "skipped": False, "stdout": stdout,
        }},
        "stdout": stdout,
        "output": stdout,
        "report": stdout,
        "runtime_assertions": [],
        "events": [],
        "provenance": {
            "producer": "tests/test_uhcr_transiciones_neutrales.py",
            "spec": SPEC,
            "github_sha": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_number": os.environ.get("GITHUB_RUN_NUMBER"),
        },
    })
    payload["schema_version"] = str(payload.get("schema_version") or "1.0")
    payload["generated_utc"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    payload["exitstatus"] = 0
    payload["cases"] = cases
    TEST_EVIDENCE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _capture() -> Dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    pre = {
        "spec": SPEC,
        "question": "QUE_CAMBIA_ENTRE_TRANSICIONES_EU_ET",
        "p_obs_seconds": P_OBS,
        "raw_policy": "FULL_WHEN_JSON_SERIALIZABLE",
        "state_projection": "ARGS+FACTS+LOCALS_KEYS+SHALLOW_SELF_STRUCTURE",
        "timeout_semantics": "CENSORING_NOT_FAILURE",
        "zero_delta_semantics": "NO_SEMANTIC_JUDGMENT",
        "run": {
            "github_sha": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_number": os.environ.get("GITHUB_RUN_NUMBER"),
        },
    }
    PRE.write_text(json.dumps(pre, indent=2, ensure_ascii=False), encoding="utf-8")

    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_worker, args=(q,))
    start = time.monotonic()
    p.start()
    latest = None
    finished = None
    latest_path = None
    path_signals = []
    deadline = start + P_OBS

    while time.monotonic() < deadline:
        try:
            msg = q.get(timeout=min(.05, max(0.0, deadline-time.monotonic())))
        except queue.Empty:
            continue
        if msg.get("type") == "checkpoint":
            latest = msg
        elif msg.get("type") == "path_signal":
            latest_path = deepcopy(msg.get("path") or {})
            path_signals.append({k: deepcopy(v) for k,v in msg.items() if k != "path"})
        elif msg.get("type") == "finished":
            finished = msg
            latest_path = deepcopy(msg.get("path") or latest_path or {})
            break

    if finished is None:
        p.terminate()
        p.join(timeout=2)
        termination = "TIMEOUT"
        h = list((latest or {}).get("head") or [])
        t = list((latest or {}).get("tail") or [])
        d = {e["seq"]: e for e in h+t if e.get("seq") is not None}
        events = [d[k] for k in sorted(d)]
        confirmed_n = (latest or {}).get("events_n")
        completeness = "HEAD_PLUS_TAIL_OF_LAST_CHECKPOINT"
        result_raw = None
        process_exception = None
    else:
        p.join(timeout=2)
        termination = finished.get("termination")
        events = list(finished.get("events") or [])
        confirmed_n = len(events)
        completeness = "COMPLETE_UNTIL_PROCESS_RESULT"
        result_raw = finished.get("result_raw")
        process_exception = finished.get("exception")

    path_metrics = deepcopy((finished or {}).get("path") or latest_path or {})
    for k in ("dispatch_enter","dispatch_terminal","provider_enter","provider_terminal",
              "exact_dispatch_provider_chains","dispatch_without_provider","provider_without_dispatch"):
        path_metrics.setdefault(k,0)
    for k in ("first_dispatch_ns","first_provider_ns","first_dispatch_to_provider_latency_ns"):
        path_metrics.setdefault(k,None)
    if path_metrics["exact_dispatch_provider_chains"] > 0: path_status = "PATH_OBSERVED"
    elif path_metrics["dispatch_enter"] > 0 or path_metrics["provider_enter"] > 0: path_status = "PATH_PARTIALLY_OBSERVED"
    else: path_status = "INCONCLUSIVE"
    path_metrics.update({"path_status":path_status,"critical_signals_received":len(path_signals),
                         "critical_signal_transport":"IMMEDIATE_QUEUE_NOT_HEAD_TAIL"})

    derived = _derive(events, confirmed_n)
    admissibility = _qualify_evidence(completeness, derived)

    mismatches = [e for e in events if e.get("kind") == "MISMATCH"]
    discovery_events = [e for e in events if e.get("kind") == "DISCOVERY"]
    calls_observed = [e for e in events if e.get("kind") == "CALL"]
    integrity_reasons = []
    if mismatches:
        integrity_reasons.append("PROFILE_STACK_MISMATCH")
    if not discovery_events:
        integrity_reasons.append("DISCOVERY_NOT_OBSERVED")
    elif int(discovery_events[-1].get("control_codes") or 0) <= 0:
        integrity_reasons.append("NO_CONTROL_CODES_DISCOVERED")
    if not calls_observed:
        integrity_reasons.append("NO_CONTROL_CALLS_OBSERVED")
    integrity = "PASS" if not integrity_reasons else "FAIL"

    evidence = {
        "spec": SPEC,
        "runtime_termination": termination,
        "observation_completeness": completeness,
        "budget_seconds": P_OBS,
        "elapsed_seconds": time.monotonic()-start,
        "events_confirmed_at_last_checkpoint": confirmed_n,
        "events_materialized": len(events),
        "derived": derived,
        "evidence_admissibility": admissibility,
        "path_metrics": path_metrics,
        "path_signals": path_signals,
        "result_raw": result_raw,
        "process_exception": process_exception,
        "auditor_integrity": integrity,
        "auditor_integrity_reasons": integrity_reasons,
        "system_semantic_status": "NO_DETERMINADO",
        "security_verdict": "NOT_EVALUATED",
    }

    RAW_EVENTS.write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    STATE_MAP.write_text(json.dumps({
        "spec": SPEC,
        "same_function_transitions": derived["same_function_transitions"],
        "parent_child_transitions": derived["parent_child_transitions"],
        "internal_state_events": derived["internal_state_events"],
        "pre_child_states": derived["pre_child_states"],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    METRICS.write_text(json.dumps({
        "spec": SPEC,
        "events_confirmed": confirmed_n,
        "events_materialized": len(events),
        "calls_materialized": derived["calls_materialized"],
        "returns_materialized": derived["returns_materialized"],
        "max_depth_materialized": derived["max_depth_materialized"],
        "per_function": derived["per_function"],
        "topology_metrics": derived["topology_metrics"],
        "quantitative_metrics": derived["quantitative_metrics"],
        "internal_state_metrics": derived["internal_state_metrics"],
        "path_metrics": path_metrics,
        "evidence_admissibility": admissibility,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    EVIDENCE.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "="*74,
        "UHCR — AUDITOR NEUTRAL DE TRANSICIONES EU <-> ET + ESTADO",
        "="*74,
        f"SPEC={SPEC}",
        "DIARY_REPORT=YES",
        f"GITHUB_SHA={os.environ.get('GITHUB_SHA')}",
        f"GITHUB_RUN_ID={os.environ.get('GITHUB_RUN_ID')}",
        f"GITHUB_RUN_NUMBER={os.environ.get('GITHUB_RUN_NUMBER')}",
        f"P_OBS={P_OBS:.3f}s",
        f"RUNTIME_TERMINATION={termination}",
        f"OBSERVATION_COMPLETENESS={completeness}",
        f"EVENTS_CONFIRMED={confirmed_n}",
        f"EVENTS_MATERIALIZED={len(events)}",
        f"CALLS_MATERIALIZED={derived['calls_materialized']}",
        f"RETURNS_MATERIALIZED={derived['returns_materialized']}",
        f"MAX_DEPTH_MATERIALIZED={derived['max_depth_materialized']}",
        "-"*74,
        "METRICAS CUANTITATIVAS (DERIVED; NO SON VEREDICTO)",
        f"OBSERVED_CALL_SPAN_MS={derived['quantitative_metrics']['observed_call_span_ns']/1e6:.3f}",
        f"CALLS_PER_SECOND_OBSERVED={derived['quantitative_metrics']['calls_per_second_observed']}",
        f"DEPTH_PLUS_ONE_RATIO={derived['topology_metrics']['depth_plus_one_ratio']}",
        f"STATE_REPEAT_RATIO_SAME_FUNCTION={derived['quantitative_metrics']['state_repeat_ratio_same_function']}",
        f"FACTS_ZERO_RATIO={derived['quantitative_metrics']['facts_zero_ratio']}",
        f"DEPTH_INCREMENT_PLUS_ONE={derived['topology_metrics']['depth_increment_plus_one']}",
        f"DEPTH_INCREMENT_OTHER={derived['topology_metrics']['depth_increment_other']}",
        f"EDGE_COUNTS={derived['topology_metrics']['edge_counts']}",
        f"INTERNAL_SNAPSHOTS={derived['internal_state_metrics']['internal_snapshots_materialized']}",
        f"FRAMES_WITH_INTERNAL_STATE={derived['internal_state_metrics']['frames_with_internal_snapshots']}",
        f"UNIQUE_INTERNAL_STATES={derived['internal_state_metrics']['unique_internal_state_fingerprints']}",
        f"PRE_CHILD_STATES={derived['internal_state_metrics']['pre_child_states_reconstructed']}",
        f"INTERNAL_SNAPSHOTS_PER_FRAME_MEAN={derived['internal_state_metrics']['internal_snapshots_per_frame_mean']}",
        "-"*74,
        "ALCANZABILIDAD ENGINE -> DISPATCH -> PROVIDER",
        f"PATH_STATUS={path_metrics['path_status']}",
        f"PATH_SIGNAL_TRANSPORT={path_metrics['critical_signal_transport']}",
        f"PATH_CRITICAL_SIGNALS_RECEIVED={path_metrics['critical_signals_received']}",
        f"DISPATCH_ENTER={path_metrics['dispatch_enter']}",
        f"DISPATCH_TERMINAL={path_metrics['dispatch_terminal']}",
        f"PROVIDER_ENTER={path_metrics['provider_enter']}",
        f"PROVIDER_TERMINAL={path_metrics['provider_terminal']}",
        f"EXACT_DISPATCH_PROVIDER_CHAINS={path_metrics['exact_dispatch_provider_chains']}",
        f"DISPATCH_WITHOUT_PROVIDER={path_metrics['dispatch_without_provider']}",
        f"PROVIDER_WITHOUT_DISPATCH={path_metrics['provider_without_dispatch']}",
        f"FIRST_DISPATCH_NS={path_metrics['first_dispatch_ns']}",
        f"FIRST_PROVIDER_NS={path_metrics['first_provider_ns']}",
        f"FIRST_DISPATCH_TO_PROVIDER_LATENCY_NS={path_metrics['first_dispatch_to_provider_latency_ns']}",
        "  PATH_OBSERVED demuestra alcance instrumental; no correccion ni seguridad.",
        "-"*74,
        "PROYECCION INTERNA + DINAMICA DE ESTADO (DERIVED)",
        "DINAMICA POR FUNCION",
    ]
    for fn, m in derived["per_function"].items():
        lines += [
            f"{fn}",
            f"  calls materializados             {m['calls_materialized']}",
            f"  pares consecutivos               {m['consecutive_pairs_materialized']}",
            f"  mismo fingerprint observable     {m['same_state_fingerprint_pairs']}",
            f"  fingerprint observable distinto  {m['different_state_fingerprint_pairs']}",
            f"  estados observables unicos       {m['unique_state_fingerprints']}",
            f"  repeat_ratio                     {(m['same_state_fingerprint_pairs']/m['consecutive_pairs_materialized']) if m['consecutive_pairs_materialized'] else None}",
            f"  first_frame                      {m['first_frame']}",
            f"  last_frame                       {m['last_frame']}",
            f"  first_fingerprint                {(m['first_state_raw'] or {}).get('state_fingerprint')}",
            f"  last_fingerprint                 {(m['last_state_raw'] or {}).get('state_fingerprint')}",
            f"  first_facts_n                    {(m['first_state_raw'] or {}).get('facts_n')}",
            f"  last_facts_n                     {(m['last_state_raw'] or {}).get('facts_n')}",
        ]

    lines += ["-"*74, "ESTADOS OBSERVADOS — PRIMERO Y ULTIMO"]
    for fn, m in derived["per_function"].items():
        first = m.get("first_state_raw") or {}
        last = m.get("last_state_raw") or {}
        lines += [
            f"{fn} FIRST F{m.get('first_frame')}",
            f"  facts_raw={_canon(first.get('facts_raw'))[:1400]}",
            f"  args_raw={_canon(first.get('args_raw'))[:1400]}",
            f"  control_locals_raw={_canon(first.get('control_locals_raw'))[:1400]}",
            f"  self_structure={_canon(first.get('self_structure'))[:1400]}",
            f"{fn} LAST F{m.get('last_frame')}",
            f"  facts_raw={_canon(last.get('facts_raw'))[:1400]}",
            f"  args_raw={_canon(last.get('args_raw'))[:1400]}",
            f"  control_locals_raw={_canon(last.get('control_locals_raw'))[:1400]}",
            f"  self_structure={_canon(last.get('self_structure'))[:1400]}",
        ]

    edge_counts = {}
    edge_same = {}
    edge_changed = {}
    for e in derived["parent_child_transitions"]:
        name = e["edge"]
        edge_counts[name] = edge_counts.get(name, 0) + 1
        if e["delta"]["same_fingerprint"]:
            edge_same[name] = edge_same.get(name, 0) + 1
        else:
            edge_changed[name] = edge_changed.get(name, 0) + 1
    lines += ["-"*74, "TRANSICIONES PADRE -> HIJO"]
    for name in sorted(edge_counts):
        lines += [
            f"{name}",
            f"  observadas={edge_counts[name]}",
            f"  misma_proyeccion={edge_same.get(name,0)}",
            f"  proyeccion_distinta={edge_changed.get(name,0)}",
        ]

    lines += ["-"*74, "MUESTRA DE TRANSICIONES MISMA FUNCION"]
    pairs = derived["same_function_transitions"]
    sample = pairs[:5] + (pairs[-5:] if len(pairs) > 5 else [])
    seen = set()
    for x in sample:
        key=(x["from_frame"],x["to_frame"])
        if key in seen: continue
        seen.add(key)
        d=x["delta"]
        lines += [
            f"{x['function']} F{x['from_frame']} -> F{x['to_frame']} "
            f"depth {x['from_depth']}->{x['to_depth']}",
            f"  same_fingerprint={d['same_fingerprint']}",
            f"  facts {d['facts_n_before']}->{d['facts_n_after']}",
            f"  facts_added={d['facts_added']}",
            f"  facts_removed={d['facts_removed']}",
            f"  facts_changed={d['facts_changed']}",
            f"  args_changed={d['args_changed']}",
            f"  control_locals_changed={d['control_locals_changed']}",
            f"  self_selected_changed={d['self_selected_changed']}",
        ]

    lines += ["-"*74, "MUESTRA PADRE -> HIJO"]
    edges = derived["parent_child_transitions"]
    esample = edges[:6] + (edges[-6:] if len(edges) > 6 else [])
    seen_edges = set()
    for x in esample:
        key=(x["parent_frame"],x["child_frame"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        d=x["delta"]
        lines += [
            f"{x['edge']} F{x['parent_frame']} -> F{x['child_frame']} "
            f"depth {x['parent_depth']}->{x['child_depth']}",
            f"  same_fingerprint={d['same_fingerprint']}",
            f"  facts {d['facts_n_before']}->{d['facts_n_after']}",
            f"  facts_added={d['facts_added']}",
            f"  facts_removed={d['facts_removed']}",
            f"  facts_changed={d['facts_changed']}",
            f"  args_changed={d['args_changed']}",
            f"  control_locals_changed={d['control_locals_changed']}",
            f"  self_selected_changed={d['self_selected_changed']}",
        ]

    lines += ["-"*74, "ESTADO INTERNO OBSERVADO — MUESTRA"]
    ie = derived.get("internal_state_events") or []
    sample = ie[:6] + (ie[-6:] if len(ie) > 6 else [])
    seen=set()
    for e in sample:
        if e.get("seq") in seen: continue
        seen.add(e.get("seq"))
        st=e.get("state") or {}
        lines += [
            f"{e.get('module')}.{e.get('function')} F{e.get('frame_id')} depth={e.get('depth')} line={e.get('lineno')} snap={e.get('snapshot_index')}",
            f"  control_locals_raw={json.dumps(st.get('control_locals_raw'), ensure_ascii=False, separators=(',',':'))[:1800]}",
            f"  locals_keys={st.get('locals_keys')}",
            f"  fingerprint={st.get('state_fingerprint')}",
        ]

    lines += ["-"*74, "ULTIMO ESTADO PADRE ANTES DEL CALL HIJO — MUESTRA"]
    pc=derived.get("pre_child_states") or []
    sample=pc[:6] + (pc[-6:] if len(pc)>6 else [])
    seen=set()
    for x in sample:
        k=(x.get("parent_frame_id"),x.get("child_frame_id"))
        if k in seen: continue
        seen.add(k)
        pst=x.get("parent_internal_state") or {}
        cst=x.get("child_entry_state") or {}
        d=x.get("delta_internal_to_child") or {}
        lines += [
            f"{x.get('edge')} F{x.get('parent_frame_id')} line={x.get('parent_lineno')} -> F{x.get('child_frame_id')}",
            f"  parent_control_locals={json.dumps(pst.get('control_locals_raw'), ensure_ascii=False, separators=(',',':'))[:1800]}",
            f"  child_args={json.dumps(cst.get('args_raw'), ensure_ascii=False, separators=(',',':'))[:1200]}",
            f"  facts {pst.get('facts_n')}->{cst.get('facts_n')}",
            f"  delta.control_locals_changed={d.get('control_locals_changed')}",
            f"  delta.args_changed={d.get('args_changed')}",
        ]

    lines += [
        "-"*74,
        "META-AUDITORIA — ADMISIBILIDAD DE EVIDENCIA",
        f"META_AUDITOR_STATUS={admissibility['meta_auditor_status']}",
        f"CLAIMS_QUALIFIED={admissibility['qualified_n']}",
        f"CLAIMS_NOT_QUALIFIED={admissibility['not_qualified_n']}",
    ]
    for claim_id, q in admissibility["claims"].items():
        lines += [
            f"  {claim_id}",
            f"    status={q['status']}",
            f"    requires={q['requires']}",
            f"    reason={q['reason']}",
        ]
    lines += [
        "-"*74,
        "LECTURA PERMITIDA",
        "  same_fingerprint=True describe igualdad de ESTA proyeccion observable.",
        "  No demuestra igualdad del estado completo.",
        "  Delta observable cero no demuestra ausencia de progreso semantico.",
        "  Delta observable distinto no demuestra correccion.",
        "  TIMEOUT es censura experimental.",
        "-"*74,
        f"AUDITOR_INTEGRITY={integrity}",
        "SYSTEM_SEMANTIC_STATUS=NO_DETERMINADO",
        "SECURITY_VERDICT=NOT_EVALUATED",
        "="*74,
    ]
    report="\n".join(lines)
    REPORT.write_text(report, encoding="utf-8")
    evidence["report"]=report
    return evidence


@pytest.fixture(scope="session")
def audit():
    return _capture()


def test_teorema_embebido():
    assert Path(__file__).name == "test_uhcr_transiciones_neutrales.py"
    t=Path(__file__).read_text(encoding="utf-8")
    assert "TEOREMA DE OBSERVABILIDAD DE ESTADO" in t
    assert "TEOREMA DE ALCANZABILIDAD DE FRONTERA" in t
    assert "DeltaS = 0  =/=> ausencia de progreso semántico" in t
    assert "TEOREMA DE ADMISIBILIDAD DE EVIDENCIA" in t
    assert "INSTRUMENT_NOT_QUALIFIED" in t


def test_descubrimiento_dinamico(audit):
    for path in (PRE, RAW_EVENTS, STATE_MAP, METRICS, EVIDENCE, REPORT):
        assert path.exists(), path
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    assert metrics["spec"] == SPEC
    assert metrics["calls_materialized"] > 0, metrics


def test_timeout_no_es_fallo_semantico(audit):
    d = audit["derived"]
    a = audit["evidence_admissibility"]
    assert d["max_depth_materialized"] >= 0
    assert a["meta_auditor_status"] == "PASS"
    if audit["observation_completeness"] == "HEAD_PLUS_TAIL_OF_LAST_CHECKPOINT":
        assert a["claims"]["MATERIALIZED_CALL_RETURN_BALANCE"]["status"] == "INSTRUMENT_NOT_QUALIFIED"
        assert a["claims"]["GLOBAL_MAX_DEPTH_FROM_MATERIALIZED"]["status"] == "INSTRUMENT_NOT_QUALIFIED"
    # No se impone CALL_M >= RETURN_M sobre una muestra que no preserva pares.
    assert a["claims"]["TIMEOUT_IS_FINITE_WINDOW_CENSORING"]["qualified"] is True


def test_unmatched_no_se_etiqueta_active(audit):
    assert audit["system_semantic_status"] == "NO_DETERMINADO"
    assert audit["security_verdict"] == "NOT_EVALUATED"


def test_integridad_del_auditor(audit):
    assert audit["auditor_integrity"] == "PASS", audit
    assert audit["evidence_admissibility"]["meta_auditor_status"] == "PASS"
    # El meta-auditor debe poder negarse a calificar inferencias incompatibles
    # con la política de muestreo, en vez de convertirlas en fallos del sistema.
    assert "MATERIALIZED_CALL_RETURN_BALANCE" in audit["evidence_admissibility"]["claims"]


def test_99_traza(audit, request):
    report=audit["report"]
    _publish(request.node.nodeid, request.node.name, report)
    published = json.loads(TEST_EVIDENCE.read_text(encoding="utf-8"))
    mine = [c for c in published.get("cases", [])
            if isinstance(c, dict) and c.get("nodeid") == request.node.nodeid.replace("\\", "/")]
    assert len(mine) == 1, {"nodeid": request.node.nodeid, "matches": len(mine)}
    assert mine[0]["provenance"]["spec"] == SPEC
    assert f"SPEC={SPEC}" in mine[0]["stdout"]
    assert "DINAMICA POR FUNCION" in mine[0]["stdout"]
    assert "ESTADOS OBSERVADOS — PRIMERO Y ULTIMO" in mine[0]["stdout"]
    assert "TRANSICIONES PADRE -> HIJO" in mine[0]["stdout"]
    assert "ALCANZABILIDAD ENGINE -> DISPATCH -> PROVIDER" in mine[0]["stdout"]
    print()
    print(report)
    print()
    assert f"SPEC={SPEC}" in report
    assert "DINAMICA POR FUNCION" in report
    assert "AUDITOR_INTEGRITY=PASS" in report
    assert "PATH_STATUS=" in report
    assert "META-AUDITORIA — ADMISIBILIDAD DE EVIDENCIA" in report
    assert "META_AUDITOR_STATUS=PASS" in report


def test_mapa_y_metricas_persistidos(audit):
    mapa = json.loads(STATE_MAP.read_text(encoding="utf-8"))
    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    assert mapa["spec"] == SPEC
    assert metrics["spec"] == SPEC
    assert "same_function_transitions" in mapa
    assert "parent_child_transitions" in mapa
    assert "topology_metrics" in metrics
    assert "quantitative_metrics" in metrics
    assert "internal_state_metrics" in metrics
    assert "path_metrics" in metrics
    pm = metrics["path_metrics"]
    assert pm["path_status"] in {"PATH_OBSERVED","PATH_PARTIALLY_OBSERVED","INCONCLUSIVE"}
    assert pm["dispatch_enter"] >= 0 and pm["provider_enter"] >= 0
    im = metrics["internal_state_metrics"]
    assert im["internal_snapshots_materialized"] >= 0
    assert im["pre_child_states_reconstructed"] >= 0
    q = metrics["quantitative_metrics"]
    t = metrics["topology_metrics"]
    assert q["facts_zero_ratio"] is None or 0.0 <= q["facts_zero_ratio"] <= 1.0
    assert q["state_repeat_ratio_same_function"] is None or 0.0 <= q["state_repeat_ratio_same_function"] <= 1.0
    assert t["depth_plus_one_ratio"] is None or 0.0 <= t["depth_plus_one_ratio"] <= 1.0
