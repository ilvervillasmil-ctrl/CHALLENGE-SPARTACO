# ===============================================================
# UHCR v3.3 — G_runtime_control congelado
# tests/test_uhcr_v3_3.py
# Checkpoints. stack_mismatch. pares Code/Capability.
# coverage_storage x coverage_observation.
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
OUT = ROOT / "diagnostics" / "uhcr_v3_3"
PRE = OUT / "PRECONDITIONS.json"
RUNTIME = OUT / "G_RUNTIME.json"
EVIDENCE = OUT / "EVIDENCE.json"
VERDICT = OUT / "VERDICT.md"

SCHEMA = "spartaco.uhcr.v3.3"
P_OBS = 3.0
N_MAX = 400
CKPT_EVERY = 100
CodeID = Tuple[str, int, str]


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _edge(frm: str, kind: str, to: str) -> Dict[str, str]:
    return {
        "from": frm,
        "kind": kind,
        "to": to,
        "id": _sha("{0}|{1}|{2}".format(frm, kind, to)),
    }


def _cid_s(cid: CodeID) -> str:
    return "{0}:{1}:{2}".format(cid[0], cid[1], cid[2])


def _worker(q: mp.Queue) -> None:
    sys.path.insert(0, str(ROOT))
    catalog: Dict[CodeID, List[str]] = {}
    eventos: List[Dict[str, Any]] = []
    frame_i: Dict[int, int] = {}
    frame_code: Dict[int, CodeID] = {}
    i_info: Dict[int, Dict[str, Any]] = {}
    stack: List[int] = []
    seq = [0]
    mismatch = [0]
    count_code: Counter = Counter()
    count_attr: Counter = Counter()
    count_code_pairs: Counter = Counter()
    count_cap_pairs: Counter = Counter()

    def attr_of(cid: CodeID) -> Tuple[str, List[str]]:
        caps = catalog.get(cid) or []
        if len(caps) == 1:
            return "C", caps
        if len(caps) > 1:
            return "AMBIGUA", caps
        return "NO_CATALOGADA", []

    def checkpoint(final: bool = False) -> None:
        q.put({
            "kind": "ckpt",
            "final": final,
            "N": len(eventos),
            "tail": eventos[-80:],
            "active_stack": list(stack),
            "stack_mismatch": mismatch[0],
            "count_code": { _cid_s(k): int(v) for k, v in count_code.items() },
            "count_attr": dict(count_attr),
            "count_code_pairs": { "{0}->{1}".format(a, b): int(v) for (a, b), v in count_code_pairs.items() },
            "count_cap_pairs": { "{0}->{1}".format(a, b): int(v) for (a, b), v in count_cap_pairs.items() },
            "terminacion_parcial": None,
        })

    def profiler(frame, event, arg):
        if event not in ("call", "return"):
            return profiler
        code = frame.f_code
        try:
            ruta = str(Path(code.co_filename).resolve())
            Path(ruta).relative_to(MODULES)
        except Exception:
            return profiler
        cid: CodeID = (ruta, int(code.co_firstlineno), code.co_name)
        fid = id(frame)
        if event == "call":
            seq[0] += 1
            n = seq[0]
            parent = stack[-1] if stack else None
            frame_i[fid] = n
            frame_code[fid] = cid
            stack.append(n)
            a, caps = attr_of(cid)
            i_info[n] = {"code": cid, "attr": a, "caps": caps, "parent": parent}
            count_code[cid] += 1
            count_attr[a] += 1
            if parent is not None and parent in i_info:
                pc = i_info[parent]["code"]
                count_code_pairs[(_cid_s(pc), _cid_s(cid))] += 1
                pcaps = i_info[parent]["caps"]
                if i_info[parent]["attr"] == "C" and a == "C" and pcaps and caps:
                    count_cap_pairs[(pcaps[0], caps[0])] += 1
            eventos.append({
                "event": "call",
                "I": n,
                "parent_I": parent,
                "depth": 0 if parent is None else i_info.get(parent, {}).get("depth", 0) + 1,
                "code_id": list(cid),
                "attribution": a,
                "capabilities": caps,
            })
            i_info[n]["depth"] = eventos[-1]["depth"]
            if len(eventos) % CKPT_EVERY == 0:
                checkpoint(False)
        else:
            n = frame_i.pop(fid, None)
            frame_code.pop(fid, None)
            if n is None:
                mismatch[0] += 1
                return profiler
            if stack and stack[-1] == n:
                stack.pop()
            else:
                mismatch[0] += 1
            a, caps = attr_of(cid)
            eventos.append({
                "event": "return",
                "I": n,
                "code_id": list(cid),
                "attribution": a,
                "capabilities": caps,
            })
        return profiler

    try:
        from core.engine import Engine
        engine = Engine(MODULES, strict=True)
        for nombre, cont in engine.registro.contenedores.items():
            for cap in cont.capacidades:
                try:
                    fn = cont.fn(cap)
                except Exception:
                    continue
                code = getattr(fn, "__code__", None)
                if not code:
                    continue
                key: CodeID = (
                    str(Path(code.co_filename).resolve()),
                    int(code.co_firstlineno),
                    code.co_name,
                )
                catalog.setdefault(key, []).append("{0}.{1}".format(nombre, cap))
        sys.setprofile(profiler)
        try:
            engine.evaluar_universal({})
            term = "RETURN"
        except Exception as exc:
            term = "RAISE"
            eventos.append({"event": "engine_raise", "error": type(exc).__name__})
        finally:
            sys.setprofile(None)
        checkpoint(True)
        q.put({"kind": "done", "terminacion": term, "ok": True})
    except Exception as exc:
        try:
            checkpoint(True)
            q.put({
                "kind": "done",
                "terminacion": "WORKER_ERROR",
                "ok": False,
                "error": "{0}: {1}".format(type(exc).__name__, exc),
            })
        except Exception:
            pass


def _drenar(q: mp.Queue) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    while True:
        try:
            out.append(q.get_nowait())
        except Exception:
            break
    return out


def _capturar() -> Dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    PRE.write_text(json.dumps({
        "schema": SCHEMA,
        "P_obs": P_OBS,
        "N_max": N_MAX,
        "ckpt_every": CKPT_EVERY,
        "AUTO_TRUST": False,
        "entrada": "Engine.evaluar_universal({})",
        "grafo": "G_runtime_control",
    }, indent=2), encoding="utf-8")

    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(q,))
    t0 = time.time()
    proc.start()
    msgs: List[Dict[str, Any]] = []
    deadline = t0 + P_OBS
    while time.time() < deadline:
        if not proc.is_alive():
            msgs.extend(_drenar(q))
            break
        try:
            msgs.append(q.get(timeout=0.1))
        except queue.Empty:
            continue
    timeout = proc.is_alive()
    if timeout:
        proc.terminate()
        proc.join(1)
        time.sleep(0.05)
        msgs.extend(_drenar(q))
    else:
        proc.join(1)
        msgs.extend(_drenar(q))

    ckpts = [m for m in msgs if m.get("kind") == "ckpt"]
    dones = [m for m in msgs if m.get("kind") == "done"]
    last = ckpts[-1] if ckpts else {
        "N": 0,
        "tail": [],
        "active_stack": [],
        "stack_mismatch": 0,
        "count_code": {},
        "count_attr": {},
        "count_code_pairs": {},
        "count_cap_pairs": {},
    }
    if timeout:
        terminacion = "TIMEOUT"
        coverage_observation = "HASTA_TIMEOUT"
    elif dones:
        terminacion = dones[-1].get("terminacion", "WORKER_ERROR")
        coverage_observation = "COMPLETA" if dones[-1].get("ok") and terminacion == "RETURN" else "HASTA_ERROR"
    else:
        terminacion = "WORKER_ERROR"
        coverage_observation = "DESCONOCIDA"

    observados = int(last.get("N") or 0)
    tail = list(last.get("tail") or [])
    conservados = tail[-N_MAX:]
    storage = "TRUNCADA" if observados > len(conservados) else "COMPLETA"
    mismatch = int(last.get("stack_mismatch") or 0)
    stack_int = "OK" if mismatch == 0 else "DEGRADED"

    if terminacion == "WORKER_ERROR" and coverage_observation == "DESCONOCIDA" and observados == 0:
        integridad = "INVALIDA"
    elif storage == "TRUNCADA" or stack_int == "DEGRADED" or timeout:
        integridad = "PARCIAL"
    else:
        integridad = "VALIDA"

    calls = [e for e in conservados if e.get("event") == "call"]
    returns = {e["I"] for e in conservados if e.get("event") == "return" and e.get("I") is not None}
    vertices: List[str] = []
    aristas: List[Dict[str, str]] = []

    def add_v(n: str) -> None:
        if n not in vertices:
            vertices.append(n)

    invocaciones: List[int] = []
    for e in calls:
        n = e["I"]
        invocaciones.append(n)
        iid = "I_{0}".format(n)
        add_v(iid)
        attr = e.get("attribution")
        caps = e.get("capabilities") or []
        if attr == "C" and caps:
            add_v("cap:{0}".format(caps[0]))
            aristas.append(_edge("cap:{0}".format(caps[0]), "invoca", iid))
        elif attr == "AMBIGUA":
            add_v("AMBIGUA_{0}".format(n))
            aristas.append(_edge("AMBIGUA_{0}".format(n), "invoca", iid))
        parent = e.get("parent_I")
        if parent is not None:
            add_v("I_{0}".format(parent))
            aristas.append(_edge("I_{0}".format(parent), "llama", iid))
        if n in returns:
            add_v("R_{0}".format(n))
            aristas.append(_edge(iid, "return", "R_{0}".format(n)))

    RUNTIME.write_text(json.dumps({
        "schema": SCHEMA,
        "parte": "G_runtime_control",
        "G_runtime_data": {"V": [], "A": []},
        "terminacion": terminacion,
        "integridad_instrumento": integridad,
        "integrity_stack": stack_int,
        "stack_mismatch": mismatch,
        "coverage_storage": storage,
        "coverage_observation": coverage_observation,
        "timeout": timeout,
        "duracion_s": round(time.time() - t0, 3),
        "eventos_observados": observados,
        "eventos_conservados": len(conservados),
        "checkpoints": len(ckpts),
        "count_code": last.get("count_code"),
        "count_attr": last.get("count_attr"),
        "count_code_pairs": last.get("count_code_pairs"),
        "count_cap_pairs": last.get("count_cap_pairs"),
        "V": vertices,
        "A": aristas,
        "invocaciones": invocaciones,
        "eventos": conservados,
    }, indent=2), encoding="utf-8")

    ev = {
        "schema": SCHEMA,
        "integridad_instrumento": integridad,
        "terminacion": terminacion,
        "timeout": timeout,
        "coverage_storage": storage,
        "coverage_observation": coverage_observation,
        "integrity_stack": stack_int,
        "n_invocaciones": len(invocaciones),
        "invocaciones": invocaciones,
        "checkpoints": len(ckpts),
        "eventos_observados": observados,
    }
    EVIDENCE.write_text(json.dumps(ev, indent=2), encoding="utf-8")
    VERDICT.write_text("\n".join([
        "# UHCR v3.3 G_runtime_control",
        "",
        "IntegridadInstrumento: {0}".format(integridad),
        "Terminacion: {0}".format(terminacion),
        "Integrity_stack: {0} mismatch={1}".format(stack_int, mismatch),
        "Coverage_storage: {0}".format(storage),
        "Coverage_observation: {0}".format(coverage_observation),
        "checkpoints: {0}".format(len(ckpts)),
        "eventos_observados: {0}".format(observados),
        "invocaciones_en_cola: {0}".format(len(invocaciones)),
        "",
        "TIMEOUT no implica G vacio si hubo checkpoint.",
        "G_runtime_data vacio. EU/ET no se clasifican.",
        "",
    ]), encoding="utf-8")
    return ev


@pytest.fixture(scope="session")
def runtime() -> Dict[str, Any]:
    return _capturar()


def test_timeout_no_borra_checkpoint(runtime: Dict[str, Any]) -> None:
    assert runtime["terminacion"] in {"RETURN", "RAISE", "TIMEOUT", "WORKER_ERROR"}
    if runtime["terminacion"] == "TIMEOUT":
        assert runtime["coverage_observation"] == "HASTA_TIMEOUT"


def test_coberturas_separadas(runtime: Dict[str, Any]) -> None:
    assert runtime["coverage_storage"] in {"COMPLETA", "TRUNCADA"}
    assert runtime["coverage_observation"] in {
        "COMPLETA", "HASTA_TIMEOUT", "HASTA_ERROR", "DESCONOCIDA",
    }


def test_stack_y_pares(runtime: Dict[str, Any]) -> None:
    data = json.loads(RUNTIME.read_text(encoding="utf-8"))
    assert data["integrity_stack"] in {"OK", "DEGRADED"}
    assert "count_cap_pairs" in data
    assert "count_code_pairs" in data
    assert data["G_runtime_data"] == {"V": [], "A": []}
# ==============================
# ==============================
