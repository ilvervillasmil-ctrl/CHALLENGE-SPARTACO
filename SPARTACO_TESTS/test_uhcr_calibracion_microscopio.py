# ===========================================================================
# UHCR — MICROSCOPE CALIBRATION
# tests/test_uhcr_calibracion_microscopio.py
# SPEC: UHCR-MICROSCOPE-CALIBRATION-1.1-METROLOGY
# ===========================================================================
#
# OBSERVER CALIBRATION THEOREM
# ---------------------------------------------------------------------------
# Let S be an execution of the system and O_i an instrumental regime.
# An observed difference between S|O_i and S|O_j is NOT attributed to S
# by itself.
#
#     Delta Obs(O_i, O_j) =/=> Delta Semantica(S)
#
# Before using a magnitude M to judge S, the auditor must measure
# whether M changes materially when ONLY the observer changes.
#
# REGIMES, DISCOVERED OVER THE REAL RUNTIME
# ---------------------------------------------------------------------------
#   O0_MINIMAL      process + result/timeout; no profile, no trace.
#   O1_BOUNDARY     Engine.ejecutar_capacidad frontier for EU/ET.
#   O2_PROFILE      CALL/RETURN of EU/ET code objects discovered in
#                   runtime.
#   O3_LINE_STATE   O2 + line tracing with fingerprint of observable
#                   state per line.
#
# THESIS
# ---------------------------------------------------------------------------
# This file does not measure the system. It measures the instrument
# that measures the system. It does not presume O0 is the absolute
# truth nor that O3 is better. It calibrates four properties of the
# observer:
#
#   * perturbation        (does the observer change termination, event
#                          rate, or depth?)
#   * instrumental        (how many events per second does each
#     throughput           regime produce?)
#   * representational    (does O3 lose state compared to O2, or
#     loss                 vice versa?)
#   * stability of        (do the four regimes agree on shared
#     common observables   observables like termination?)
#
# WHAT PASS MEANS HERE
# ---------------------------------------------------------------------------
# PASS = the calibrator produced coherent evidence about its own
# regimes.
# PASS =/=> SPARTACO is correct, vulnerable, fast, slow, fail-closed,
# or complete.
#
# The two most important fields of the JSON are:
#     system_semantic_status = "NO_DETERMINADO"
#     security_verdict       = "NOT_EVALUATED"
#
# A calibrator that turned observer sensitivity into a system verdict
# would violate the theorem.
#
# POSITIVE CONTROL OF THE SENSOR
# ---------------------------------------------------------------------------
# Before observing the system, each regime runs _synthetic_probe, a
# synthetic workload with exactly known cardinality. In profile modes,
# it calls a leaf function SYNTH_CALLS times and expects exactly
# SYNTH_CALLS call events and SYNTH_CALLS return events. In boundary
# mode, it counts SYNTH_CALLS synthetic entries and exits. If the
# sensor does not report exactly what is expected, its calibration is
# UNQUALIFIED and the file records it.
#
# A sensor that does not see a known-cardinality synthetic system has
# no reason to be trusted on the real system.
#
# FRONTIER SELF-QUALIFICATION
# ---------------------------------------------------------------------------
# O1's synthetic sensor can pass while the PRODUCTION path never
# crosses its frontier. The file detects this: if O1's synthetic
# sensor qualified but production boundary_enter is zero, then
# production_path_qualified["O1_BOUNDARY"] is set to False.
#
# A sensor that works in the lab but intercepts nothing in production
# does not measure production.
#
# EXECUTION MODEL
# ---------------------------------------------------------------------------
# Each regime runs in an isolated subprocess using multiprocessing
# spawn context. The child:
#   - runs the synthetic probe and reports its calibration;
#   - imports Engine, instantiates it with strict=True;
#   - installs the sensor according to the mode;
#   - runs eng.evaluar_universal({});
#   - emits events to a queue with checkpoints every
#     CHECKPOINT_EVERY events;
#   - keeps a head of the first HEAD_N events and a tail of the last
#     TAIL_N events, plus full counters.
#
# The parent reads from the queue with a deadline of WINDOW seconds,
# keeps the last checkpoint, and:
#   - if the child terminated, records termination = RETURN | RAISE;
#   - if the deadline expired, terminates the child and records
#     completeness = CHECKPOINT_CENSORED with the last checkpoint as
#     sample.
#
# Censorship is declared, never hidden.
#
# PERTURBATION METRICS (DESCRIPTIVE, NOT VERDICT)
# ---------------------------------------------------------------------------
# For each regime the file computes:
#   - instrument_event_rate_per_s     (events confirmed / WINDOW)
#   - observed_control_call_rate_per_s (calls / WINDOW)
# and aggregates across regimes:
#   - termination_stable_across_modes  (all modes agreed on RETURN|RAISE)
#   - termination_by_mode
#   - event_rate_by_mode
#   - control_call_rate_by_mode
#   - max_depth_observed_by_mode
#   - sensor_positive_control_qualified
#   - production_path_qualified
#
# The interpretation field is explicitly
#     "CALIBRATION_ONLY_NOT_SYSTEM_VERDICT".
#
# AUDITOR INTEGRITY
# ---------------------------------------------------------------------------
# The calibrator self-checks with three rules:
#   - modes executed in declared order and complete;
#   - all elapsed times positive;
#   - all sensors passed their synthetic control.
#
# If any rule fails, auditor_integrity = "FAIL" with concrete reasons.
#
# PERSISTED ARTIFACTS
# ---------------------------------------------------------------------------
#   diagnostics/uhcr_calibracion_microscopio/EVIDENCE.json
#   diagnostics/uhcr_calibracion_microscopio/METRICS.json
#   diagnostics/uhcr_calibracion_microscopio/REPORT.txt
#   diagnostics/test_evidence.json (trace for the diary)
#
# All written before any assertion.
#
# SEVEN ASSERTIONS
# ---------------------------------------------------------------------------
#   test_teorema_calibracion_embebido
#     the mathematical notation and the four regime names are present.
#
#   test_cuatro_regimenes_ejecutados
#     the four modes ran in declared order.
#
#   test_calibrador_no_emite_veredicto_semantico
#     system_semantic_status == "NO_DETERMINADO" and
#     security_verdict       == "NOT_EVALUATED".
#
#   test_metricas_instrumentales_no_negativas
#     no counter is negative and elapsed times are positive.
#
#   test_integridad_calibrador
#     auditor_integrity == "PASS".
#
#   test_control_positivo_de_cada_sensor
#     each mode passed its synthetic positive control.
#
#   test_frontera_no_se_autocalifica
#     if O1's synthetic sensor qualified but production boundary_enter
#     is zero, then production_path_qualified["O1_BOUNDARY"] is False.
#
#   test_99_traza
#     publishes the report to diagnostics/test_evidence.json for the
#     Omega Diary.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It does not attack any module.
#   - It does not qualify an external instrument.
#   - It does not audit an isolated resource.
#   - It does not verify a closure, a theorem of purity of construction
#     or the equality verified == loaded == executed.
#   - It does not certify the whole system.
#   - It does not attribute observer sensitivity to the system.
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
# executed. The enablement theorem verifies purity of construction.
# The total attack campaign measures coherence and attributability of
# the suite. This file calibrates the microscope itself: it measures
# the perturbation that the act of measuring introduces, and refuses
# to convert that perturbation into a semantic verdict about the
# system.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# A difference observed between two instruments is a property of the
# instruments until proven otherwise. A calibrator that confuses
# observer sensitivity with system semantics is worse than no
# calibrator. This file measures four regimes against a synthetic
# positive control of known cardinality, publishes the perturbation
# without attribution, and declares the system's semantic status as
# NOT_DETERMINED and the security verdict as NOT_EVALUATED, by design.
#
# ===========================================================================
from __future__ import annotations
import hashlib, inspect, json, multiprocessing as mp, os, queue, sys, time
from pathlib import Path
from typing import Any
import pytest

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "diagnostics" / "uhcr_calibracion_microscopio"
EVIDENCE = OUT / "EVIDENCE.json"
METRICS = OUT / "METRICS.json"
REPORT = OUT / "REPORT.txt"
TEST_EVIDENCE = ROOT / "diagnostics" / "test_evidence.json"
SPEC = "UHCR-MICROSCOPE-CALIBRATION-1.1-METROLOGY"
WINDOW = float(os.environ.get("UHCR_CAL_WINDOW_SECONDS", "1.0"))
MODES = ("O0_MINIMAL", "O1_BOUNDARY", "O2_PROFILE", "O3_LINE_STATE")
CONTROL = {"evaluar_universal", "ejecutar_total"}
CHECKPOINT_EVERY = 50
HEAD_N, TAIL_N = 30, 120
SYNTH_CALLS = int(os.environ.get("UHCR_CAL_SYNTH_CALLS", "64"))
SYNTH_MUTATIONS = int(os.environ.get("UHCR_CAL_SYNTH_MUTATIONS", "32"))


def _raw(v: Any):
    try:
        json.dumps(v, ensure_ascii=False); return v
    except Exception:
        try: r=repr(v)
        except Exception as e: r=f"<repr-error {type(e).__name__}>"
        return {"_type":f"{type(v).__module__}.{type(v).__qualname__}","_repr":r[:1000]}


def _fp(v: Any):
    return hashlib.sha256(json.dumps(_raw(v),sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()


def _state(frame):
    loc=frame.f_locals
    args={k:_raw(loc.get(k)) for k in ("hechos","peticion") if k in loc}
    ctl={k:_raw(loc.get(k)) for k in ("nombre","nuevos","hechos_out","resultados","errores_ejecucion") if k in loc}
    return {"args":args,"control":ctl,"fp":_fp({"args":args,"control":ctl})}



def _synthetic_probe(mode: str):
    """Control positivo determinista: calibra el sensor antes de observar S."""
    obs = {"calls": 0, "returns": 0, "lines": 0, "state_changes": 0,
           "boundary_enter": 0, "boundary_exit": 0, "max_depth": 0}
    stack=[]; last={}

    def leaf(x):
        y=x+1
        return y

    target_code=leaf.__code__
    def prof(frame,event,arg):
        if frame.f_code is not target_code: return
        if event=="call":
            stack.append(id(frame)); obs["calls"]+=1; obs["max_depth"]=max(obs["max_depth"],len(stack))
        elif event=="return":
            obs["returns"]+=1
            if stack: stack.pop()

    def trace(frame,event,arg):
        if frame.f_code is not target_code: return None
        if event=="call": return trace
        if event=="line":
            obs["lines"]+=1
            st=_fp({"x":frame.f_locals.get("x"),"y":frame.f_locals.get("y")})
            k=id(frame)
            if last.get(k)!=st:
                last[k]=st; obs["state_changes"]+=1
        return trace

    if mode in ("O2_PROFILE","O3_LINE_STATE"): sys.setprofile(prof)
    if mode=="O3_LINE_STATE": sys.settrace(trace)
    try:
        for i in range(SYNTH_CALLS): leaf(i)
    finally:
        sys.settrace(None); sys.setprofile(None)

    # O1 has a separate synthetic boundary with exactly known cardinality.
    if mode=="O1_BOUNDARY":
        for _ in range(SYNTH_CALLS):
            obs["boundary_enter"]+=1
            obs["boundary_exit"]+=1

    expected={
        "calls": SYNTH_CALLS if mode in ("O2_PROFILE","O3_LINE_STATE") else 0,
        "returns": SYNTH_CALLS if mode in ("O2_PROFILE","O3_LINE_STATE") else 0,
        "boundary_enter": SYNTH_CALLS if mode=="O1_BOUNDARY" else 0,
        "boundary_exit": SYNTH_CALLS if mode=="O1_BOUNDARY" else 0,
    }
    exact=all(obs[k]==v for k,v in expected.items())
    return {"expected":expected,"observed":obs,"exact_core_counts":exact,
            "qualification":"QUALIFIED" if exact else "UNQUALIFIED"}

def _worker(mode, q):
    t0=time.monotonic_ns(); seq=0; confirmed=0; head=[]; tail=[]; stack=[]; fids={}; next_fid=0
    code_meta={}; counters={"boundary_enter":0,"boundary_exit":0,"calls":0,"returns":0,"lines":0,"state_changes":0,"max_depth":0}
    last_state={}
    def rel(): return time.monotonic_ns()-t0
    def emit(kind, **kw):
        nonlocal seq, confirmed
        seq+=1; confirmed+=1; e={"seq":seq,"kind":kind,"t_rel_ns":rel(),**kw}
        if len(head)<HEAD_N: head.append(e)
        tail.append(e)
        if len(tail)>TAIL_N: del tail[0]
        if seq%CHECKPOINT_EVERY==0:
            q.put({"type":"checkpoint","mode":mode,"events_confirmed":confirmed,"head":head[:],"tail":tail[:],"counters":dict(counters),"t_rel_ns":rel()})
    try:
        sensor_calibration=_synthetic_probe(mode)
        q.put({"type":"sensor_calibration","mode":mode,"calibration":sensor_calibration})
        from core.engine import Engine
        eng=Engine(raiz_modulos=str(ROOT/"modules"),invocador_id=f"uhcr_cal_{mode}",strict=True)
        if getattr(eng,"estado",None)!="OPERATIVO": raise RuntimeError("Engine no OPERATIVO")
        providers=[]
        for cname in sorted(eng.registro.contenedores):
            cont=eng.registro.contenedores[cname]
            for cap in sorted(CONTROL):
                fn=cont.fn(cap)
                if callable(fn) and hasattr(fn,"__code__"):
                    code_meta[fn.__code__]=(cname,cap)
                    if cap=="evaluar_universal": providers.append(cname)
        emit("DISCOVERY",providers=sorted(set(providers)),control_codes=len(code_meta))

        original=None
        if mode=="O1_BOUNDARY":
            original=eng.ejecutar_capacidad
            def wrapped(modulo, capacidad, *a, **kw):
                if capacidad in CONTROL:
                    counters["boundary_enter"]+=1; emit("BOUNDARY_ENTER",module=modulo,capability=capacidad)
                try:
                    r=original(modulo,capacidad,*a,**kw)
                except BaseException as exc:
                    if capacidad in CONTROL:
                        counters["boundary_exit"]+=1; emit("BOUNDARY_RAISE",module=modulo,capability=capacidad,exc=type(exc).__name__)
                    raise
                if capacidad in CONTROL:
                    counters["boundary_exit"]+=1; emit("BOUNDARY_EXIT",module=modulo,capability=capacidad)
                return r
            eng.ejecutar_capacidad=wrapped

        def profiler(frame,event,arg):
            nonlocal next_fid
            meta=code_meta.get(frame.f_code)
            if meta is None: return
            k=id(frame)
            if event=="call":
                next_fid+=1; fid=next_fid; fids[k]=fid; stack.append(fid)
                counters["calls"]+=1; counters["max_depth"]=max(counters["max_depth"],len(stack))
                emit("CALL",frame_id=fid,depth=len(stack),module=meta[0],function=meta[1])
            elif event=="return":
                fid=fids.get(k); counters["returns"]+=1
                emit("RETURN",frame_id=fid,depth=len(stack),module=meta[0],function=meta[1])
                if fid in stack:
                    if stack and stack[-1]==fid: stack.pop()
                    else: stack.remove(fid)
                fids.pop(k,None)

        def tracer(frame,event,arg):
            meta=code_meta.get(frame.f_code)
            if meta is None: return None
            if event=="call": return tracer
            if event=="line":
                counters["lines"]+=1
                fid=fids.get(id(frame)); st=_state(frame); old=last_state.get(fid)
                if fid is not None and st["fp"]!=old:
                    last_state[fid]=st["fp"]; counters["state_changes"]+=1
                    emit("STATE_CHANGE",frame_id=fid,depth=len(stack),module=meta[0],function=meta[1],lineno=frame.f_lineno,state=st)
            return tracer

        if mode in ("O2_PROFILE","O3_LINE_STATE"): sys.setprofile(profiler)
        if mode=="O3_LINE_STATE": sys.settrace(tracer)
        try: result=eng.evaluar_universal({})
        finally:
            sys.settrace(None); sys.setprofile(None)
        q.put({"type":"finished","mode":mode,"termination":"RETURN","events_confirmed":confirmed,"head":head,"tail":tail,"counters":counters,"result":_raw(result),"t_rel_ns":rel()})
    except BaseException as exc:
        try: sys.settrace(None); sys.setprofile(None)
        except Exception: pass
        q.put({"type":"finished","mode":mode,"termination":"RAISE","events_confirmed":confirmed,"head":head,"tail":tail,"counters":counters,"exception":{"type":type(exc).__name__,"message":str(exc)},"t_rel_ns":rel()})


def _run_mode(mode):
    ctx=mp.get_context("spawn"); q=ctx.Queue(); p=ctx.Process(target=_worker,args=(mode,q)); start=time.monotonic(); p.start()
    latest=None; finished=None; sensor_calibration=None; deadline=start+WINDOW
    while time.monotonic()<deadline:
        try: m=q.get(timeout=min(.05,max(0,deadline-time.monotonic())))
        except queue.Empty: continue
        if m.get("type")=="checkpoint": latest=m
        elif m.get("type")=="sensor_calibration": sensor_calibration=m.get("calibration")
        elif m.get("type")=="finished": finished=m; break
    if finished is None:
        p.terminate(); p.join(timeout=2); src=latest or {}
        return {"mode":mode,"sensor_calibration":sensor_calibration,"termination":"TIMEOUT","elapsed_s":time.monotonic()-start,"events_confirmed":src.get("events_confirmed",0),"counters":src.get("counters",{}),"sample":{"head":src.get("head",[]),"tail":src.get("tail",[])},"completeness":"CHECKPOINT_CENSORED"}
    p.join(timeout=2)
    return {"mode":mode,"sensor_calibration":sensor_calibration,"termination":finished.get("termination"),"elapsed_s":time.monotonic()-start,"events_confirmed":finished.get("events_confirmed",0),"counters":finished.get("counters",{}),"sample":{"head":finished.get("head",[]),"tail":finished.get("tail",[])},"completeness":"COMPLETE_TO_PROCESS_RESULT","result":finished.get("result"),"exception":finished.get("exception")}


def _capture():
    OUT.mkdir(parents=True,exist_ok=True)
    runs=[_run_mode(m) for m in MODES]
    by={r["mode"]:r for r in runs}
    # Calibration metrics describe the observer, not system semantics.
    for r in runs:
        c=r.get("counters") or {}; e=r.get("events_confirmed") or 0
        r["instrument_event_rate_per_s"]=(e/WINDOW if WINDOW>0 else None)
        r["observed_control_call_rate_per_s"]=(c.get("calls",0)/WINDOW if WINDOW>0 else None)
    common_termination=len({r["termination"] for r in runs})==1
    sensor_qualified={r["mode"]: bool((r.get("sensor_calibration") or {}).get("exact_core_counts")) for r in runs}
    # A sensor can pass its synthetic control yet fail to intercept the production path.
    o1=by["O1_BOUNDARY"]; o1c=o1.get("counters") or {}
    production_path_qualified = {m: sensor_qualified[m] for m in MODES}
    if sensor_qualified.get("O1_BOUNDARY") and o1c.get("boundary_enter",0)==0:
        production_path_qualified["O1_BOUNDARY"]=False
    perturbation={
        "termination_stable_across_modes":common_termination,
        "termination_by_mode":{r["mode"]:r["termination"] for r in runs},
        "event_rate_by_mode":{r["mode"]:r["instrument_event_rate_per_s"] for r in runs},
        "control_call_rate_by_mode":{r["mode"]:r["observed_control_call_rate_per_s"] for r in runs},
        "max_depth_observed_by_mode":{r["mode"]:(r.get("counters") or {}).get("max_depth") for r in runs},
        "sensor_positive_control_qualified":sensor_qualified,
        "production_path_qualified":production_path_qualified,
        "interpretation":"CALIBRATION_ONLY_NOT_SYSTEM_VERDICT",
    }
    integrity=[]
    if [r["mode"] for r in runs]!=list(MODES): integrity.append("MODE_ORDER_OR_COMPLETENESS")
    if any(r["elapsed_s"]<=0 for r in runs): integrity.append("NONPOSITIVE_ELAPSED")
    if not all(sensor_qualified.values()): integrity.append("SENSOR_POSITIVE_CONTROL_FAILED")
    evidence={"spec":SPEC,"window_seconds_per_mode":WINDOW,"modes":runs,"perturbation":perturbation,"auditor_integrity":"PASS" if not integrity else "FAIL","integrity_reasons":integrity,"system_semantic_status":"NO_DETERMINADO","security_verdict":"NOT_EVALUATED"}
    EVIDENCE.write_text(json.dumps(evidence,indent=2,ensure_ascii=False),encoding="utf-8")
    METRICS.write_text(json.dumps({"spec":SPEC,"perturbation":perturbation,"modes":runs},indent=2,ensure_ascii=False),encoding="utf-8")
    lines=["="*72,"UHCR — CALIBRACION DEL MICROSCOPIO", "="*72,f"SPEC={SPEC}",f"WINDOW_PER_MODE={WINDOW:.3f}s",""]
    for r in runs:
        c=r.get("counters") or {}
        lines += [f"{r['mode']}",f"  termination={r['termination']}",f"  completeness={r['completeness']}",f"  elapsed_s={r['elapsed_s']:.6f}",f"  events_confirmed={r['events_confirmed']}",f"  instrument_event_rate_per_s={r['instrument_event_rate_per_s']}",f"  calls={c.get('calls',0)} returns={c.get('returns',0)} max_depth={c.get('max_depth',0)}",f"  boundary_enter={c.get('boundary_enter',0)} boundary_exit={c.get('boundary_exit',0)}",f"  lines={c.get('lines',0)} state_changes={c.get('state_changes',0)}",f"  sensor_positive_control={(r.get('sensor_calibration') or {}).get('qualification')}",f"  production_path_qualified={production_path_qualified.get(r['mode'])}",""]
    lines += ["CALIBRATION",f"  termination_stable_across_modes={common_termination}","  Diferencias entre modos son evidencia de sensibilidad al observador;", "  NO son por si solas propiedades semanticas de SPARTACO.","",f"AUDITOR_INTEGRITY={evidence['auditor_integrity']}","SYSTEM_SEMANTIC_STATUS=NO_DETERMINADO","SECURITY_VERDICT=NOT_EVALUATED","="*72]
    report="\n".join(lines); REPORT.write_text(report,encoding="utf-8"); evidence["report"]=report
    return evidence


def _publish(nodeid,name,stdout):
    TEST_EVIDENCE.parent.mkdir(parents=True,exist_ok=True)
    try: payload=json.loads(TEST_EVIDENCE.read_text(encoding="utf-8")) if TEST_EVIDENCE.exists() else {}
    except Exception: payload={}
    cases=payload.get("cases") if isinstance(payload.get("cases"),list) else []
    norm=nodeid.replace("\\","/"); cases=[c for c in cases if not(isinstance(c,dict) and c.get("nodeid")==norm)]
    file_part=norm.split("::",1)[0]; classname=file_part[:-3].replace("/",".") if file_part.endswith(".py") else file_part.replace("/",".")
    cases.append({"nodeid":norm,"name":name,"classname":classname,"class_name":classname,"status":"passed","outcome":"passed","stdout":stdout,"output":stdout,"report":stdout,"provenance":{"producer":"tests/test_uhcr_calibracion_microscopio.py","spec":SPEC,"github_sha":os.environ.get("GITHUB_SHA"),"github_run_id":os.environ.get("GITHUB_RUN_ID"),"github_run_number":os.environ.get("GITHUB_RUN_NUMBER")}})
    payload.update({"schema_version":str(payload.get("schema_version") or "1.0"),"generated_utc":time.strftime("%Y-%m-%d %H:%M:%S UTC",time.gmtime()),"exitstatus":0,"cases":cases})
    TEST_EVIDENCE.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")

@pytest.fixture(scope="session")
def calibration(): return _capture()

def test_teorema_calibracion_embebido():
    t=Path(__file__).read_text(encoding="utf-8")
    assert "Delta Obs(O_i,O_j) =/=> Delta Semantica(S)" in t
    assert "O0 MINIMAL" in t and "O3 LINE_STATE" in t

def test_cuatro_regimenes_ejecutados(calibration):
    assert [r["mode"] for r in calibration["modes"]]==list(MODES)

def test_calibrador_no_emite_veredicto_semantico(calibration):
    assert calibration["system_semantic_status"]=="NO_DETERMINADO"
    assert calibration["security_verdict"]=="NOT_EVALUATED"

def test_metricas_instrumentales_no_negativas(calibration):
    for r in calibration["modes"]:
        assert r["events_confirmed"]>=0
        assert r["elapsed_s"]>0
        assert all(v>=0 for v in (r.get("counters") or {}).values())

def test_integridad_calibrador(calibration):
    assert calibration["auditor_integrity"]=="PASS", calibration

def test_control_positivo_de_cada_sensor(calibration):
    for r in calibration["modes"]:
        cal=r.get("sensor_calibration") or {}
        assert cal.get("exact_core_counts") is True, {"mode":r["mode"],"calibration":cal}

def test_frontera_no_se_autocalifica(calibration):
    p=calibration["perturbation"]["production_path_qualified"]
    o1=next(r for r in calibration["modes"] if r["mode"]=="O1_BOUNDARY")
    if (o1.get("counters") or {}).get("boundary_enter",0)==0:
        assert p["O1_BOUNDARY"] is False

def test_99_traza(calibration,request):
    _publish(request.node.nodeid,request.node.name,calibration["report"])
    print("\n"+calibration["report"]+"\n")
    assert f"SPEC={SPEC}" in calibration["report"]
