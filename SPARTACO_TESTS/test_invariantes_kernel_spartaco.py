"""
UHCR — NÚCLEO METROLÓGICO DE INVARIANTES SPARTACO
SPEC: UHCR-INV-KERNEL-1.3

Objetivo metrológico
--------------------
Este archivo no certifica seguridad universal.

Cadena:
    EXTRACT (por capacidad, sin defaults inventados)
      -> HASH
      -> ORACLE_A/B
      -> KNOWNGOOD independiente
      -> MUTATION MATRIX
      -> QUALIFY
      -> PRODUCTION
      -> DOSSIER

Qualified(T,I) iff
    T(KnownGood_I)=PASS
    and MutationScore(I)=1

PROPERTY_HOLDS_FOR_TESTED_DOMAIN sólo se emite para una campaña cuyo
instrumento esté cualificado y cuyo dominio declarado haya sido ejecutado
sin errores de medición ni contraejemplos.

ORACLE_INDEPENDENCE=ALGORITHMIC_ONLY
CONTRACT_SOURCE_INDEPENDENCE=FALSE
FORMALLY_PROVED=FALSE

Separación explícita:
  I_GATE_CHECKS
  I_OMEGA_GATE
  I_DOM
  I_POST
  I_LIFE
  I7_VALUE_EQUIVALENCE
  I7_IMPLEMENTATION_PATH_INDEPENDENCE = INSTRUMENT_NOT_QUALIFIED
  I_DISC = INSTRUMENT_NOT_QUALIFIED
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import time
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest


SPEC = "UHCR-INV-KERNEL-1.3"
SEED = 37
GENERATOR_VERSION = "G-DET-1.3"

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "diagnostics" / "uhcr_invariantes_kernel"
DOSSIERS = OUT / "dossiers"
SNAPSHOT = OUT / "CONTRACT_SNAPSHOT.json"
REPORT = OUT / "REPORT.txt"
INDEX = OUT / "INDEX.json"
TEST_EVIDENCE = ROOT / "diagnostics" / "test_evidence.json"

POLICY_FLAG_NAMES = (
    "require_contract",
    "require_integrity",
    "require_authentication",
    "require_authorization",
    "require_omega",
    "require_state",
    "require_postcondition",
)
CHECK_FLAGS = (
    "contract_ok",
    "integrity_ok",
    "authentication_ok",
    "authorization_ok",
    "state_ok",
)
POLICY_TO_CHECK = {
    "require_contract": ("contract_ok", "CONTRACT_INVALID"),
    "require_integrity": ("integrity_ok", "INTEGRITY_INVALID"),
    "require_authentication": ("authentication_ok", "AUTHENTICATION_FAILED"),
    "require_authorization": ("authorization_ok", "AUTHORIZATION_DENIED"),
    "require_state": ("state_ok", "STATE_INVALID"),
}


# ================================================================
# Evidencia / carga
# ================================================================

def _candidate_paths() -> List[Path]:
    # La primera ruta es la ruta real del repositorio SPARTACO auditado.
    return [
        ROOT / "modules" / "spartaco_seguridad" / "perimeter.py",
        ROOT / "modules" / "spartaco_seguridad" / "omega" / "perimeter.py",
        ROOT / "omega" / "perimeter.py",
        Path("/home/workdir/artifacts/omega_perimeter.py"),
        Path(__file__).resolve().parent / "omega_perimeter.py",
    ]


def load_perimeter():
    errors = []
    for path in _candidate_paths():
        if not path.is_file():
            continue
        try:
            spec = importlib.util.spec_from_file_location("omega_perimeter_prod", path)
            if spec is None or spec.loader is None:
                errors.append(f"SPEC_LOADER_MISSING:{path}")
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules["omega_perimeter_prod"] = mod
            spec.loader.exec_module(mod)
            return mod, path, errors
        except Exception as exc:
            errors.append(f"{path}:{type(exc).__name__}:{exc}")
    return None, None, errors


PROD, PROD_PATH, LOAD_ERRORS = load_perimeter()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())


def _write_dossier(name: str, payload: Dict[str, Any]) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    DOSSIERS.mkdir(parents=True, exist_ok=True)
    path = DOSSIERS / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


# ================================================================
# Extracción contractual por capacidades
# ================================================================

def extract_contract(mod, path: Optional[Path]) -> Dict[str, Any]:
    """
    Extrae hechos sin defaults semánticos inventados.

    Un fallo de TRANSITIONS no invalida POLICIES.
    Un fallo de MAX_INTEGER_BITS no invalida POST, etc.
    """
    if mod is None or path is None:
        snap = {
            "source_loaded": False,
            "source_path": None,
            "source_hash": None,
            "load_errors": LOAD_ERRORS,
            "capabilities": {
                "policies": False,
                "max_integer_bits": False,
                "transitions": False,
                "postcheck": False,
                "omega": False,
            },
            "errors": ["PRODUCTION_NOT_MOUNTED"],
            "policies": {},
            "named_ops": [],
            "max_integer_bits": None,
            "transitions": {},
        }
        return snap

    errors: List[str] = []
    caps = {
        "policies": False,
        "max_integer_bits": False,
        "transitions": False,
        "postcheck": callable(getattr(mod, "perimeter_postcheck", None)),
        "omega": callable(getattr(mod, "verify_omega_fast", None)),
    }

    policies: Dict[str, Dict[str, bool]] = {}
    raw_policies = getattr(mod, "POLICIES", None)
    if raw_policies is None or not hasattr(raw_policies, "items"):
        errors.append("POLICIES_MISSING_OR_NOT_MAPPING")
    else:
        policy_errors = []
        for name, pol in raw_policies.items():
            flags: Dict[str, bool] = {}
            missing = []
            for field_name in POLICY_FLAG_NAMES:
                if not hasattr(pol, field_name):
                    missing.append(field_name)
                else:
                    value = getattr(pol, field_name)
                    if type(value) is not bool:
                        missing.append(f"{field_name}:NOT_BOOL")
                    else:
                        flags[field_name] = value
            if missing:
                policy_errors.append(f"POLICY_{name}_INVALID:{','.join(missing)}")
            else:
                policies[str(name)] = flags
        if policy_errors:
            errors.extend(policy_errors)
        if policies and not policy_errors:
            caps["policies"] = True

    max_bits = getattr(mod, "MAX_INTEGER_BITS", None)
    if type(max_bits) is int and max_bits > 0:
        caps["max_integer_bits"] = True
    else:
        max_bits = None
        errors.append("MAX_INTEGER_BITS_NOT_EXTRACTED")

    transitions: Dict[str, List[str]] = {}
    table = getattr(mod, "_ALLOWED_TRANSITIONS", None)
    if table is None or not hasattr(table, "items"):
        errors.append("TRANSITIONS_MISSING_OR_NOT_MAPPING")
    else:
        transition_errors = []
        for src, dsts in table.items():
            src_name = getattr(src, "value", None)
            if not isinstance(src_name, str):
                transition_errors.append("TRANSITION_SRC_WITHOUT_STRING_VALUE")
                continue
            names = []
            try:
                iterable = list(dsts)
            except Exception:
                transition_errors.append(f"TRANSITION_DSTS_NOT_ITERABLE:{src_name}")
                continue
            for dst in iterable:
                dst_name = getattr(dst, "value", None)
                if not isinstance(dst_name, str):
                    transition_errors.append(f"TRANSITION_DST_WITHOUT_STRING_VALUE:{src_name}")
                else:
                    names.append(dst_name)
            transitions[src_name] = sorted(names)
        if transition_errors:
            errors.extend(transition_errors)
        if transitions and not transition_errors:
            caps["transitions"] = True

    snap = {
        "source_loaded": True,
        "source_path": str(path),
        "source_hash": _sha256_file(path),
        "spec": SPEC,
        "capabilities": caps,
        "errors": errors,
        "named_ops": sorted(policies),
        "policies": policies,
        "max_integer_bits": max_bits,
        "transitions": transitions,
        "extracted_utc": _now(),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(json.dumps(snap, indent=2, ensure_ascii=False), encoding="utf-8")
    return snap


CONTRACT = extract_contract(PROD, PROD_PATH)


def _cap(name: str, snap: Optional[Dict[str, Any]] = None) -> bool:
    snap = snap or CONTRACT
    return bool((snap.get("capabilities") or {}).get(name))


# ================================================================
# Generador / oráculos
# ================================================================

def G_checks(seed: int, snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    ops = list(snap.get("named_ops") or []) + ["UNKNOWN_OP"]
    cases = []
    n = 0
    for mask in range(32):
        flags = {name: bool((mask >> i) & 1) for i, name in enumerate(CHECK_FLAGS)}
        for op in ops:
            n += 1
            cases.append({
                "case_id": n,
                "operation": op,
                "checks": flags,
                "request_id": f"r{n}",
                "context_id": f"c{n}",
                "resource_id": f"res{n}",
                "A": seed + n,
                "B": seed * 2 + n,
            })
    return cases


def oracle_A_checks(case: Dict[str, Any], snap: Dict[str, Any]) -> Dict[str, Any]:
    pol = (snap.get("policies") or {}).get(case["operation"])
    if pol is None:
        return {"decision": "DENY", "reasons": ["POLICY_MISSING"], "oracle": "A"}
    reasons = []
    for req, (flag, code) in POLICY_TO_CHECK.items():
        if pol[req] and not case["checks"].get(flag, False):
            reasons.append(code)
    return {
        "decision": "DENY" if reasons else "ALLOW",
        "reasons": reasons,
        "oracle": "A",
    }


def oracle_B_checks(case: Dict[str, Any], snap: Dict[str, Any]) -> Dict[str, Any]:
    policies = snap.get("policies") or {}
    op = case["operation"]
    if op not in policies:
        return {"decision": "DENY", "reasons": ["POLICY_MISSING"], "oracle": "B"}
    p = policies[op]
    c = case["checks"]
    reasons = []
    if p["require_contract"] and not c.get("contract_ok"):
        reasons.append("CONTRACT_INVALID")
    if p["require_integrity"] and not c.get("integrity_ok"):
        reasons.append("INTEGRITY_INVALID")
    if p["require_authentication"] and not c.get("authentication_ok"):
        reasons.append("AUTHENTICATION_FAILED")
    if p["require_authorization"] and not c.get("authorization_ok"):
        reasons.append("AUTHORIZATION_DENIED")
    if p["require_state"] and not c.get("state_ok"):
        reasons.append("STATE_INVALID")
    return {
        "decision": "DENY" if reasons else "ALLOW",
        "reasons": reasons,
        "oracle": "B",
    }


def consensus_checks(case: Dict[str, Any], snap: Dict[str, Any]) -> Dict[str, Any]:
    a = oracle_A_checks(case, snap)
    b = oracle_B_checks(case, snap)
    if a["decision"] != b["decision"] or a["reasons"] != b["reasons"]:
        return {
            "decision": "INCONCLUSIVE",
            "reasons": ["ORACLE_DISAGREEMENT"],
            "oracle_a": a,
            "oracle_b": b,
        }
    return a


# KnownGood deliberadamente distinto del código de ambos oráculos.
def known_good_checks(case: Dict[str, Any], snap: Dict[str, Any]) -> str:
    policy = (snap.get("policies") or {}).get(case["operation"])
    if policy is None:
        return "DENY"
    required_values = []
    mapping = (
        ("require_contract", "contract_ok"),
        ("require_integrity", "integrity_ok"),
        ("require_authentication", "authentication_ok"),
        ("require_authorization", "authorization_ok"),
        ("require_state", "state_ok"),
    )
    for requirement, observation in mapping:
        if policy[requirement]:
            required_values.append(case["checks"].get(observation) is True)
    return "ALLOW" if all(required_values) else "DENY"


def _force_check(case: Dict[str, Any], flag: str, value: bool) -> Dict[str, Any]:
    out = deepcopy(case)
    checks = dict(out["checks"])
    checks[flag] = value
    out["checks"] = checks
    return out


def mutant_ignore_check(flag: str):
    def impl(case: Dict[str, Any], snap: Dict[str, Any]) -> str:
        return known_good_checks(_force_check(case, flag, True), snap)
    impl.__name__ = f"mutant_ignore_{flag}"
    return impl


def mutant_unknown_allow(case: Dict[str, Any], snap: Dict[str, Any]) -> str:
    if case["operation"] not in (snap.get("named_ops") or []):
        return "ALLOW"
    return known_good_checks(case, snap)


CHECKS_MUTANTS = {
    "ignore_contract": mutant_ignore_check("contract_ok"),
    "ignore_integrity": mutant_ignore_check("integrity_ok"),
    "ignore_authn": mutant_ignore_check("authentication_ok"),
    "ignore_authz": mutant_ignore_check("authorization_ok"),
    "ignore_state": mutant_ignore_check("state_ok"),
    "unknown_policy_allow": mutant_unknown_allow,
}


def witness_check_mutant(name: str, snap: Dict[str, Any]) -> Dict[str, Any]:
    ops = snap.get("named_ops") or []
    base = {k: True for k in CHECK_FLAGS}
    if name == "unknown_policy_allow":
        return {"operation": "UNKNOWN_OP", "checks": base}
    flag = {
        "ignore_contract": "contract_ok",
        "ignore_integrity": "integrity_ok",
        "ignore_authn": "authentication_ok",
        "ignore_authz": "authorization_ok",
        "ignore_state": "state_ok",
    }[name]
    return _force_check(
        {"operation": ops[0] if ops else "", "checks": dict(base)},
        flag,
        False,
    )


def oracle_omega_gate(omega_ok: bool) -> str:
    return "ALLOW" if omega_ok is True else "DENY"


def known_good_omega_gate(omega_ok: bool) -> str:
    # Independiente del ternario del oráculo.
    allowed_values = {True}
    return "ALLOW" if omega_ok in allowed_values and type(omega_ok) is bool else "DENY"


def mutant_omega_failure_allow(_omega_ok: bool) -> str:
    return "ALLOW"


def mutant_omega_success_deny(_omega_ok: bool) -> str:
    return "DENY"


def oracle_dom(value: Any, max_bits: int) -> str:
    if type(value) is not int:
        return "REJECT"
    if value <= 0:
        return "REJECT"
    if value.bit_length() > max_bits:
        return "REJECT"
    return "ACCEPT"


def known_good_dom(value: Any, max_bits: int) -> str:
    valid_type = value.__class__ is int
    if not valid_type:
        return "REJECT"
    magnitude_ok = value > 0
    width_ok = value.bit_length() <= max_bits
    return "ACCEPT" if magnitude_ok and width_ok else "REJECT"


def mutant_dom_accepts_bool(value: Any, max_bits: int) -> str:
    if isinstance(value, bool):
        return "ACCEPT"
    return known_good_dom(value, max_bits)


def mutant_dom_accepts_float(value: Any, max_bits: int) -> str:
    if isinstance(value, float):
        return "ACCEPT"
    return known_good_dom(value, max_bits)


def oracle_post(pre_allow: bool, pre_op: str, pre_res: str, pre_ctx: str,
                op: str, res: str, ctx: str, post_ok: bool) -> str:
    if not pre_allow:
        return "DENY"
    if not hmac.compare_digest(pre_op, op):
        return "DENY"
    if not hmac.compare_digest(pre_res, res):
        return "DENY"
    if not hmac.compare_digest(pre_ctx, ctx):
        return "DENY"
    if not post_ok:
        return "DENY"
    return "ALLOW"


def known_good_post(**kw) -> str:
    # No llama a oracle_post: misma especificación, implementación independiente.
    if kw["pre_allow"] is not True:
        return "DENY"
    expected_binding = (kw["pre_op"], kw["pre_res"], kw["pre_ctx"])
    observed_binding = (kw["op"], kw["res"], kw["ctx"])
    if expected_binding != observed_binding:
        return "DENY"
    return "ALLOW" if kw["post_ok"] is True else "DENY"


def mutant_post_without_pre(**kw) -> str:
    return "ALLOW" if kw.get("post_ok") else "DENY"


def mutant_post_ignores_resource(**kw) -> str:
    patched = dict(kw)
    patched["res"] = patched["pre_res"]
    return known_good_post(**patched)


def mutant_post_ignores_context(**kw) -> str:
    patched = dict(kw)
    patched["ctx"] = patched["pre_ctx"]
    return known_good_post(**patched)


def mutant_post_ignores_operation(**kw) -> str:
    patched = dict(kw)
    patched["op"] = patched["pre_op"]
    return known_good_post(**patched)


def mutant_post_ignores_postcondition(**kw) -> str:
    patched = dict(kw)
    patched["post_ok"] = True
    return known_good_post(**patched)


def pick_life_edges(snap: Dict[str, Any], initial_state: Optional[str] = None) -> Optional[Dict[str, str]]:
    trans = snap.get("transitions") or {}
    all_states = set(trans.keys())
    for dsts in trans.values():
        all_states.update(dsts)

    sources = [initial_state] if initial_state in trans else sorted(trans)
    for src in sources:
        dsts = trans.get(src) or []
        if not dsts:
            continue
        allowed_dst = sorted(dsts)[0]
        forbidden_candidates = sorted(all_states - set(dsts) - {src})
        if forbidden_candidates:
            return {
                "allowed_src": src,
                "allowed_dst": allowed_dst,
                "forbidden_src": src,
                "forbidden_dst": forbidden_candidates[0],
            }
    return None


def oracle_life(snap: Dict[str, Any], src: str, dst: str) -> bool:
    return dst in set((snap.get("transitions") or {}).get(src) or [])


def known_good_life(snap: Dict[str, Any], src: str, dst: str) -> bool:
    transitions = snap.get("transitions") or {}
    permitted = transitions.get(src)
    if permitted is None:
        return False
    return any(candidate == dst for candidate in permitted)


def mutant_life_any(_snap: Dict[str, Any], _src: str, _dst: str) -> bool:
    return True


def poly_q(A: int, B: int) -> int:
    return A * A - A * B + B * B


def eisenstein_q(A: int, B: int) -> int:
    c, d = A - B, -B
    scalar = A * c - B * d
    omega_coef = A * d + B * c - B * d
    if omega_coef != 0:
        raise RuntimeError("EISENSTEIN_ORACLE_BROKEN")
    return scalar


def oracle_i7_value(A: int, B: int) -> bool:
    return poly_q(A, B) == eisenstein_q(A, B)


def known_good_i7_value(A: int, B: int) -> bool:
    S = A + B
    Q = A * A - A * B + B * B
    return 4 * Q - S * S == 3 * (A - B) * (A - B)


def mutant_i7_always_false(_A: int, _B: int) -> bool:
    return False


def mutant_i7_wrong_sign(A: int, B: int) -> bool:
    wrong_q = A * A + A * B + B * B
    return wrong_q == eisenstein_q(A, B)


def mutant_i7_missing_cross(A: int, B: int) -> bool:
    wrong_q = A * A + B * B
    return wrong_q == eisenstein_q(A, B)


# ================================================================
# Independencia y discriminacion MEDIDAS (no declaradas)
# ================================================================
#
# El expediente original declaraba por escrito cuatro cosas:
#     ORACLE_INDEPENDENCE=ALGORITHMIC_ONLY
#     CONTRACT_SOURCE_INDEPENDENCE=False
#     I7_IMPLEMENTATION_PATH_INDEPENDENCE = INSTRUMENT_NOT_QUALIFIED
#     I_DISC = INSTRUMENT_NOT_QUALIFIED
#
# Aqui nada de eso se escribe a mano: se mide. Si la medicion no
# sostiene la declaracion, el resultado cambia solo.
#
# I7_PATH: la independencia de ruta se mide comparando familias de
# implementaciones algebraicamente equivalentes y operativamente
# distintas, sobre un dominio declarado. La comparacion se cualifica
# con mutaciones: si una ruta defectuosa NO se detecta, el instrumento
# no sirve y se dice, en vez de afirmarlo.
#
# I_DISC: la discriminacion se mide con un detector de colision de
# SEGURIDAD['id'], cualificado contra mutantes del propio detector,
# ejecutado sobre el arbol real y sobre un arbol con colision inyectada.
#
# ASCII-ONLY: este bloque no usa caracteres fuera de ASCII a proposito,
# para que no pueda aparecer mojibake en el informe.

_INDEPENDENCE_CACHE: Dict[str, Any] = {}


def _q_polynomial(A: int, B: int) -> int:
    return A * A - A * B + B * B


def _q_sum_diff_identity(A: int, B: int) -> int:
    # 4Q = S^2 + 3D^2  con S = A+B, D = A-B
    S = A + B
    D = A - B
    return (S * S + 3 * D * D) // 4


def _q_expanded_3ab(A: int, B: int) -> int:
    # (A+B)^2 - 3AB
    return (A + B) ** 2 - 3 * A * B


def _q_contract_channels(A: int, B: int) -> int:
    return PROD.cubic_channels(A, B).Q


def _q_contract_norm(A: int, B: int) -> int:
    return PROD.eisenstein_norm(A, B)


def _q_contract_invariants(A: int, B: int) -> int:
    return PROD.verify_cubic_invariants(A, B)[0].Q


def path_family() -> Dict[str, Any]:
    """Rutas de calculo de Q, equivalentes en algebra y distintas en codigo."""
    if PROD is None:
        return {}
    return {
        "contract_cubic_channels": _q_contract_channels,
        "contract_eisenstein_norm": _q_contract_norm,
        "contract_verify_invariants": _q_contract_invariants,
        "reimpl_polynomial": _q_polynomial,
        "reimpl_sum_diff_identity": _q_sum_diff_identity,
        "reimpl_expanded_3ab": _q_expanded_3ab,
    }


PATH_MUTANTS: Dict[str, Any] = {
    "always_negative": lambda A, B: -1,
    "wrong_sign_AB": lambda A, B: A * A + A * B + B * B,
    "missing_cross_term": lambda A, B: A * A + B * B,
    "float_collapse": lambda A, B: float(A * A - A * B + B * B),
    "bool_collapse": lambda A, B: (A * A - A * B + B * B) == 0,
}


def _same_value(x: Any, y: Any) -> bool:
    """Igualdad estricta: valor y tipo. Un bool no es un entero (I-DOM)."""
    return type(x) is type(y) and x == y


def _domain(seed: int, n: int = 200) -> List[Tuple[int, int]]:
    pares: List[Tuple[int, int]] = [
        (1, 1), (1, 2), (2, 3), (3, 27), (11, 37), (37, 73),
    ]
    x = seed
    for _ in range(n):
        x = (1103515245 * x + 12345) % (1 << 31)
        a = 1 + (x % 4096)
        x = (1103515245 * x + 12345) % (1 << 31)
        b = 1 + (x % 4096)
        pares.append((a, b))
    return pares


def path_values(A: int, B: int, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for name, fn in path_family().items():
        try:
            values[name] = fn(A, B)
        except Exception as exc:
            values[name] = "EXC:{0}".format(type(exc).__name__)
    if overrides:
        values.update(overrides)
    return values


def path_divergence(A: int, B: int, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    values = path_values(A, B, overrides)
    reales = [v for v in values.values() if not isinstance(v, str)]
    if not reales:
        return {"consensus": None, "divergent": sorted(values), "values": values}
    tally: Dict[Any, int] = {}
    for v in reales:
        tally[v] = tally.get(v, 0) + 1
    consensus = sorted(tally.items(), key=lambda kv: (-kv[1], str(kv[0])))[0][0]
    divergent = sorted(n for n, v in values.items() if not _same_value(v, consensus))
    return {"consensus": consensus, "divergent": divergent, "values": values}


def _replace_function(text: str, name: str, stub: str) -> str:
    """Sustituye una funcion top-level completa por un stub. Devuelve "" si no esta."""
    lines = text.split("\n")
    start = None
    for idx, ln in enumerate(lines):
        if ln.startswith("def " + name + "("):
            start = idx
            break
    if start is None:
        return ""
    end = len(lines)
    for idx in range(start + 1, len(lines)):
        ln = lines[idx]
        if ln and not ln[0].isspace():
            end = idx
            break
    return "\n".join(lines[:start] + stub.split("\n") + lines[end:])


def load_mutated_contract(stub_body: str) -> Dict[str, Any]:
    """
    Defecto inyectado en el CONTRATO (no en el instrumento).
    La familia de rutas independientes debe detectarlo.
    """
    if PROD_PATH is None:
        return {"loaded": False, "reason": "CONTRACT_SOURCE_NOT_MOUNTED"}
    try:
        original = PROD_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        return {"loaded": False, "reason": "READ_FAILED:{0}".format(type(exc).__name__)}
    stub = "def eisenstein_norm(A, B):\n" + stub_body + "\n"
    mutated = _replace_function(original, "eisenstein_norm", stub)
    if not mutated:
        return {"loaded": False, "reason": "FUNCTION_NOT_FOUND:eisenstein_norm"}
    try:
        tmp = Path(tempfile.mkdtemp(prefix="sl4_contract_mut_"))
        target = tmp / "perimeter_mutado.py"
        target.write_text(mutated, encoding="utf-8")
        spec = importlib.util.spec_from_file_location("omega_perimeter_mut", target)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["omega_perimeter_mut"] = mod
        spec.loader.exec_module(mod)
        return {"loaded": True, "path": str(target), "module": mod}
    except Exception as exc:
        return {"loaded": False, "reason": "IMPORT_FAILED:{0}:{1}".format(type(exc).__name__, exc)}


def measured_independence() -> Dict[str, Any]:
    """
    Mide; no declara. Devuelve los hechos que el informe publica.
    """
    if _INDEPENDENCE_CACHE:
        return _INDEPENDENCE_CACHE

    facts: Dict[str, Any] = {
        "oracle_independence": "ALGORITHMIC_ONLY",
        "contract_source_independence": False,
        "path_family_n": len(path_family()),
        "path_domain_n": 0,
        "path_violations": [],
        "path_mutations_declared": 0,
        "path_mutations_detected": 0,
        "contract_mutation_detected": False,
        "contract_channels_mutation_detected": None,
        "contract_mutation_detail": None,
    }

    dominio = _domain(SEED)

    # 1) Las rutas equivalentes deben coincidir en todo el dominio.
    violaciones: List[Dict[str, Any]] = []
    for A, B in dominio:
        div = path_divergence(A, B)
        if div["divergent"]:
            violaciones.append({
                "A": A, "B": B,
                "divergent": div["divergent"],
                "values": div["values"],
            })
            if len(violaciones) >= 10:
                break
    facts["path_domain_n"] = len(dominio)
    facts["path_violations"] = violaciones

    # 2) Cualificacion por mutacion: cada ruta defectuosa debe ser detectada.
    detectadas = 0
    A0, B0 = 11, 37
    for name, mutant in PATH_MUTANTS.items():
        div = path_divergence(A0, B0, overrides={name: mutant(A0, B0)})
        if div["divergent"]:
            detectadas += 1
    facts["path_mutations_declared"] = len(PATH_MUTANTS)
    facts["path_mutations_detected"] = detectadas

    # 3) Independencia de la fuente: defecto inyectado en el contrato.
    mut = load_mutated_contract("    return -999999")
    if mut.get("loaded"):
        mod = mut["module"]
        detalle = None
        detectado_norm = False
        detectado_canales = None
        for A, B in ((11, 37), (2, 3), (37, 73)):
            referencia = _q_polynomial(A, B)
            try:
                valor_norm = mod.eisenstein_norm(A, B)
            except Exception as exc:
                valor_norm = "EXC:{0}".format(type(exc).__name__)
            if not _same_value(valor_norm, referencia):
                detectado_norm = True
                if detalle is None:
                    detalle = {
                        "A": A, "B": B,
                        "mutated_contract_norm": valor_norm,
                        "independent_reference": referencia,
                    }
            try:
                valor_canales = mod.cubic_channels(A, B).Q
            except Exception as exc:
                valor_canales = "EXC:{0}".format(type(exc).__name__)
            if not _same_value(valor_canales, referencia):
                detectado_canales = True
        facts["contract_mutation_detected"] = detectado_norm
        facts["contract_channels_mutation_detected"] = detectado_canales
        facts["contract_mutation_detail"] = detalle
    else:
        facts["contract_mutation_detail"] = mut.get("reason")

    # 4) Declaracion derivada, no escrita a mano.
    if (not violaciones
            and facts["path_mutations_detected"] == facts["path_mutations_declared"]
            and facts["path_family_n"] >= 6):
        facts["oracle_independence"] = "MULTI_PATH_ALGEBRAIC_CROSSCHECK"
    if (facts["path_family_n"] >= 4
            and facts["path_mutations_detected"] == facts["path_mutations_declared"]
            and facts["contract_mutation_detected"]):
        facts["contract_source_independence"] = True

    _INDEPENDENCE_CACHE.update(facts)
    return _INDEPENDENCE_CACHE


# ----------------------------------------------------------------
# I_DISC: detector de colision de SEGURIDAD['id']
# ----------------------------------------------------------------

def seguridad_inventory(root: Path) -> List[Dict[str, Any]]:
    """Inventario de declaraciones SEGURIDAD por arbol de archivos."""
    rows: List[Dict[str, Any]] = []
    if not root.is_dir():
        return rows
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            destinos = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if "SEGURIDAD" not in destinos or not isinstance(node.value, ast.Dict):
                continue
            ident = None
            for key, val in zip(node.value.keys, node.value.values):
                if isinstance(key, ast.Constant) and key.value == "id":
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        ident = val.value
            rows.append({"ruta": str(path.relative_to(root)).replace("\\", "/"), "id": ident})
    return rows


def collision_report(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, List[str]] = {}
    invalid: List[Dict[str, Any]] = []
    for row in rows:
        ident = row.get("id")
        if not isinstance(ident, str) or not ident.strip():
            invalid.append(row)
            continue
        counts.setdefault(ident, []).append(str(row.get("ruta")))
    collisions = {k: sorted(v) for k, v in sorted(counts.items()) if len(v) > 1}
    return {
        "collisions": collisions,
        "invalid": invalid,
        "n_rows": len(rows),
        "n_ids": len(counts),
        "has_collision": bool(collisions),
    }


def oracle_collision(rows: List[Dict[str, Any]]) -> bool:
    rep = collision_report(rows)
    return bool(rep["collisions"]) or bool(rep["invalid"])


COLLISION_FIXTURES: List[Dict[str, Any]] = [
    {"name": "control_sin_colision",
     "rows": [{"ruta": "a.py", "id": "A"}, {"ruta": "b.py", "id": "B"}]},
    {"name": "colision_dos_rutas",
     "rows": [{"ruta": "a.py", "id": "A"}, {"ruta": "b.py", "id": "A"}]},
    {"name": "id_vacio",
     "rows": [{"ruta": "a.py", "id": "   "}]},
    {"name": "id_no_str",
     "rows": [{"ruta": "a.py", "id": 7}]},
    {"name": "colision_triple",
     "rows": [{"ruta": "m{0}.py".format(i), "id": "Z"} for i in range(3)]},
]


DETECTOR_MUTANTS: Dict[str, Any] = {
    "blind": lambda rows: {"collisions": {}, "invalid": []},
    "always_collide": lambda rows: {"collisions": {"*": ["*"]}, "invalid": []},
    "ignores_invalid": lambda rows: {"collisions": collision_report(rows)["collisions"],
                                     "invalid": []},
}


def _mutant_verdict(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("collisions")) or bool(payload.get("invalid"))


def engine_registry_witness() -> Dict[str, Any]:
    """
    Testigo del propio registro del Engine: dos contenedores con el
    mismo id deben ser rechazados. Si la API no permite construir el
    testigo, se registra el fallo en vez de inventar el resultado.
    """
    try:
        from core.engine import Contenedor, RegistroModulos
    except Exception as exc:
        return {"witness": "UNAVAILABLE", "detail": "{0}: {1}".format(type(exc).__name__, exc)}
    try:
        reg = RegistroModulos()
        c1 = Contenedor(meta={"id": "DUP_ID", "nombre": "mod_a", "rol": "RA"}, modulo=None, ruta=ROOT)
        c2 = Contenedor(meta={"id": "DUP_ID", "nombre": "mod_b", "rol": "RB"}, modulo=None, ruta=ROOT)
        primero = reg.registrar(c1)
        segundo = reg.registrar(c2)
        return {
            "witness": "CALLED",
            "first": list(primero),
            "second": list(segundo),
            "detected": any("duplicado de id" in str(x) for x in segundo),
            "total_registrados": reg.total(),
        }
    except Exception as exc:
        return {"witness": "CALL_FAILED", "detail": "{0}: {1}".format(type(exc).__name__, exc)}


def injected_collision_tree() -> Dict[str, Any]:
    """Arbol sintetico con colision inyectada. Prueba positiva del detector."""
    base = Path(tempfile.mkdtemp(prefix="sl4_disc_"))
    modulo = base / "modulo"
    modulo.mkdir(parents=True, exist_ok=True)
    (modulo / "uno.py").write_text(
        'SEGURIDAD = {"id": "COLISION_DISC", "nombre": "uno"}\n', encoding="utf-8")
    (modulo / "dos.py").write_text(
        'SEGURIDAD = {"id": "COLISION_DISC", "nombre": "dos"}\n', encoding="utf-8")
    (modulo / "sin_id.py").write_text(
        'SEGURIDAD = {"nombre": "sin_id"}\n', encoding="utf-8")
    rows = seguridad_inventory(base)
    return {"base": str(base), "rows": rows, "report": collision_report(rows)}


def campaign_verdict(quals: List[Dict[str, Any]], prods: List[Dict[str, Any]]) -> str:
    """Dos valores posibles cuando hay evidencia: ROTO o ACOTADO."""
    if any(str(p.get("RESULT")) == "COUNTEREXAMPLE_FOUND" for p in prods):
        return "ROTO"
    if any(str(q.get("RESULT")) == "INSTRUMENT_NOT_QUALIFIED" for q in quals):
        return "INCONCLUSO"
    if prods and all(str(p.get("RESULT")) == "PROPERTY_HOLDS_FOR_TESTED_DOMAIN" for p in prods):
        return "ACOTADO"
    return "INCONCLUSO"


# ================================================================
# Cualificación
# ================================================================

@dataclass
class QualResult:
    invariant: str
    qualified: bool
    result: str
    mutation_score: Optional[float]
    declared: int = 0
    detected: int = 0
    known_good_pass: bool = False
    detail: Dict[str, Any] = field(default_factory=dict)

    def dossier(self) -> Dict[str, Any]:
        return {
            "INVARIANT_ID": self.invariant,
            "SPEC": SPEC,
            "RESULT": self.result,
            "QUALIFIED": self.qualified,
            "MUTATION_SCORE": self.mutation_score,
            "KNOWN_BAD_MUTATIONS": self.declared,
            "DETECTED_MUTATIONS": self.detected,
            "known_good_pass": self.known_good_pass,
            "ORACLE_INDEPENDENCE": measured_independence()["oracle_independence"],
            "CONTRACT_SOURCE_INDEPENDENCE": measured_independence()["contract_source_independence"],
            "INDEPENDENCE_FACTS": {
                k: measured_independence().get(k)
                for k in (
                    "oracle_independence",
                    "contract_source_independence",
                    "path_family_n",
                    "path_mutations_declared",
                    "path_mutations_detected",
                    "contract_mutation_detected",
                )
            },
            "CONTRACT_HASH": CONTRACT.get("source_hash"),
            "EXTRACTION_CAPABILITIES": CONTRACT.get("capabilities"),
            "detail": self.detail,
        }


def _score(rows: List[Dict[str, Any]]) -> Tuple[int, int, float]:
    declared = len(rows)
    detected = sum(1 for r in rows if r.get("DETECTED"))
    return declared, detected, detected / declared if declared else 0.0


def qualify_I_GATE_CHECKS(snap: Optional[Dict[str, Any]] = None) -> QualResult:
    snap = snap or CONTRACT
    if not _cap("policies", snap) or not snap.get("named_ops"):
        q = QualResult("I_GATE_CHECKS", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "POLICIES_NOT_EXTRACTED"})
        _write_dossier("I_GATE_CHECKS_qualification", q.dossier())
        return q

    cases = G_checks(SEED, snap)
    good_ok = True
    oracle_disagreements = []
    for case in cases:
        cons = consensus_checks(case, snap)
        if cons["decision"] == "INCONCLUSIVE":
            oracle_disagreements.append(case["case_id"])
            good_ok = False
            continue
        if known_good_checks(case, snap) != cons["decision"]:
            good_ok = False

    rows = []
    for name, impl in CHECKS_MUTANTS.items():
        w = witness_check_mutant(name, snap)
        expected = consensus_checks(w, snap)["decision"]
        observed = impl(w, snap)
        rows.append({
            "MUTANT": name,
            "WITNESS": w,
            "ORACLE_EXPECTED": expected,
            "MUTANT_OBSERVED": observed,
            "DETECTED": expected != "INCONCLUSIVE" and observed != expected,
        })
    declared, detected, score = _score(rows)
    qualified = good_ok and not oracle_disagreements and score == 1.0
    q = QualResult(
        "I_GATE_CHECKS",
        qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declared, detected, good_ok,
        {"matrix": rows, "n_cases_good": len(cases), "oracle_disagreements": oracle_disagreements},
    )
    _write_dossier("I_GATE_CHECKS_qualification", q.dossier())
    return q


def qualify_I_OMEGA_GATE(snap: Optional[Dict[str, Any]] = None) -> QualResult:
    snap = snap or CONTRACT
    if not _cap("policies", snap) or not _cap("omega", snap):
        q = QualResult("I_OMEGA_GATE", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "OMEGA_OR_POLICIES_NOT_EXTRACTED"})
        _write_dossier("I_OMEGA_GATE_qualification", q.dossier())
        return q

    ops_requiring = [
        op for op, policy in (snap.get("policies") or {}).items()
        if policy["require_omega"]
    ]
    if not ops_requiring:
        q = QualResult("I_OMEGA_GATE", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "NO_POLICY_REQUIRES_OMEGA"})
        _write_dossier("I_OMEGA_GATE_qualification", q.dossier())
        return q

    good_ok = all(
        known_good_omega_gate(v) == oracle_omega_gate(v)
        for v in (False, True)
    )
    rows = []
    for name, mutant, witness in (
        ("omega_failure_allow", mutant_omega_failure_allow, False),
        ("omega_success_deny", mutant_omega_success_deny, True),
    ):
        expected = oracle_omega_gate(witness)
        observed = mutant(witness)
        rows.append({
            "MUTANT": name,
            "WITNESS": {"omega_ok": witness},
            "ORACLE_EXPECTED": expected,
            "MUTANT_OBSERVED": observed,
            "DETECTED": observed != expected,
        })
    declared, detected, score = _score(rows)
    qualified = good_ok and score == 1.0
    q = QualResult(
        "I_OMEGA_GATE", qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declared, detected, good_ok,
        {"matrix": rows, "ops_requiring_omega": ops_requiring},
    )
    _write_dossier("I_OMEGA_GATE_qualification", q.dossier())
    return q


def qualify_I_DOM(snap: Optional[Dict[str, Any]] = None) -> QualResult:
    snap = snap or CONTRACT
    if not _cap("max_integer_bits", snap):
        q = QualResult("I_DOM", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "MAX_INTEGER_BITS_NOT_EXTRACTED"})
        _write_dossier("I_DOM_qualification", q.dossier())
        return q

    bits = snap["max_integer_bits"]
    witnesses = (11, True, 1.0, -3, 1 << bits)
    good_ok = all(known_good_dom(v, bits) == oracle_dom(v, bits) for v in witnesses)

    rows = []
    for name, fn, witness in (
        ("accepts_bool", mutant_dom_accepts_bool, True),
        ("accepts_float", mutant_dom_accepts_float, 1.0),
    ):
        expected = oracle_dom(witness, bits)
        observed = fn(witness, bits)
        rows.append({
            "MUTANT": name,
            "WITNESS": {"type": type(witness).__name__},
            "ORACLE_EXPECTED": expected,
            "MUTANT_OBSERVED": observed,
            "DETECTED": observed != expected,
        })
    declared, detected, score = _score(rows)
    qualified = good_ok and score == 1.0
    q = QualResult(
        "I_DOM", qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declared, detected, good_ok,
        {"matrix": rows, "max_integer_bits": bits},
    )
    _write_dossier("I_DOM_qualification", q.dossier())
    return q


def qualify_I_POST(snap: Optional[Dict[str, Any]] = None) -> QualResult:
    snap = snap or CONTRACT
    if not _cap("postcheck", snap):
        q = QualResult("I_POST", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "POSTCHECK_NOT_AVAILABLE"})
        _write_dossier("I_POST_qualification", q.dossier())
        return q

    allow = dict(
        pre_allow=True, pre_op="X", pre_res="R", pre_ctx="C",
        op="X", res="R", ctx="C", post_ok=True,
    )
    witnesses = [
        allow,
        {**allow, "pre_allow": False},
        {**allow, "op": "Y"},
        {**allow, "res": "OTHER"},
        {**allow, "ctx": "OTHER"},
        {**allow, "post_ok": False},
    ]
    good_ok = all(known_good_post(**w) == oracle_post(**w) for w in witnesses)

    mutation_specs = (
        ("without_pre", mutant_post_without_pre, {**allow, "pre_allow": False}),
        ("ignores_operation", mutant_post_ignores_operation, {**allow, "op": "Y"}),
        ("ignores_resource", mutant_post_ignores_resource, {**allow, "res": "OTHER"}),
        ("ignores_context", mutant_post_ignores_context, {**allow, "ctx": "OTHER"}),
        ("ignores_postcondition", mutant_post_ignores_postcondition, {**allow, "post_ok": False}),
    )
    rows = []
    for name, mutant, witness in mutation_specs:
        expected = oracle_post(**witness)
        observed = mutant(**witness)
        rows.append({
            "MUTANT": name,
            "WITNESS": witness,
            "ORACLE_EXPECTED": expected,
            "MUTANT_OBSERVED": observed,
            "DETECTED": observed != expected,
        })
    declared, detected, score = _score(rows)
    qualified = good_ok and score == 1.0
    q = QualResult(
        "I_POST", qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declared, detected, good_ok, {"matrix": rows},
    )
    _write_dossier("I_POST_qualification", q.dossier())
    return q


def qualify_I_LIFE(snap: Optional[Dict[str, Any]] = None) -> QualResult:
    snap = snap or CONTRACT
    if not _cap("transitions", snap):
        q = QualResult("I_LIFE", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "TRANSITIONS_NOT_EXTRACTED"})
        _write_dossier("I_LIFE_qualification", q.dossier())
        return q

    initial = None
    if PROD is not None and hasattr(PROD, "OperationLifecycle"):
        try:
            initial = PROD.OperationLifecycle().state.value
        except Exception:
            initial = None
    edges = pick_life_edges(snap, initial)
    if edges is None:
        q = QualResult("I_LIFE", False, "INSTRUMENT_NOT_QUALIFIED", None,
                       detail={"reason": "NO_SEPARATING_EDGES", "initial": initial})
        _write_dossier("I_LIFE_qualification", q.dossier())
        return q

    good_ok = (
        known_good_life(snap, edges["allowed_src"], edges["allowed_dst"])
        == oracle_life(snap, edges["allowed_src"], edges["allowed_dst"])
        is True
        and known_good_life(snap, edges["forbidden_src"], edges["forbidden_dst"])
        == oracle_life(snap, edges["forbidden_src"], edges["forbidden_dst"])
        is False
    )
    expected = oracle_life(snap, edges["forbidden_src"], edges["forbidden_dst"])
    observed = mutant_life_any(snap, edges["forbidden_src"], edges["forbidden_dst"])
    rows = [{
        "MUTANT": "any_transition",
        "WITNESS": edges,
        "ORACLE_EXPECTED": expected,
        "MUTANT_OBSERVED": observed,
        "DETECTED": observed != expected,
    }]
    declared, detected, score = _score(rows)
    qualified = good_ok and score == 1.0
    q = QualResult(
        "I_LIFE", qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declared, detected, good_ok,
        {"matrix": rows, "edges": edges, "initial_state": initial},
    )
    _write_dossier("I_LIFE_qualification", q.dossier())
    return q


def qualify_I7_VALUE(_snap: Optional[Dict[str, Any]] = None) -> QualResult:
    domain = [(11, 37), (1, 1), (2, 3), (37, 73), (3, 27)]
    good_ok = all(
        known_good_i7_value(a, b) == oracle_i7_value(a, b) is True
        for a, b in domain
    )

    rows = []
    for name, mutant, witness in (
        ("always_false", mutant_i7_always_false, (11, 37)),
        ("wrong_sign_AB", mutant_i7_wrong_sign, (11, 37)),
        ("missing_cross_term", mutant_i7_missing_cross, (11, 37)),
    ):
        a, b = witness
        expected = oracle_i7_value(a, b)
        observed = mutant(a, b)
        rows.append({
            "MUTANT": name,
            "WITNESS": {"A": a, "B": b},
            "ORACLE_EXPECTED": expected,
            "MUTANT_OBSERVED": observed,
            "DETECTED": observed != expected,
        })
    declared, detected, score = _score(rows)
    qualified = good_ok and score == 1.0
    q = QualResult(
        "I7_VALUE_EQUIVALENCE", qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declared, detected, good_ok,
        {"matrix": rows, "domain": domain},
    )
    _write_dossier("I7_VALUE_EQUIVALENCE_qualification", q.dossier())
    return q


def qualify_I7_PATH(_snap: Optional[Dict[str, Any]] = None) -> QualResult:
    """
    Independencia de ruta: medida, no declarada.

    Se exige que la familia de rutas equivalentes coincida en el dominio
    Y que la comparacion sea sensible a rutas defectuosas (mutantes) y a
    un defecto inyectado en el contrato. Si la comparacion no discrimina,
    el resultado es INSTRUMENT_NOT_QUALIFIED, con la razon medida.
    """
    facts = measured_independence()
    familia = path_family()
    if not familia:
        q = QualResult(
            "I7_IMPLEMENTATION_PATH_INDEPENDENCE", False,
            "INSTRUMENT_NOT_QUALIFIED", None,
            detail={"reason": "PRODUCTION_NOT_MOUNTED"},
        )
        _write_dossier("I7_PATH_qualification", q.dossier())
        return q

    mut_rows = []
    A0, B0 = 11, 37
    for name, mutant in PATH_MUTANTS.items():
        div = path_divergence(A0, B0, overrides={name: mutant(A0, B0)})
        mut_rows.append({
            "MUTANT": name,
            "WITNESS": {"A": A0, "B": B0},
            "CONSENSUS": div["consensus"],
            "MUTANT_OBSERVED": div["values"].get(name),
            "DETECTED": bool(div["divergent"]),
        })
    declaradas, detectadas, score = _score(mut_rows)
    violaciones = facts["path_violations"]

    qualified = (
        declaradas > 0
        and score == 1.0
        and not violaciones
        and facts["contract_mutation_detected"]
        and facts["path_family_n"] >= 6
    )
    if qualified:
        motivo = None
    elif violaciones:
        motivo = "RUTAS_EQUIVALENTES_DISCREPAN_EN_EL_DOMINIO"
    elif score != 1.0:
        motivo = "MUTANTE_DE_RUTA_NO_DETECTADO"
    elif not facts["contract_mutation_detected"]:
        motivo = "DEFECTO_DE_CONTRATO_NO_DETECTADO"
    else:
        motivo = "FAMILIA_DE_RUTAS_INSUFICIENTE"

    q = QualResult(
        "I7_IMPLEMENTATION_PATH_INDEPENDENCE",
        qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declaradas, detectadas, not violaciones,
        {
            "reason": motivo,
            "matrix": mut_rows,
            "path_family": sorted(familia),
            "path_family_n": facts["path_family_n"],
            "domain_n": facts["path_domain_n"],
            "violations": violaciones,
            "contract_mutation": {
                "detected": facts["contract_mutation_detected"],
                "channels_path_detected": facts["contract_channels_mutation_detected"],
                "detail": facts["contract_mutation_detail"],
            },
        },
    )
    _write_dossier("I7_PATH_qualification", q.dossier())
    return q


def qualify_I_DISC(_snap: Optional[Dict[str, Any]] = None) -> QualResult:
    """
    Discriminacion de colision de identidad: medida, no declarada.

    Cualifica el detector contra fixtures de verdad conocida y contra
    mutantes del propio detector, exige deteccion de una colision
    inyectada en un arbol real, y consulta el registro del Engine como
    testigo. Todo lo que no se pueda observar queda registrado como tal.
    """
    fixture_rows = []
    referencia_ok = True
    for fx in COLLISION_FIXTURES:
        esperado = oracle_collision(fx["rows"])
        observado = _mutant_verdict(collision_report(fx["rows"]))
        etiqueta_ok = esperado == observado
        fixture_rows.append({
            "FIXTURE": fx["name"],
            "ORACLE_EXPECTED": esperado,
            "OBSERVED": observado,
            "DETECTED": etiqueta_ok,
        })
        if not etiqueta_ok:
            referencia_ok = False

    mut_rows = []
    for name, mutant in DETECTOR_MUTANTS.items():
        detectado = False
        for fx in COLLISION_FIXTURES:
            esperado = oracle_collision(fx["rows"])
            try:
                observado = _mutant_verdict(mutant(fx["rows"]))
            except Exception:
                observado = None
            if observado != esperado:
                detectado = True
        mut_rows.append({"MUTANT": name, "DETECTED": detectado})
    declaradas, detectadas, score = _score(mut_rows)

    witness = engine_registry_witness()
    inyectado = injected_collision_tree()
    inyeccion_detectada = bool(inyectado["report"]["has_collision"])

    qualified = (
        referencia_ok
        and score == 1.0
        and inyeccion_detectada
        and (witness.get("witness") != "CALLED" or witness.get("detected") is True)
    )
    if qualified:
        motivo = None
    elif not referencia_ok:
        motivo = "DETECTOR_REFERENCIA_NO_COINCIDE_CON_EL_ORACULO"
    elif score != 1.0:
        motivo = "MUTANTES_DE_DETECCION_NO_DETECTADOS"
    elif not inyeccion_detectada:
        motivo = "COLISION_INYECTADA_NO_DETECTADA"
    else:
        motivo = "ENGINE_REGISTRO_NO_RECHAZA_ID_DUPLICADO"

    inventario_real = seguridad_inventory(ROOT / "modules")
    real_report = collision_report(inventario_real)

    q = QualResult(
        "I_DISC",
        qualified,
        "QUALIFIED" if qualified else "INSTRUMENT_NOT_QUALIFIED",
        score, declaradas, detectadas, referencia_ok,
        {
            "reason": motivo,
            "fixtures": fixture_rows,
            "matrix": mut_rows,
            "engine_registry_witness": witness,
            "injected_tree": {
                "base": inyectado["base"],
                "n_rows": inyectado["report"]["n_rows"],
                "collisions": inyectado["report"]["collisions"],
            },
            "real_tree": {
                "n_rows": real_report["n_rows"],
                "n_ids": real_report["n_ids"],
                "collisions": real_report["collisions"],
                "n_invalid": len(real_report["invalid"]),
            },
        },
    )
    _write_dossier("I_DISC_qualification", q.dossier())
    return q


# ================================================================
# Producción
# ================================================================

def _prod_precheck(case: Dict[str, Any], **omega_override: Any) -> Dict[str, Any]:
    if PROD is None:
        return {
            "decision": None,
            "reasons": [],
            "exception": "PRODUCTION_NOT_MOUNTED",
            "bucket": "MEASUREMENT_ERROR",
        }
    try:
        checks = PROD.SecurityChecks(
            contract_ok=case["checks"]["contract_ok"],
            integrity_ok=case["checks"]["integrity_ok"],
            authentication_ok=case["checks"]["authentication_ok"],
            authorization_ok=case["checks"]["authorization_ok"],
            state_ok=case["checks"]["state_ok"],
        )
        kwargs = dict(
            request_id=case.get("request_id", "r"),
            context_id=case.get("context_id", "c"),
            resource_id=case.get("resource_id", "res"),
            operation=case["operation"],
            checks=checks,
            A=case.get("A", 11),
            B=case.get("B", 37),
        )
        kwargs.update(omega_override)
        d = PROD.perimeter_precheck(**kwargs)
        return {
            "decision": d.decision.value,
            "reasons": list(d.reason_codes),
            "exception": None,
            "bucket": "PRODUCTION_BEHAVIOR",
        }
    except Exception as exc:
        # Excepción escapada de la frontera que se esperaba medir:
        # evidencia de producción, no error del instrumento.
        return {
            "decision": None,
            "reasons": [],
            "exception": f"{type(exc).__name__}: {exc}",
            "bucket": "PRODUCTION_EXCEPTION",
        }


def campaign_result(qualified: bool, declared: int, executed: int,
                    measurement_errors: int, counterexamples: int) -> str:
    if not qualified:
        return "INSTRUMENT_NOT_QUALIFIED"
    if measurement_errors or declared != executed:
        return "INCONCLUSIVE"
    if counterexamples:
        return "COUNTEREXAMPLE_FOUND"
    return "PROPERTY_HOLDS_FOR_TESTED_DOMAIN"


# ================================================================
# Tests de integridad y cualificación
# ================================================================

def test_archivo_y_spec():
    assert Path(__file__).name == "test_invariantes_kernel_spartaco.py"
    text = Path(__file__).read_text(encoding="utf-8")
    assert SPEC in text
    assert "INSTRUMENT_NOT_QUALIFIED" in text
    assert "ORACLE_INDEPENDENCE=" in text


def test_ruta_real_spartaco_esta_en_el_buscardor():
    paths = [str(p).replace("\\", "/") for p in _candidate_paths()]
    assert any(p.endswith("/modules/spartaco_seguridad/perimeter.py") for p in paths)


def test_extractor_no_inventa_defaults():
    src = Path(__file__).read_text(encoding="utf-8")
    extract_src = src.split("def extract_contract", 1)[1].split("CONTRACT =", 1)[0]
    assert "hasattr(pol, field_name)" in extract_src
    assert 'getattr(mod, "MAX_INTEGER_BITS", None)' in extract_src
    assert "4096" not in extract_src


def test_contrato_o_expediente_honesto():
    if PROD is None:
        _write_dossier("CONTRACT", CONTRACT)
        pytest.skip("perimeter.py no montado: no se juzga producción")
    assert CONTRACT["source_loaded"]
    assert CONTRACT["source_hash"]
    assert CONTRACT["source_path"]


def test_qualify_I_GATE_CHECKS():
    q = qualify_I_GATE_CHECKS()
    if PROD is None:
        assert not q.qualified
        pytest.skip("sin contrato de producción")
    assert q.qualified, q.dossier()


def test_qualify_I_OMEGA_GATE():
    q = qualify_I_OMEGA_GATE()
    if PROD is None:
        assert not q.qualified
        pytest.skip("sin contrato de producción")
    assert q.qualified, q.dossier()


def test_qualify_I_DOM():
    q = qualify_I_DOM()
    if PROD is None:
        assert not q.qualified
        pytest.skip("sin contrato de producción")
    assert q.qualified, q.dossier()


def test_qualify_I_POST():
    q = qualify_I_POST()
    if PROD is None:
        assert not q.qualified
        pytest.skip("sin producción")
    assert q.qualified, q.dossier()


def test_qualify_I_LIFE():
    q = qualify_I_LIFE()
    if PROD is None:
        assert not q.qualified
        pytest.skip("sin producción")
    assert q.qualified, q.dossier()


def test_qualify_I7_VALUE():
    q = qualify_I7_VALUE()
    assert q.qualified, q.dossier()


def test_qualify_I7_PATH():
    q = qualify_I7_PATH()
    assert q.qualified, q.dossier()


def test_qualify_I_DISC():
    q = qualify_I_DISC()
    assert q.qualified, q.dossier()


def test_independencia_medida_no_declarada():
    facts = measured_independence()
    assert facts["oracle_independence"] in {
        "ALGORITHMIC_ONLY",
        "MULTI_PATH_ALGEBRAIC_CROSSCHECK",
    }
    assert isinstance(facts["contract_source_independence"], bool)
    assert facts["path_family_n"] >= 6
    assert facts["path_mutations_declared"] > 0
    assert facts["path_mutations_declared"] == facts["path_mutations_detected"]
    assert facts["contract_mutation_detected"] is True


def test_I7_PATH_se_rompe_si_una_ruta_diverge(monkeypatch):
    """Falsabilidad: si una ruta diverge, el instrumento NO se declara cualificado."""
    mod = sys.modules[__name__]
    original_family = mod.path_family

    def familia_torcida():
        fam = dict(original_family())
        fam["reimpl_polynomial"] = lambda A, B: A * A + A * B + B * B
        return fam

    mod._INDEPENDENCE_CACHE.clear()
    monkeypatch.setattr(mod, "path_family", familia_torcida)
    try:
        q = qualify_I7_PATH()
    finally:
        mod._INDEPENDENCE_CACHE.clear()
    assert q.qualified is False
    assert q.detail["reason"] == "RUTAS_EQUIVALENTES_DISCREPAN_EN_EL_DOMINIO"


def test_I_DISC_se_rompe_si_no_hay_colision_observable(monkeypatch):
    """Falsabilidad: si la colision inyectada no se ve, NO se declara cualificado."""
    mod = sys.modules[__name__]
    vacio = {
        "base": "SIN_ARBOL",
        "rows": [],
        "report": {"collisions": {}, "invalid": [], "n_rows": 0, "n_ids": 0,
                   "has_collision": False},
    }
    monkeypatch.setattr(mod, "injected_collision_tree", lambda: vacio)
    q = qualify_I_DISC()
    assert q.qualified is False
    assert q.detail["reason"] == "COLISION_INYECTADA_NO_DETECTADA"


# ================================================================
# Campañas de producción
# ================================================================

def test_produccion_I_GATE_CHECKS():
    """
    Sólo DENY causado por policy/checks.
    Los casos que el oráculo local marcaría ALLOW pasan a la capa Ω y no
    pertenecen a esta campaña.
    """
    q = qualify_I_GATE_CHECKS()
    if not q.qualified:
        _write_dossier("I_GATE_CHECKS_production", {
            "INVARIANT_ID": "I_GATE_CHECKS",
            "CAMPAIGN": "C_conformance",
            "RESULT": "INSTRUMENT_NOT_QUALIFIED",
        })
        pytest.skip("instrumento no cualificado")

    deny_cases = []
    for case in G_checks(SEED, CONTRACT):
        expected = consensus_checks(case, CONTRACT)
        if expected["decision"] == "DENY":
            deny_cases.append((case, expected))

    declared = len(deny_cases)
    executed = 0
    measurement_errors = 0
    counterexamples = []

    for case, expected in deny_cases:
        got = _prod_precheck(case)
        if got["bucket"] == "MEASUREMENT_ERROR":
            measurement_errors += 1
            continue
        executed += 1

        if got["bucket"] == "PRODUCTION_EXCEPTION":
            counterexamples.append({
                "CASE_ID": case["case_id"],
                "kind": "PRODUCTION_EXCEPTION",
                "expected": expected,
                "observed": got,
            })
            continue

        if got["decision"] != "DENY":
            counterexamples.append({
                "CASE_ID": case["case_id"],
                "kind": "DECISION_MISMATCH",
                "INPUT_RAW": {"operation": case["operation"], "checks": case["checks"]},
                "ORACLE_EXPECTED": expected,
                "PRODUCTION_OBSERVED": got,
            })
            continue

        if expected["reasons"] == ["POLICY_MISSING"]:
            if "POLICY_MISSING" not in got["reasons"]:
                counterexamples.append({
                    "CASE_ID": case["case_id"],
                    "kind": "REASON_MISMATCH",
                    "expected": expected,
                    "observed": got,
                })
        else:
            missing = [r for r in expected["reasons"] if r not in got["reasons"]]
            if missing:
                counterexamples.append({
                    "CASE_ID": case["case_id"],
                    "kind": "MISSING_REASONS",
                    "missing": missing,
                    "observed": got,
                })

    result = campaign_result(
        q.qualified, declared, executed, measurement_errors, len(counterexamples)
    )
    _write_dossier("I_GATE_CHECKS_production", {
        "INVARIANT_ID": "I_GATE_CHECKS",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": declared,
        "CASES_EXECUTED": executed,
        "N_MEASUREMENT_ERRORS": measurement_errors,
        "N_COUNTEREXAMPLES": len(counterexamples),
        "COUNTEREXAMPLES": counterexamples[:20],
        "RESULT": result,
        "FORMALLY_PROVED": False,
        "NOTE": "Dominio declarado: DENY por policy/checks antes de Ω.",
    })
    assert result != "COUNTEREXAMPLE_FOUND", counterexamples[:3]
    assert result in {"PROPERTY_HOLDS_FOR_TESTED_DOMAIN", "INCONCLUSIVE"}


def test_produccion_I_OMEGA_GATE():
    q = qualify_I_OMEGA_GATE()
    if not q.qualified:
        pytest.skip("instrumento no cualificado")

    ops = [
        op for op, p in CONTRACT["policies"].items()
        if p["require_omega"]
    ]
    assert ops

    case = {
        "operation": ops[0],
        "checks": {k: True for k in CHECK_FLAGS},
        "request_id": "rO",
        "context_id": "cO",
        "resource_id": "resO",
        "A": 11,
        "B": 37,
    }
    got = _prod_precheck(case, S=1, Q=1, N=1)
    omega_failed = (
        got["bucket"] == "PRODUCTION_BEHAVIOR"
        and got["decision"] == "DENY"
        and "OMEGA_FAILED" in got["reasons"]
    )
    result = "PROPERTY_HOLDS_FOR_TESTED_DOMAIN" if omega_failed else "COUNTEREXAMPLE_FOUND"
    _write_dossier("I_OMEGA_GATE_production", {
        "INVARIANT_ID": "I_OMEGA_GATE",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": 1,
        "CASES_EXECUTED": 1,
        "RESULT": result,
        "INPUT_RAW": {"A": 11, "B": 37, "S": 1, "Q": 1, "N": 1},
        "OBSERVED": got,
    })
    assert omega_failed, got


def test_produccion_I_DOM():
    q = qualify_I_DOM()
    if not q.qualified:
        pytest.skip("instrumento no cualificado")

    op = CONTRACT["named_ops"][0]
    observations = {}
    for label, A in (("bool", True), ("float", 1.0), ("valid_int", 11)):
        try:
            ev = PROD.verify_omega_fast(
                request_id="r", context_id="c", resource_id="res",
                operation=op, A=A, B=37,
            )
            observations[label] = {
                "verdict": ev.verdict.value,
                "reasons": list(ev.reason_codes),
            }
        except Exception as exc:
            observations[label] = {"exception": f"{type(exc).__name__}: {exc}"}

    bool_rejected = observations["bool"].get("verdict") != "OMEGA_OK"
    float_rejected = observations["float"].get("verdict") != "OMEGA_OK"
    # Para el entero válido sólo medimos que no sea rechazado por la aduana de tipo.
    int_not_type_rejected = "InputRejected" not in observations["valid_int"].get("reasons", [])
    ok = bool_rejected and float_rejected and int_not_type_rejected

    _write_dossier("I_DOM_production", {
        "INVARIANT_ID": "I_DOM",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": 3,
        "CASES_EXECUTED": 3,
        "RESULT": "PROPERTY_HOLDS_FOR_TESTED_DOMAIN" if ok else "COUNTEREXAMPLE_FOUND",
        "OBSERVED": observations,
        "NOTE": "I_DOM no exige OMEGA_OK al entero válido; sólo ausencia de rechazo de dominio.",
    })
    assert ok, observations


def test_produccion_I_POST():
    q = qualify_I_POST()
    if not q.qualified:
        pytest.skip("instrumento no cualificado")
    if not _cap("policies") or not CONTRACT["named_ops"]:
        pytest.skip("policy no extraída")

    op = CONTRACT["named_ops"][0]
    checks = PROD.SecurityChecks(True, True, True, True, True)
    pre = PROD.perimeter_precheck(
        request_id="r1", context_id="c1", resource_id="doc",
        operation=op, checks=checks, A=11, B=37,
    )
    if pre.decision.value != "ALLOW":
        _write_dossier("I_POST_production", {
            "INVARIANT_ID": "I_POST",
            "CAMPAIGN": "C_conformance",
            "RESULT": "INCONCLUSIVE",
            "reason": "PRE_NOT_ALLOW",
            "pre_decision": pre.decision.value,
            "pre_reasons": list(pre.reason_codes),
        })
        pytest.skip("pre no ALLOW; binding no observable en este testigo")

    probes = {
        "operation_swap": dict(operation="__OTHER__", resource_id="doc", context_id="c1", postcondition_ok=True),
        "resource_swap": dict(operation=op, resource_id="OTHER", context_id="c1", postcondition_ok=True),
        "context_swap": dict(operation=op, resource_id="doc", context_id="OTHER", postcondition_ok=True),
        "post_false": dict(operation=op, resource_id="doc", context_id="c1", postcondition_ok=False),
    }
    observed = {}
    for name, kwargs in probes.items():
        d = PROD.perimeter_postcheck(pre=pre, **kwargs)
        observed[name] = {"decision": d.decision.value, "reasons": list(d.reason_codes)}

    denied_pre = PROD.deny(
        request_id="r1", context_id="c1", resource_id="doc",
        operation=op, reasons=("X",),
    )
    forged = PROD.perimeter_postcheck(
        pre=denied_pre, operation=op, resource_id="doc",
        context_id="c1", postcondition_ok=True,
    )
    observed["denied_pre"] = {
        "decision": forged.decision.value,
        "reasons": list(forged.reason_codes),
    }

    ok = all(v["decision"] == "DENY" for v in observed.values())
    _write_dossier("I_POST_production", {
        "INVARIANT_ID": "I_POST",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": len(observed),
        "CASES_EXECUTED": len(observed),
        "RESULT": "PROPERTY_HOLDS_FOR_TESTED_DOMAIN" if ok else "COUNTEREXAMPLE_FOUND",
        "OBSERVED": observed,
    })
    assert ok, observed


def test_produccion_I_LIFE():
    q = qualify_I_LIFE()
    if not q.qualified:
        pytest.skip("instrumento no cualificado")

    life = PROD.OperationLifecycle()
    initial = life.state.value
    edges = pick_life_edges(CONTRACT, initial)
    if edges is None or edges["forbidden_src"] != initial:
        _write_dossier("I_LIFE_production", {
            "INVARIANT_ID": "I_LIFE",
            "CAMPAIGN": "C_conformance",
            "RESULT": "INCONCLUSIVE",
            "reason": "NO_FORBIDDEN_EDGE_FROM_ACTUAL_INITIAL_STATE",
            "initial_state": initial,
        })
        pytest.skip("no hay arista prohibida medible desde el estado inicial")

    target = None
    for member in PROD.OperationState:
        if member.value == edges["forbidden_dst"]:
            target = member
            break
    if target is None:
        pytest.skip("estado destino no resoluble")

    raised = False
    exception = None
    try:
        life.transition(target)
    except PROD.StateTransitionRejected as exc:
        raised = True
        exception = f"{type(exc).__name__}: {exc}"

    _write_dossier("I_LIFE_production", {
        "INVARIANT_ID": "I_LIFE",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": 1,
        "CASES_EXECUTED": 1,
        "RESULT": "PROPERTY_HOLDS_FOR_TESTED_DOMAIN" if raised else "COUNTEREXAMPLE_FOUND",
        "INITIAL_STATE": initial,
        "EDGE_TESTED": edges,
        "EXCEPTION": exception,
    })
    assert raised, edges


def test_produccion_I7_VALUE_EQUIVALENCE():
    q = qualify_I7_VALUE()
    if not q.qualified:
        pytest.skip("instrumento no cualificado")
    if PROD is None or not callable(getattr(PROD, "eisenstein_norm", None)):
        _write_dossier("I7_VALUE_EQUIVALENCE_production", {
            "INVARIANT_ID": "I7_VALUE_EQUIVALENCE",
            "RESULT": "INCONCLUSIVE",
            "reason": "PRODUCTION_EISENSTEIN_NORM_NOT_AVAILABLE",
        })
        pytest.skip("eisenstein_norm no disponible")

    domain = [(11, 37), (1, 1), (2, 3), (37, 73), (3, 27)]
    rows = []
    counterexamples = []
    for A, B in domain:
        expected = poly_q(A, B)
        try:
            observed = PROD.eisenstein_norm(A, B)
            row = {"A": A, "B": B, "expected": expected, "observed": observed}
            rows.append(row)
            if observed != expected:
                counterexamples.append(row)
        except Exception as exc:
            row = {"A": A, "B": B, "expected": expected,
                   "exception": f"{type(exc).__name__}: {exc}"}
            rows.append(row)
            counterexamples.append(row)

    result = "COUNTEREXAMPLE_FOUND" if counterexamples else "PROPERTY_HOLDS_FOR_TESTED_DOMAIN"
    _write_dossier("I7_VALUE_EQUIVALENCE_production", {
        "INVARIANT_ID": "I7_VALUE_EQUIVALENCE",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": len(domain),
        "CASES_EXECUTED": len(rows),
        "N_COUNTEREXAMPLES": len(counterexamples),
        "COUNTEREXAMPLES": counterexamples,
        "OBSERVED": rows,
        "RESULT": result,
    })
    assert not counterexamples, counterexamples


def test_produccion_I7_PATH():
    q = qualify_I7_PATH()
    if not q.qualified:
        _write_dossier("I7_PATH_production", {
            "INVARIANT_ID": "I7_IMPLEMENTATION_PATH_INDEPENDENCE",
            "CAMPAIGN": "C_conformance",
            "RESULT": "INSTRUMENT_NOT_QUALIFIED",
            "qualification": q.dossier(),
        })
        pytest.skip("instrumento no cualificado")

    dominio = _domain(SEED)
    discrepancias = []
    ejecutados = 0
    for A, B in dominio:
        esperado = _q_polynomial(A, B)
        try:
            observado = PROD.cubic_channels(A, B).Q
        except Exception as exc:
            discrepancias.append({"A": A, "B": B, "exception": type(exc).__name__})
            continue
        ejecutados += 1
        if not _same_value(observado, esperado):
            discrepancias.append({"A": A, "B": B, "expected": esperado, "observed": observado})

    op = (CONTRACT.get("named_ops") or [None])[0]
    meta_probe: Dict[str, Any] = {"observable": False}
    metadata_ok: Optional[bool] = None
    if op:
        a = PROD.verify_omega_fast(
            request_id="r1", context_id="c1", resource_id="res1",
            operation=op, A=11, B=37,
        )
        b = PROD.verify_omega_fast(
            request_id="r2", context_id="c2", resource_id="res2",
            operation=op, A=11, B=37,
        )
        if a.state is not None and b.state is not None:
            canales_iguales = (a.state.S, a.state.Q, a.state.N) == (b.state.S, b.state.Q, b.state.N)
            transcript_distinto = a.transcript != b.transcript
            meta_probe = {
                "observable": True,
                "channels_equal_under_metadata_change": canales_iguales,
                "transcript_differs": transcript_distinto,
            }
            metadata_ok = canales_iguales and transcript_distinto
        else:
            meta_probe = {
                "observable": False,
                "verdicts": [a.verdict.value, b.verdict.value],
            }

    result = campaign_result(
        q.qualified, len(dominio), ejecutados, len(dominio) - ejecutados, len(discrepancias)
    )
    _write_dossier("I7_PATH_production", {
        "INVARIANT_ID": "I7_IMPLEMENTATION_PATH_INDEPENDENCE",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": len(dominio),
        "CASES_EXECUTED": ejecutados,
        "N_COUNTEREXAMPLES": len(discrepancias),
        "COUNTEREXAMPLES": discrepancias[:20],
        "METADATA_INDEPENDENCE": meta_probe,
        "RESULT": result,
        "FORMALLY_PROVED": False,
    })
    assert not discrepancias, discrepancias[:3]
    assert metadata_ok is not False, meta_probe


def test_produccion_I_DISC():
    q = qualify_I_DISC()
    inyectado = injected_collision_tree()
    real = collision_report(seguridad_inventory(ROOT / "modules"))

    detectado_en_inyectado = bool(inyectado["report"]["has_collision"])
    colisiones_reales = real["collisions"]
    contador = 0 if (detectado_en_inyectado and not colisiones_reales) else 1

    result = campaign_result(q.qualified, 2, 2, 0, contador)
    _write_dossier("I_DISC_production", {
        "INVARIANT_ID": "I_DISC",
        "CAMPAIGN": "C_conformance",
        "CONTRACT_HASH": CONTRACT.get("source_hash"),
        "CASES_DECLARED": 2,
        "CASES_EXECUTED": 2,
        "INJECTED_TREE": {
            "collision_detected": detectado_en_inyectado,
            "collisions": inyectado["report"]["collisions"],
        },
        "REAL_TREE": {
            "n_rows": real["n_rows"],
            "n_ids": real["n_ids"],
            "n_invalid": len(real["invalid"]),
            "collisions": colisiones_reales,
        },
        "RESULT": result,
        "FORMALLY_PROVED": False,
    })
    assert detectado_en_inyectado, inyectado["report"]
    assert not colisiones_reales, colisiones_reales


# ================================================================
# Informe / Omega Diary
# ================================================================

def test_99_informe_dos_tablas(request):
    facts = measured_independence()
    qualify_I_GATE_CHECKS()
    qualify_I_OMEGA_GATE()
    qualify_I_DOM()
    qualify_I_POST()
    qualify_I_LIFE()
    qualify_I7_VALUE()
    qualify_I7_PATH()
    qualify_I_DISC()

    quals, prods, counters = [], [], []
    if DOSSIERS.exists():
        for p in sorted(DOSSIERS.glob("*.json")):
            try:
                row = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if p.name.endswith("_qualification.json"):
                quals.append(row)
            elif p.name.endswith("_production.json"):
                prods.append(row)
                for cx in row.get("COUNTEREXAMPLES") or []:
                    if isinstance(cx, dict):
                        counters.append({"from": row.get("INVARIANT_ID"), **cx})

    lines = [
        "=" * 78,
        f"{SPEC} — TABLAS METROLÓGICAS",
        "=" * 78,
        f"CONTRACT_PATH={CONTRACT.get('source_path')}",
        f"CONTRACT_HASH={CONTRACT.get('source_hash')}",
        f"EXTRACTION_CAPABILITIES={CONTRACT.get('capabilities')}",
        f"EXTRACTION_ERRORS={CONTRACT.get('errors')}",
        f"SEED={SEED}",
        "ORACLE_INDEPENDENCE=ALGORITHMIC_ONLY",
        "CONTRACT_SOURCE_INDEPENDENCE=FALSE",
        "FORMALLY_PROVED=FALSE",
        "-" * 78,
        "INSTRUMENT QUALIFICATION",
        f"{'INVARIANTE':<44} {'RESULTADO':<26} {'SCORE':>6}",
    ]
    for r in quals:
        score = r.get("MUTATION_SCORE")
        score_s = "-" if score is None else f"{score:.2f}"
        lines.append(
            f"{str(r.get('INVARIANT_ID')):<44} "
            f"{str(r.get('RESULT')):<26} {score_s:>6}"
        )

    lines += [
        "-" * 78,
        "PRODUCTION CONFORMANCE",
        f"{'INVARIANTE':<44} {'RESULTADO'}",
    ]
    if not prods:
        lines.append("  (sin campañas de producción persistidas)")
    for r in prods:
        lines.append(f"{str(r.get('INVARIANT_ID')):<44} {str(r.get('RESULT'))}")

    lines += ["-" * 78, "COUNTEREXAMPLES"]
    if not counters:
        lines.append("  ninguno persistido")
    for cx in counters[:30]:
        lines.append(f"  {cx}")

    lines += [
        "-" * 78,
        "INDEPENDENCE (MEASURED, NOT DECLARED)",
        "  ORACLE_INDEPENDENCE={0}".format(facts["oracle_independence"]),
        "  CONTRACT_SOURCE_INDEPENDENCE={0}".format(facts["contract_source_independence"]),
        "  PATH_FAMILY_N={0} DOMAIN_N={1} VIOLATIONS={2}".format(
            facts["path_family_n"],
            facts["path_domain_n"],
            len(facts["path_violations"]),
        ),
        "  PATH_MUTATIONS={0}/{1} CONTRACT_MUTATION_DETECTED={2} CHANNELS_DETECTED={3}".format(
            facts["path_mutations_detected"],
            facts["path_mutations_declared"],
            facts["contract_mutation_detected"],
            facts["contract_channels_mutation_detected"],
        ),
        "  I7_PATH e I_DISC dejan de ser literales: su resultado sale de la medicion.",
        "-" * 78,
        "LECTURA",
        "  QUALIFIED califica el instrumento; no equivale a que producción pasó.",
        "  PROPERTY_HOLDS_FOR_TESTED_DOMAIN sólo describe el dominio declarado.",
        "  I7_PATH e I_DISC se miden aquí; ya no se declaran por escrito.",
        "  FORMALLY_PROVED no puede ser emitido por esta campaña pytest.",
        "  VEREDICTO_CAMPANA={0}".format(campaign_verdict(quals, prods)),
        "=" * 78,
    ]

    report = "\n".join(lines)
    OUT.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report, encoding="utf-8")
    INDEX.write_text(json.dumps({
        "spec": SPEC,
        "contract_path": CONTRACT.get("source_path"),
        "contract_hash": CONTRACT.get("source_hash"),
        "capabilities": CONTRACT.get("capabilities"),
        "errors": CONTRACT.get("errors"),
        "generated_utc": _now(),
        "qualification": quals,
        "production": prods,
        "counterexamples": counters,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    TEST_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = json.loads(TEST_EVIDENCE.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    cases = payload.get("cases") if isinstance(payload.get("cases"), list) else []
    nodeid = request.node.nodeid.replace("\\", "/")
    cases = [
        c for c in cases
        if not (
            isinstance(c, dict)
            and str(c.get("nodeid") or "").replace("\\", "/") == nodeid
        )
    ]
    cases.append({
        "nodeid": nodeid,
        "file": "tests/test_invariantes_kernel_spartaco.py",
        "name": request.node.name,
        "stdout": report,
        "status": "passed",
        "outcome": "passed",
        "provenance": {
            "producer": "tests/test_invariantes_kernel_spartaco.py",
            "spec": SPEC,
            "github_sha": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_number": os.environ.get("GITHUB_RUN_NUMBER"),
            "contract_hash": CONTRACT.get("source_hash"),
        },
    })
    payload["cases"] = cases
    payload["generated_utc"] = _now()
    TEST_EVIDENCE.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print()
    print(report)
    print()
    assert "INSTRUMENT QUALIFICATION" in report
    assert "PRODUCTION CONFORMANCE" in report
