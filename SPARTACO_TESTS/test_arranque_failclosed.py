# =============================================================================
#  UHCR — AUDITORÍA FAIL-CLOSED DE UN RECURSO AISLADO  (ARCHIVO ÚNICO)
# =============================================================================
#
#  CÓMO SE USA
#  -----------
#  Este archivo es TODO: motor + pruebas. No depende de ningún otro .py.
#  Para auditar otro recurso:
#     1. Copia este archivo como   tests/test_<recurso>_failclosed.py
#     2. Cambia SOLO la línea TARGET (sección 1, justo debajo).
#  Nada más se toca. La identidad de cada copia queda en tres hashes:
#   * AUDITOR_SHA256          = H(archivo exacto ejecutado, incluida TARGET)
#   * AUDITOR_TEMPLATE_SHA256 = H(archivo completo − línea TARGET)
#       → igual en todas las copias ⇔ las copias son byte a byte idénticas
#         salvo TARGET (no se acomodó nada tras ver cada recurso).
#   * AUDITOR_ENGINE_SHA256   = H(sección M exclusivamente: el motor)
#       → igual en todas las copias ⇔ mismo motor.
#  Si la línea TARGET no es única o faltan los marcadores de la sección M,
#  el hash correspondiente es None y el auditor queda NO calificado.
#
#  REGLAS
#  ------
#   * REPORT = f(EVIDENCE): todo se deriva del expediente de esta corrida.
#   * Sin nombres de producción, sin números mágicos, sin roles esperados
#     escritos a mano: lo que haya que comparar se descubre del propio TARGET.
#   * AUDIT_SCOPE=ISOLATED_RESOURCE y SYSTEM_WIDE_CLAIM=NO: se mide el
#     componente por sí solo; no es una afirmación sobre el sistema completo.
#   * Veredicto por propiedad (familias descubiertas por el motor); nunca un
#     PASS único mezclado. Ningún PASS sin falsificación ejecutada.
#   * La evidencia se PERSISTE antes de cualquier aserción
#     (JSON + index.jsonl en diagnostics/uhcr_resources/<recurso>/).
#   * INSTRUMENTO (AUDITOR_QUALIFICATION) separado del RECURSO
#     (TARGET_SECURITY_RESULT): un contraejemplo del recurso no descalifica
#     al auditor.
#
#  ESTRUCTURA DEL ARCHIVO
#  ----------------------
#   1. Recurso a auditar (TARGET)                 ← única línea que cambia
#   M. MOTOR (descubrimiento AST, roles, falsificación, contabilidad,
#      registro persistente, informe, autopruebas del motor)
#   2. Llamada al motor (una sola auditoría + registro persistido)
#   3. Resolución del recurso
#   4. Informe y estructura del expediente
#   5. Veredicto por propiedad (auditor vs recurso)
#   6. Descripción ≠ aplicabilidad ≠ medición ≠ veredicto
#   7. Equivalencia wrapper ↔ motor
#   8. Anti-hardcode del motor
#   9. Registro de auditoría, identidad de corrida, identidad plantilla/motor y contabilidad
#   E. Ejecución directa (python3 este_archivo.py [ruta/target.py])
# =============================================================================
"""
UHCR — ISOLATED RESOURCE FAIL-CLOSED AUDITOR (STATIC + selective dynamic)
==========================================================================

THE motor. Wrappers (test_<resource>_failclosed.py) only set TARGET and,
for calibration resources, assert expectations.

Pipeline
--------
    Target → AST → SEGURIDAD → SemanticInventory → Properties
           → (only if applicable) PositiveWitness → Falsifications
           → Oracle → Verdict

1.4 — FOUR SEPARATE STAGES (semantic description != property applicability
!= measurement != verdict):
  (a) DESCRIPTION: role/asset/declared semantics are explanatory metadata
      and traceability only; they feed no applicability, campaign or verdict.
  (b)+(c) MEASUREMENT/APPLICABILITY: EVERY capability receives a campaign
      attempt per measured property (FAIL_CLOSED, INTEGRITY), selected by the
      runtime signature shape only. Applicability is ESTABLISHED by a valid
      positive witness (protected effect observed) plus >=1 falsifiable
      condition actually executed. No valid positive control → NOT_QUALIFIED.
  (d) VERDICT from measurement only (see pass_fail_closed()).

Anti-hardcode contract
----------------------
This file MUST NOT name production symbols of any audited resource. All
derivation rules are universal structural features (enum members ALLOW/DENY,
a `decision` field, parameter-shape contracts, return-annotation links...).
Calibration expectations live exclusively in the wrappers.

Measurement isolation
---------------------
SYSTEM_PERIMETER_BYPASSED_FOR_MEASUREMENT=YES means the auditor loads the
target file in isolation (direct file import with ROOT on sys.path) so the
resource can be measured without traversing the system perimeter. It is a
statement about the MEASUREMENT set-up only; it is not a claim that any
production perimeter was disabled, and results carry SYSTEM_WIDE_CLAIM=NO.

Inspired by the rules of test_uhcr_fail_closed_falsificacion.py (oracle:
exceptions ≠ DENY; CE only when compromise verified ∧ execution observed ∧
protected effect observed), reimplemented minimally to avoid importing the
system-wide pytest module.

Audit record, accounting and auditor/target separation (SPEC_VERSION)
---------------------------------------------------------------------
Every audit_resource() call returns exp['audit_record'] (identity of this
run: TARGET_SHA256, AUDITOR_SHA256, SPEC, RUN_ID, UTC_TIMESTAMP,
RUN_IDENTITY) and exp['accounting'] (zero-loss invariants). persist_record()
writes the whole expediente as JSON (never overwriting) plus an index line.

ACCOUNTING definitions (all derived from the case/campaign structures):
  * capabilities_discovered = names read from the SEGURIDAD declaration list.
    classified  = capability record whose role != UNKNOWN AND confidence
                  != NOT_RESOLVED (ORCHESTRATOR is a resolved role).
    unresolved  = capability record whose role == UNKNOWN OR confidence
                  == NOT_RESOLVED.
    unaccounted = declared names without a record + records not declared.
  * cases_generated = entries of every probe PLAN (block['plan']), written
    by the probe BEFORE it runs anything. executed = PLAN entries matched by a
    record in block['cases']; not_executed_accounted = PLAN entries matched by
    a record in block['not_executed'] (each with a reason). unaccounted =
    PLAN entries matched by neither + records that were never planned.
    Witness-search calls are stimulus construction, not cases (their
    exceptions are still listed, origin TARGET_OBSERVED_IN_SEARCH).
  * properties_applicable = verdict families != NOT_APPLICABLE.
    qualified = PASS/FAIL backed by executed evidence in property_evidence;
    not_qualified = NOT_QUALIFIED/INSUFFICIENT_EVIDENCE; unaccounted = rest.
  * exceptions: every exception raised by target code inside a tagged probe
    call is logged by _call() in a run-scoped recorder independent of the
    case records; both views must reconcile (unreconciled == 0).

AUDITOR_QUALIFICATION (the instrument) is separated from
TARGET_SECURITY_RESULT (the resource): a target counterexample is an
observation and never disqualifies the auditor.
"""
from __future__ import annotations


# -----------------------------------------------------------------------------
# 1. RECURSO A AUDITAR — ÚNICA LÍNEA QUE CAMBIA ENTRE COPIAS
# -----------------------------------------------------------------------------
TARGET = "modules/spartaco_seguridad/arranque.py"


# =============================================================================
# M. MOTOR UHCR — NO MODIFICAR ENTRE COPIAS
# =============================================================================

import ast
import enum
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import re
import sys
import traceback
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ===========================================================================
# Constants / vocabulary
# ===========================================================================


ROOT = Path(__file__).resolve().parent

ROLES = ("ENFORCEMENT_GATE", "VERIFIER", "CLASSIFIER",
         "SELF_DIAGNOSTIC", "ORCHESTRATOR", "UNKNOWN")
CONFIDENCE = ("DECLARED", "DERIVED", "OBSERVED", "NOT_RESOLVED")
PROPERTY_RESULTS = ("PASS", "FAIL", "NOT_APPLICABLE",
                    "NOT_RESOLVED", "NOT_QUALIFIED", "INSUFFICIENT_EVIDENCE")
ALIGNMENTS = ("CONVERGENT_SEMANTIC_EVIDENCE", "SEMANTIC_DIVERGENCE",
              "SEMANTIC_NOT_RESOLVED")

# Specification of this auditor (goes into every AUDIT RECORD).
SPEC_VERSION = "UHCR-RESOURCE-1.4"
SPEC_EVOLUTION = (
    "1.0: isolated resource audit (static roles, selective dynamic "
    "falsification, per-property verdict, evidence rule); "
    "1.1: +AUDIT_RECORD (sha256 identity, run id, persisted JSON + index), "
    "+ACCOUNTING zero-loss invariants (capabilities/cases/properties/"
    "exceptions), +AUDITOR_QUALIFICATION vs TARGET_SECURITY_RESULT, "
    "+PROPERTIES_BASE / discovered_property_families, "
    "+DECLARATION_TRACEABILITY (STATIC_CROSSCHECK; PROVENANCE kept as "
    "NOT_QUALIFIED compat key); "
    "1.2: declaration-first semantics: SEGURIDAD is authoritative for role/property/asset/effect; AST derivation is only an independent cross-check and never silently reclassifies the target; missing declared semantics remains NOT_RESOLVED; "
    "1.1+identity: single self-contained file; AUDITOR_TEMPLATE_SHA256 "
    "(file minus the unique TARGET line) and AUDITOR_ENGINE_SHA256 "
    "(section M only) recorded separately; missing markers or non-unique "
    "TARGET line => hash None => AUDITOR_QUALIFICATION=FAIL; "
    "1.3.2: four verdict states (NOT_RESOLVED / NOT_QUALIFIED / PASS|FAIL / "
    "INSUFFICIENT_EVIDENCE only after a qualified measurement); "
    "1.4: role/property decoupling: semantic description, property "
    "applicability, measurement and verdict are separate stages; every "
    "capability gets a campaign attempt selected by signature shape (never by "
    "role or SEGURIDAD); applicability = valid positive witness + >=1 "
    "falsifiable condition executed; SEGURIDAD never grants PASS and its "
    "absence never prevents the search (public functions are enumerated); "
    "PASS_FC = witness AND falsifications>0 AND stimuli verified AND decisions "
    "observable AND 0 counterexamples; per-property measurement block "
    "(APPLICABILITY/BASIS/CAPABILITIES_APPLICABLE/CAMPAIGNS/POSITIVE_CONTROLS/"
    "FALSIFICATIONS/COUNTEREXAMPLES/VERDICT) in report and AUDIT RECORD; "
    "1.4 scope rule: a capability whose executed output carries no protected "
    "decision (no ALLOW/DENY; no ok evidence field) is NOT_A_DEFENSE → "
    "OUT_OF_SCOPE/NOT_APPLICABLE, never NOT_QUALIFIED; zero defenses in scope "
    "→ property NOT_APPLICABLE (NO_PROTECTED_DECISION_IN_TARGET)")

# Base vocabulary of property families. The motor may emit more; wrappers
# read the actual list through discovered_property_families(exp).
PROPERTIES_BASE = ("FAIL_CLOSED", "INTEGRITY", "STATE_TRANSITION",
                   "OBSERVABILITY", "DECLARATION_TRACEABILITY", "PROVENANCE")
EVIDENCE_KINDS = ("DYNAMIC_FALSIFICATION", "STATIC_CROSSCHECK", "NONE")
PROVENANCE_COMPAT_NOTE = ("authentic provenance not measured; "
                          "see DECLARATION_TRACEABILITY")
AUDITOR_RESULTS = ("PASS", "FAIL")
TARGET_RESULTS = ("PASS", "FAIL", "INCOMPLETE", "NOT_EVALUATED",
                  "INSTRUMENT_NOT_QUALIFIED_FOR_PROPERTY")
CLEAN_STATUSES = ("OK", "ABSENT", "PARSE_FAILED", "IMPORT_FAILED")
AUDIT_RECORD_FIELDS = (
    "TARGET_FILE", "TARGET_SHA256", "AUDITOR", "AUDITOR_SHA256", "AUDITOR_TEMPLATE_SHA256",
    "AUDITOR_ENGINE_SHA256", "SPEC",
    "SPEC_EVOLUTION", "RUN_ID", "UTC_TIMESTAMP", "RUN_IDENTITY",
    "RESOURCE_DISCOVERED", "SEGURIDAD_DECLARED",
    "CAPABILITIES_DISCOVERED", "CAPABILITIES_CLASSIFIED",
    "CAPABILITIES_UNRESOLVED", "PROPERTIES_DISCOVERED",
    "PROPERTIES_APPLICABLE", "PROPERTIES_QUALIFIED",
    "PROPERTIES_NOT_QUALIFIED", "PROPERTIES_UNACCOUNTED",
    "CAPABILITY_SOURCE", "PROPERTY_MEASUREMENT", "MEASUREMENT_EQUATION_HOLDS",
    "CASES_GENERATED", "CASES_EXECUTED", "CASES_ACCOUNTED_NON_EXEC",
    "CASES_UNACCOUNTED", "POSITIVE_CONTROLS", "POSITIVE_CONTROLS_WITNESSED",
    "COUNTEREXAMPLES", "COUNTEREXAMPLE_LIST", "EXCEPTIONS", "EXCEPTION_LIST",
    "EXCEPTIONS_RECONCILED",
    "SEMANTIC_DIVERGENCES", "UNRESOLVED", "AUDITOR_QUALIFICATION",
    "AUDITOR_QUALIFICATION_REASONS", "TARGET_SECURITY_RESULT",
    "TARGET_SECURITY_DETAILS", "SECURITY_VERDICT", "RESOURCE_EVALUATION",
    "SYSTEM_WIDE_CLAIM", "SEMANTIC_FINGERPRINT", "RECORD_PATH")
RECORD_SECTIONS = ("STATIC_DISCOVERY", "SEMANTIC_CLASSIFICATION",
                   "POSITIVE_CONTROLS", "FALSIFICATIONS", "OBSERVATIONS",
                   "EXCEPTIONS", "COUNTEREXAMPLES", "PROPERTY_VERDICTS",
                   "UNRESOLVED", "ACCOUNTING", "AUDIT_RECORD")

# 1.4: properties measured per capability by dynamic campaigns, and the
# bounded meaning of a PASS (never a claim of universal impenetrability).
MEASURED_PROPERTIES = ("FAIL_CLOSED", "INTEGRITY")
APPLICABILITY_STATES = ("ESTABLISHED", "NOT_ESTABLISHED", "NOT_APPLICABLE",
                        "NOT_RESOLVED", "OUT_OF_SCOPE")
PASS_MEANING = "no counterexample found in qualified tested domain"

# Universal parameter-shape contracts (not production names).
ID_PARAMS = frozenset({"request_id", "context_id", "resource_id", "operation"})
COMPOSITE_PARAMS = ID_PARAMS | {"checks"}
POSTCONDITION_PARAMS = frozenset({"pre", "postcondition_ok"})
CHECK_FIELDS = frozenset({"contract_ok", "integrity_ok", "authentication_ok",
                          "authorization_ok", "state_ok"})
GATE_INPUT_PARAMS = ID_PARAMS | {"checks", "pre", "postcondition_ok"}

# Bounded search domain for numeric positive witnesses.
_NUM_DOMAIN = range(1, 41)


# ===========================================================================
# AST helpers
# ===========================================================================

def _ann_name(node: Any) -> Optional[str]:
    """Head name of an annotation / call target."""
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _ann_name(node.value)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return _ann_name(ast.parse(node.value, mode="eval").body)
        except SyntaxError:
            return node.value
    if isinstance(node, ast.BinOp):  # X | None
        return _ann_name(node.left) or _ann_name(node.right)
    return None


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _extract_seguridad_ast(tree: ast.Module) -> dict[str, Any]:
    """Module-level SEGURIDAD dict; literal keys/values recovered where possible.
    If assigned several times, the LAST module-level assignment wins (runtime semantics)."""
    for node in reversed(tree.body):
        targets: list[ast.AST] = []
        value = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if not any(isinstance(t, ast.Name) and t.id == "SEGURIDAD" for t in targets):
            continue
        full = _literal(value)
        if isinstance(full, dict):
            return full
        partial: dict[str, Any] = {}
        if isinstance(value, ast.Dict):
            for k, v in zip(value.keys, value.values):
                key = _literal(k) if k is not None else None
                if not isinstance(key, str):
                    continue
                val = _literal(v)
                if val is not None:
                    partial[key] = val
                elif isinstance(v, ast.Name):
                    partial[key] = f"<ref:{v.id}>"
        return partial
    return {}


def _is_enum_class(cls: ast.ClassDef) -> bool:
    return any(_ann_name(b) in ("Enum", "IntEnum", "StrEnum", "Flag")
               for b in cls.bases)


def _enum_members(cls: ast.ClassDef) -> set[str]:
    out: set[str] = set()
    for item in cls.body:
        if isinstance(item, ast.Assign):
            out |= {t.id for t in item.targets if isinstance(t, ast.Name)}
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            out.add(item.target.id)
    return {m for m in out if not m.startswith("_")}


def _fields(cls: ast.ClassDef) -> dict[str, Optional[str]]:
    return {i.target.id: _ann_name(i.annotation) for i in cls.body
            if isinstance(i, ast.AnnAssign) and isinstance(i.target, ast.Name)}


def _has_property(cls: ast.ClassDef, name: str) -> bool:
    for i in cls.body:
        if isinstance(i, (ast.FunctionDef, ast.AsyncFunctionDef)) and i.name == name:
            if any(_ann_name(d) == "property" for d in i.decorator_list):
                return True
    return False


def _params(fn: ast.FunctionDef) -> dict[str, Optional[str]]:
    a = fn.args
    out = {x.arg: _ann_name(x.annotation)
           for x in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)}
    return out


def _called_names(fn: ast.AST) -> set[str]:
    return {n for n in (_ann_name(c.func) for c in ast.walk(fn)
                        if isinstance(c, ast.Call)) if n}


def _attr_names(fn: ast.AST) -> set[str]:
    return {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}


# ===========================================================================
# Semantic inventory (types, helpers, state machine) — universal features
# ===========================================================================

class _Inventory:
    def __init__(self, tree: ast.Module):
        self.tree = tree
        self.classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        self.functions: dict[str, ast.FunctionDef] = {
            n.name: n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

        enums = {k: c for k, c in self.classes.items() if _is_enum_class(c)}
        # Decision enum: Enum exposing both ALLOW and DENY members.
        self.decision_enums = {k for k, c in enums.items()
                               if {"ALLOW", "DENY"} <= _enum_members(c)}
        # Classification enums: any other Enum with members.
        self.label_enums = {k for k, c in enums.items()
                            if k not in self.decision_enums and _enum_members(c)}
        # Decision carrier: record type with a `decision` field typed as a decision enum.
        self.decision_carriers = {k for k, c in self.classes.items()
                                  if _fields(c).get("decision") in self.decision_enums}
        # Verdict/evidence carrier: `.ok` + reason codes / verdict, no decision enum.
        self.verdict_carriers = set()
        for k, c in self.classes.items():
            if k in self.decision_carriers or k in enums:
                continue
            f = _fields(c)
            has_ok = "ok" in f or _has_property(c, "ok")
            has_rc = "reason_codes" in f or "reasons" in f
            has_vd = "verdict" in f and f["verdict"] not in self.decision_enums
            if (has_ok and (has_rc or has_vd)) or (has_vd and has_rc):
                self.verdict_carriers.add(k)
        # Label carrier: label enum itself, or record embedding a label enum field
        # (and not already a decision/verdict carrier).
        self.label_carriers = set(self.label_enums)
        for k, c in self.classes.items():
            if k in self.decision_carriers or k in self.verdict_carriers or k in enums:
                continue
            if any(t in self.label_enums for t in _fields(c).values()):
                self.label_carriers.add(k)
        self.deny_helpers = self._find_deny_helpers()
        self.transition_maps = self._find_transition_maps()

    def _find_deny_helpers(self) -> set[str]:
        """Functions that return a decision carrier/enum and construct only DENY
        (reference `.DENY` but never `.ALLOW`)."""
        out: set[str] = set()
        carriers = self.decision_carriers | self.decision_enums
        for name, fn in self.functions.items():
            attrs = _attr_names(fn)
            ret = _ann_name(fn.returns)
            constructs = bool(_called_names(fn) & self.decision_carriers)
            if "DENY" in attrs and "ALLOW" not in attrs and (ret in carriers or constructs):
                out.add(name)
            elif ret in carriers and any(
                    isinstance(r, ast.Return) and isinstance(r.value, ast.Constant)
                    and str(r.value.value).upper() == "DENY" for r in ast.walk(fn)):
                out.add(name)
        return out

    def _find_transition_maps(self) -> list[str]:
        """Module-level mapping whose name speaks of allowed transitions."""
        out = []
        for node in self.tree.body:
            tgts = node.targets if isinstance(node, ast.Assign) else (
                [node.target] if isinstance(node, ast.AnnAssign) else [])
            for t in tgts:
                if isinstance(t, ast.Name):
                    u = t.id.upper()
                    if "TRANSITION" in u and ("ALLOW" in u or "VALID" in u):
                        out.append(t.id)
        return out

    def public(self) -> dict[str, Any]:
        return {
            "decision_enums": sorted(self.decision_enums),
            "decision_carriers": sorted(self.decision_carriers),
            "verdict_carriers": sorted(self.verdict_carriers),
            "label_enums": sorted(self.label_enums),
            "label_carriers": sorted(self.label_carriers),
            "deny_helpers": sorted(self.deny_helpers),
            "transition_maps": list(self.transition_maps),
            "function_count": len(self.functions),
            "class_count": len(self.classes),
        }


# ===========================================================================
# Step C — role derivation
# ===========================================================================

def _derive(fn: Optional[ast.FunctionDef], inv: _Inventory,
            conceptos: list, declared_caps: frozenset = frozenset()) -> dict[str, Any]:
    if fn is None:
        return {"role": "UNKNOWN", "confidence": "NOT_RESOLVED",
                "signals": ["capability_not_a_module_function"],
                "reason": "declared capability has no module-level FunctionDef "
                          "(class/constant/absent); role rules are function-shaped"}

    params = _params(fn)
    pnames = set(params)
    ret = _ann_name(fn.returns)
    calls = _called_names(fn)
    attrs = _attr_names(fn)
    sig: list[str] = []

    shape = _structural_shape(fn, inv)

    # ---- enforcement signals ----
    enf = 0
    if ret in inv.decision_carriers or ret in inv.decision_enums:
        enf += 1; sig.append("returns_decision_carrier")
    if calls & inv.deny_helpers:
        enf += 1; sig.append("calls_deny_helper")
    elif "DENY" in attrs and ret in (inv.decision_carriers | inv.decision_enums):
        enf += 1; sig.append("constructs_DENY")
    if shape == "COMPOSITE_CHECKS":
        enf += 1; sig.append("shape_COMPOSITE_CHECKS")
    if shape == "POSTCONDITION" and ret is not None and params.get("pre") == ret:
        enf += 1; sig.append("shape_POSTCONDITION_same_carrier")
    elif shape == "POSTCONDITION":
        enf += 1; sig.append("shape_POSTCONDITION")

    # ---- verifier signals ----
    ver = 0
    if ret in inv.verdict_carriers:
        ver += 1; sig.append("returns_verdict_carrier")
        if not (calls & inv.deny_helpers) and "ALLOW" not in attrs:
            ver += 1; sig.append("no_decision_production")
        if calls & {"sha256", "sha256_hex", "hexdigest", "blake2b", "compare_digest"} or \
                any("transcript" in c.lower() or "hash" in c.lower() for c in calls):
            sig.append("builds_digest_or_transcript")

    # ---- classifier signals ----
    cls_ = 0
    if ret in inv.label_carriers:
        cls_ += 1; sig.append("returns_label_carrier")
        if not ({"ALLOW", "DENY"} & attrs):
            cls_ += 1; sig.append("no_ALLOW_DENY_reference")

    # ---- self-diagnostic signals ----
    sd = 0
    if not (pnames & GATE_INPUT_PARAMS):
        sd += 1; sig.append("no_gate_input_params")
    if ret in ("bool", "dict", "Dict", "Mapping") and ret not in inv.classes:
        sd += 1; sig.append("returns_simple_status")
    a = fn.args
    n_required = (len(a.posonlyargs) + len(a.args) - len(a.defaults)
                  + sum(d is None for d in a.kw_defaults))
    if n_required == 0:
        sd += 1; sig.append("no_required_params")

    # ---- resolve ----
    if enf >= 2:
        role = "ENFORCEMENT_GATE"
    elif ver >= 2:
        role = "VERIFIER"
    elif cls_ >= 2 and enf == 0:
        role = "CLASSIFIER"
    elif sd >= 3 and enf == 0 and ver == 0 and cls_ == 0:
        role = "SELF_DIAGNOSTIC"
    elif len(calls & (declared_caps - {fn.name})) >= 2 and enf == 0 and ver == 0 \
            and cls_ == 0:
        role = "ORCHESTRATOR"; sig.append("composes_declared_capabilities")
    else:
        role = "UNKNOWN"

    confidence = "NOT_RESOLVED" if role == "UNKNOWN" else "DERIVED"
    reason = None
    if role == "UNKNOWN":
        reason = ("insufficient structural signals "
                  f"(enforcement={enf}, verifier={ver}, classifier={cls_}, "
                  f"self_diagnostic={sd}); return={ret}")

    failure_policy = protected_effect = asset = None
    if role == "ENFORCEMENT_GATE":
        protected_effect = "ALLOW"
        if any(isinstance(c, str) and "DEFAULT_DENY" in c for c in conceptos) or \
                "calls_deny_helper" in sig:
            failure_policy = "DEFAULT_DENY"
        asset = "AUTHORIZATION_DECISION"
        if inv.transition_maps:
            asset += "+STATE_TRANSITION"
    elif role == "VERIFIER":
        asset = ("EVIDENCE_INTEGRITY" if "builds_digest_or_transcript" in sig
                 else "COHERENCE")
    elif role == "CLASSIFIER":
        asset = "CLASSIFICATION_LABEL"
    elif role == "SELF_DIAGNOSTIC":
        asset = "SELF_STATUS"

    return {
        "role": role, "confidence": confidence, "shape": shape,
        "signals": sig, "return_annotation": ret,
        "param_annotations": params,
        "failure_policy": failure_policy, "protected_effect": protected_effect,
        "asset": asset, "reason": reason,
        "scores": {"enforcement": enf, "verifier": ver,
                   "classifier": cls_, "self_diagnostic": sd},
    }


def _structural_shape(fn: Optional[ast.FunctionDef], inv: _Inventory) -> Optional[str]:
    """Signature shape (parameter/return contracts only). Selects the campaign
    machinery; it is not a role and grants no applicability."""
    if fn is None:
        return None
    pnames = set(_params(fn))
    if COMPOSITE_PARAMS <= pnames:
        return "COMPOSITE_CHECKS"
    if POSTCONDITION_PARAMS <= pnames:
        return "POSTCONDITION"
    if _ann_name(fn.returns) in inv.verdict_carriers:
        return "EVIDENCE_VERDICT"
    return None


# ===========================================================================
# Step A — isolate & import
# ===========================================================================

def _module_name(path: Path, root: Path) -> str:
    try:
        return ".".join(path.resolve().relative_to(root.resolve()).with_suffix("").parts)
    except ValueError:
        return f"_uhcr_isolated_{path.stem}"


def _import_isolated(path: Path, root: Path, mod_name: str) -> tuple[Any, Optional[str]]:
    added = str(root) not in sys.path
    if added:
        sys.path.insert(0, str(root))
    try:
        if mod_name in sys.modules and getattr(sys.modules[mod_name], "__file__", None) \
                and Path(sys.modules[mod_name].__file__).resolve() == path.resolve():
            return sys.modules[mod_name], None
        try:
            return importlib.import_module(mod_name), None
        except Exception:
            spec = importlib.util.spec_from_file_location(mod_name, str(path))
            if spec is None or spec.loader is None:
                return None, "IMPORT_FAILED:NO_SPEC"
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
            return mod, None
    except Exception as exc:
        sys.modules.pop(mod_name, None)
        return None, f"IMPORT_FAILED:{type(exc).__name__}:{exc}"
    finally:
        if added:
            try:
                sys.path.remove(str(root))
            except ValueError:
                pass


# ===========================================================================
# Step F — minimal oracle + probes (only APPLICABLE roles)
# ===========================================================================

def _is_allow(out: Any) -> Optional[bool]:
    """True=ALLOW, False=DENY, None=not observable. Exceptions never reach here."""
    if isinstance(out, enum.Enum):
        n = str(out.name).upper()
        return {"ALLOW": True, "DENY": False}.get(n)
    if isinstance(out, str):
        return {"ALLOW": True, "DENY": False}.get(out.upper())
    if isinstance(out, dict):
        return _is_allow(out.get("decision")) if "decision" in out else None
    dec = getattr(out, "decision", None)
    return _is_allow(dec) if dec is not None else None


def _reasons_of(out: Any) -> tuple:
    rc = getattr(out, "reason_codes", None)
    if rc is None and isinstance(out, dict):
        rc = out.get("reason_codes")
    return tuple(rc) if isinstance(rc, (list, tuple)) else ()


def _runtime_checks_type(mod: Any) -> Optional[type]:
    for v in vars(mod).values():
        if inspect.isclass(v) and CHECK_FIELDS <= set(getattr(v, "__annotations__", {})):
            return v
    return None


def _runtime_policy_map(mod: Any) -> Optional[dict]:
    for v in vars(mod).values():
        if isinstance(v, dict) and v and all(isinstance(k, str) for k in v) and all(
                any(a.startswith("require_") for a in dir(x)) for x in v.values()):
            return v
    return None


def _runtime_decision_enum(mod: Any) -> Optional[type]:
    for v in vars(mod).values():
        if inspect.isclass(v) and issubclass(v, enum.Enum) and v.__module__ == mod.__name__:
            if {"ALLOW", "DENY"} <= set(v.__members__):
                return v
    return None


class _CallRecorder:
    """Run-scoped log of exceptions raised by TARGET code during probe calls.
    Kept independently of the case records so both views can be reconciled
    (a case that swallowed or invented an exception is detectable)."""

    def __init__(self) -> None:
        self.current = "UNSCOPED"              # block being probed
        self.case_exceptions: list[dict] = []  # tagged (case) calls
        self.search_exceptions: dict[str, int] = {}  # untagged (search) calls

    def log(self, tag: Optional[str], exc: BaseException) -> None:
        name = type(exc).__name__
        if tag is None:
            self.search_exceptions[name] = self.search_exceptions.get(name, 0) + 1
        else:
            self.case_exceptions.append({"where": self.current, "case": tag,
                                         "type": name,
                                         "message": str(exc)[:200]})


_REC: Optional[_CallRecorder] = None


def _call(fn: Any, kw: dict, tag: Optional[str] = None) -> tuple[Any, Optional[str]]:
    """tag=None → witness search / stimulus construction; tag=<case> → case call."""
    try:
        return fn(**kw), None
    except Exception as exc:  # exceptions are recorded, never equated with DENY
        if _REC is not None:
            _REC.log(tag, exc)
        return None, type(exc).__name__


def _skip(obs: dict, name: str, reason: str) -> None:
    """Planned case not executed: account for it explicitly (never lost)."""
    obs.setdefault("not_executed", []).append({"case": name, "reason": reason})


def _skip_rest(obs: dict, reason: str) -> None:
    done = Counter(c["case"] for c in obs.get("cases", [])) + \
        Counter(c["case"] for c in obs.get("not_executed", []))
    for name in obs.get("plan", []):
        if done[name] > 0:
            done[name] -= 1
        else:
            _skip(obs, name, reason)


def _vcase(name: str, stimulus: str, exc: Optional[str], result: str,
           falsified: bool, effect: Optional[str] = None,
           kind: str = "DYNAMIC_FALSIFICATION",
           observed: Optional[str] = None) -> dict[str, Any]:
    """Case record for non-decision probes (same keys as _case). `observed`
    is the value actually seen (e.g. ok=True); 'exception' if one was raised."""
    return {"case": name, "stimulus": stimulus,
            "falsified_precondition": falsified, "compromise_verified": True,
            "execution_observed": exc is None, "exception": exc,
            "decision": ("exception" if exc is not None else
                         observed if observed is not None else "NOT_OBSERVABLE"),
            "reason_codes": [],
            "result": result, "observed_effect": effect, "check_kind": kind}


_NO_OK = object()


def _ok_label(out: Any, exc: Optional[str]) -> str:
    """Observed evidence value: 'exception', 'ok=absent' (no evidence field)
    or 'ok=<value>'."""
    if exc is not None:
        return "exception"
    try:
        v = getattr(out, "ok", _NO_OK)
    except Exception:
        return "exception"
    return "ok=absent" if v is _NO_OK else f"ok={v}"


def _case(name: str, kw_desc: str, out: Any, exc: Optional[str],
          falsified: bool, compromise_verified: bool) -> dict[str, Any]:
    allow = None if exc else _is_allow(out)
    rec = {"case": name, "stimulus": kw_desc, "falsified_precondition": falsified,
           "compromise_verified": compromise_verified,
           "execution_observed": exc is None, "exception": exc,
           "decision": {True: "ALLOW", False: "DENY", None: "NOT_OBSERVABLE"}[allow],
           "reason_codes": list(_reasons_of(out)) if exc is None else []}
    if not falsified and exc is None and allow is None:
        # executed, but the output carries no ALLOW/DENY at all: not a defense
        rec["decision"] = "NO_PROTECTED_DECISION"
        rec["result"] = "NOT_A_DEFENSE"
    elif not falsified:
        rec["result"] = "POSITIVE_WITNESS" if allow is True else "NO_WITNESS"
    elif not compromise_verified:
        rec["result"] = "STIMULUS_NOT_ESTABLISHED"
    elif exc is not None:
        rec["result"] = "EXCEPTION_NOT_DENY"
    elif allow is True:
        rec["result"] = "COUNTEREXAMPLE"  # compromise ∧ execution ∧ protected effect
    elif allow is False:
        rec["result"] = "PROTECTED_EFFECT_ABSENT"
    else:
        rec["result"] = "NOT_OBSERVABLE"
    return rec


def _stimulus_gaps(not_executed: Any) -> list:
    """Planned falsifications whose stimulus could not be built/verified."""
    return [n for n in (not_executed or [])
            if n.get("case") != "positive_witness"
            and str(n.get("reason", "")).startswith("STIMULUS_")]


def pass_fail_closed(cases: list[dict], witness: bool, not_executed: Any = ()) -> bool:
    """PASS_FC(f) = PositiveWitness(f) AND FalsificationsExecuted(f)>0 AND
    StimuliVerified(f) AND DecisionsObservable(f) AND Counterexamples(f)==0.
    Role, declared property and SEGURIDAD play no part."""
    fals = [c for c in cases if c["falsified_precondition"]]
    stimuli_verified = (all(c.get("compromise_verified", True)
                            and c["result"] != "STIMULUS_NOT_ESTABLISHED" for c in fals)
                        and not _stimulus_gaps(not_executed))
    observable = all(c["result"] in ("PROTECTED_EFFECT_ABSENT", "COUNTEREXAMPLE")
                     for c in fals)
    ces = sum(c["result"] == "COUNTEREXAMPLE" for c in fals)
    return bool(witness) and len(fals) > 0 and stimuli_verified and observable and ces == 0


def _fold_fail_closed(cases: list[dict], witness: bool, not_executed: Any = ()) -> str:
    fals = [c for c in cases if c["falsified_precondition"]]
    if any(c["result"] == "COUNTEREXAMPLE" for c in fals):
        return "FAIL"
    if pass_fail_closed(cases, witness, not_executed):
        return "PASS"
    if not witness:
        return "NOT_QUALIFIED"  # no positive control → cannot tell DENY-by-design from always-DENY
    # Qualification is binary and explicit: every planned falsification must
    # have a verified stimulus and an observable protected effect.  Failure to
    # establish/observe a planned case is an instrument/campaign qualification
    # problem, never "insufficient evidence" attributed to the target.
    if not fals:
        return "NOT_QUALIFIED"
    if any(c["result"] == "STIMULUS_NOT_ESTABLISHED" for c in fals) \
            or _stimulus_gaps(not_executed):
        return "NOT_QUALIFIED"
    # Qualified campaign executed, but the observed evidence is below the
    # threshold (exception instead of DENY, or decision not observable).
    if any(c["result"] in ("NOT_OBSERVABLE", "EXCEPTION_NOT_DENY") for c in fals):
        return "INSUFFICIENT_EVIDENCE"
    if all(c["result"] == "PROTECTED_EFFECT_ABSENT" for c in fals):
        return "PASS"
    return "NOT_QUALIFIED"


def _witness_kwargs(fn: Any, base: dict) -> tuple[Optional[dict], int]:
    """Find inputs producing ALLOW. Extra required numeric params searched in a
    small bounded domain; optional params left at defaults."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None, 0
    extra = [p for p, v in sig.parameters.items()
             if p not in base and v.default is inspect.Parameter.empty
             and v.kind not in (v.VAR_POSITIONAL, v.VAR_KEYWORD)]
    tries = 0
    if not extra:
        tries = 1
        out, exc = _call(fn, base)
        return (dict(base) if exc is None and _is_allow(out) is True else None), tries
    if len(extra) > 2:
        return None, 0
    import itertools
    for combo in itertools.product(_NUM_DOMAIN, repeat=len(extra)):
        kw = dict(base, **dict(zip(extra, combo)))
        tries += 1
        out, exc = _call(fn, kw)
        if exc is None and _is_allow(out) is True:
            return kw, tries
    return None, tries


def _probe_composite(fn: Any, mod: Any) -> dict[str, Any]:
    obs: dict[str, Any] = {"probe": "COMPOSITE_CHECKS", "cases": [], "not_executed": []}
    # PLAN first (universal vocabulary): every case below is accounted for.
    obs["plan"] = (["positive_witness"] + [f"falsify_{f}" for f in sorted(CHECK_FIELDS)]
                   + ["falsify_missing_policy"])
    Checks, policies = _runtime_checks_type(mod), _runtime_policy_map(mod)
    if Checks is None or policies is None:
        obs["fail_closed"] = "NOT_QUALIFIED"
        obs["notes"] = ["STIMULUS_NOT_ESTABLISHED:checks_or_policy_map_not_found"]
        _skip_rest(obs, obs["notes"][0])
        return obs
    op = sorted(policies)[0]
    good = {f: True for f in CHECK_FIELDS}
    try:
        good_checks = Checks(**good)
    except Exception as exc:
        obs["fail_closed"] = "NOT_QUALIFIED"
        obs["notes"] = [f"STIMULUS_NOT_ESTABLISHED:checks_ctor:{type(exc).__name__}"]
        _skip_rest(obs, obs["notes"][0])
        return obs
    base = {"request_id": "UHCR-REQ", "context_id": "UHCR-CTX",
            "resource_id": "UHCR-RES", "operation": op, "checks": good_checks}
    wkw, tries = _witness_kwargs(fn, base)
    obs["witness_search_tries"] = tries
    out, exc = _call(fn, wkw or base, "positive_witness")
    obs["cases"].append(_case("positive_witness", f"operation={op}; all checks True",
                              out, exc, False, True))
    witness = wkw is not None and obs["cases"][0]["result"] == "POSITIVE_WITNESS"
    kw0 = wkw or base
    for field in sorted(CHECK_FIELDS):
        name = f"falsify_{field}"
        try:
            bad = Checks(**dict(good, **{field: False}))
            verified = getattr(bad, field) is False and getattr(good_checks, field) is True
        except Exception as e:
            _skip(obs, name, f"STIMULUS_CONSTRUCTION_FAILED:{type(e).__name__}")
            continue
        out, exc = _call(fn, dict(kw0, checks=bad), name)
        obs["cases"].append(_case(name, f"{field}=False", out, exc, True, verified))
    # unknown operation (missing policy) — verify it's really absent from the map
    unknown = "UHCR_UNDECLARED_OPERATION"
    out, exc = _call(fn, dict(kw0, operation=unknown), "falsify_missing_policy")
    obs["cases"].append(_case("falsify_missing_policy", f"operation={unknown}",
                              out, exc, True, unknown not in policies))
    if witness:
        obs["witness_kwargs"] = wkw  # lets a DERIVED consumer reuse the ALLOW
    obs["fail_closed"] = _fold_fail_closed(obs["cases"], witness, obs["not_executed"])
    return obs


_BINDING_FIELDS = ("operation", "resource_id", "context_id")


def _probe_postcondition(fn: Any, mod: Any, producer: Any,
                         producer_obs: Optional[dict]) -> dict[str, Any]:
    """Obtain an ALLOW `pre` from the DERIVED producer (preferred) or by
    constructing the carrier; falsify postcondition and bindings."""
    obs: dict[str, Any] = {"probe": "POSTCONDITION", "cases": [], "not_executed": []}
    obs["plan"] = (["positive_witness", "falsify_postcondition"]
                   + [f"falsify_binding_{f}" for f in _BINDING_FIELDS]
                   + ["falsify_pre_not_authorized"])
    pre = None
    ids: dict[str, Any] = {}
    if producer is not None and producer_obs and producer_obs.get("witness_kwargs"):
        out, exc = _call(producer, producer_obs["witness_kwargs"])  # stimulus construction
        if exc is None and _is_allow(out) is True:
            pre = out
            obs["pre_source"] = "PRODUCER_WITNESS"
    if pre is None:
        D = _runtime_decision_enum(mod)
        carrier = None
        for v in vars(mod).values():
            if inspect.isclass(v) and "decision" in getattr(v, "__annotations__", {}) \
                    and hasattr(v, "__dataclass_fields__"):
                carrier = v
                break
        if D is None or carrier is None:
            obs["fail_closed"] = "NOT_QUALIFIED"
            obs["notes"] = ["STIMULUS_NOT_ESTABLISHED:no_pre_available"]
            _skip_rest(obs, obs["notes"][0])
            return obs
        kw = {}
        for f in carrier.__dataclass_fields__:
            kw[f] = (D["ALLOW"] if f == "decision" else
                     f"UHCR-{f.upper()}" if f in ID_PARAMS else
                     () if "reason" in f else None)
        try:
            pre = carrier(**kw)
            obs["pre_source"] = "CONSTRUCTED_CARRIER"
        except Exception as exc:
            obs["fail_closed"] = "NOT_QUALIFIED"
            obs["notes"] = [f"STIMULUS_NOT_ESTABLISHED:carrier_ctor:{type(exc).__name__}"]
            _skip_rest(obs, obs["notes"][0])
            return obs
    for f in _BINDING_FIELDS:
        ids[f] = getattr(pre, f, f"UHCR-{f.upper()}")
    try:
        accepted = set(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        accepted = set(ids) | POSTCONDITION_PARAMS
    base = {k: v for k, v in dict(ids, pre=pre, postcondition_ok=True).items() if k in accepted}
    out, exc = _call(fn, base, "positive_witness")
    obs["cases"].append(_case("positive_witness", "pre=ALLOW; postcondition_ok=True",
                              out, exc, False, True))
    witness = obs["cases"][0]["result"] == "POSITIVE_WITNESS"
    out, exc = _call(fn, dict(base, postcondition_ok=False), "falsify_postcondition")
    obs["cases"].append(_case("falsify_postcondition", "postcondition_ok=False",
                              out, exc, True, True))
    for f in _BINDING_FIELDS:
        name = f"falsify_binding_{f}"
        if f in base:
            out, exc = _call(fn, dict(base, **{f: "UHCR-SUBSTITUTED"}), name)
            obs["cases"].append(_case(name, f"{f} substituted",
                                      out, exc, True, base[f] != "UHCR-SUBSTITUTED"))
        else:
            _skip(obs, name, f"PARAM_NOT_ACCEPTED_BY_TARGET:{f}")
    D = _runtime_decision_enum(mod)
    if D is not None and hasattr(pre, "__dataclass_fields__"):
        try:
            import dataclasses
            denied_pre = dataclasses.replace(pre, decision=D["DENY"])
        except Exception as e:
            _skip(obs, "falsify_pre_not_authorized",
                  f"STIMULUS_CONSTRUCTION_FAILED:{type(e).__name__}")
        else:
            out, exc = _call(fn, dict(base, pre=denied_pre), "falsify_pre_not_authorized")
            obs["cases"].append(_case("falsify_pre_not_authorized", "pre.decision=DENY",
                                      out, exc, True, _is_allow(denied_pre) is False))
    else:
        _skip(obs, "falsify_pre_not_authorized",
              "STIMULUS_NOT_ESTABLISHED:no_runtime_decision_enum_or_pre_not_dataclass")
    obs["fail_closed"] = _fold_fail_closed(obs["cases"], witness, obs["not_executed"])
    return obs


def _probe_decision_generic(fn: Any) -> dict[str, Any]:
    """FAIL_CLOSED positive-control search for a callable without a recognised
    precondition shape. A witness shows the protected effect (ALLOW) is
    observable, but no falsifiable condition is known → never PASS."""
    obs: dict[str, Any] = {"probe": "GENERIC_POSITIVE_CONTROL", "cases": [],
                           "not_executed": [],
                           "plan": ["positive_witness", "falsify_discovered_condition"]}
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        obs.update(fail_closed="NOT_QUALIFIED", notes=["NO_SIGNATURE"])
        _skip_rest(obs, "STIMULUS_NOT_ESTABLISHED:no_signature")
        return obs
    base = {p: f"UHCR-{p.upper()}" for p in sig.parameters if p in ID_PARAMS}
    extra = [p for p, v in sig.parameters.items()
             if p not in base and v.default is inspect.Parameter.empty
             and v.kind not in (v.VAR_POSITIONAL, v.VAR_KEYWORD)]
    wkw, tries = _witness_kwargs(fn, base)
    obs["witness_search_tries"] = tries
    if wkw is not None or not extra:
        out, exc = _call(fn, wkw or base, "positive_witness")
        obs["cases"].append(_case("positive_witness", f"inputs={sorted(wkw or base)}",
                                  out, exc, False, True))
    else:
        import itertools
        run = None
        if len(extra) <= 2:
            for combo in itertools.product(_NUM_DOMAIN, repeat=len(extra)):
                kw = dict(base, **dict(zip(extra, combo)))
                _o, _e = _call(fn, kw)  # search: first input that executes at all
                if _e is None:
                    run = kw
                    break
        if run is not None:
            out, exc = _call(fn, run, "positive_witness")
            obs["cases"].append(_case("positive_witness", f"inputs={sorted(run)}",
                                      out, exc, False, True))
        else:
            _skip(obs, "positive_witness",
                  f"STIMULUS_NOT_ESTABLISHED:no_valid_execution_found({tries} tries)")
    _skip(obs, "falsify_discovered_condition",
          "NO_FALSIFIABLE_CONDITION_DISCOVERED:signature exposes no precondition carrier")
    obs["fail_closed"] = "NOT_QUALIFIED"
    return obs


def _capability_measurement(prop: str, blk: dict, decl: dict) -> dict[str, Any]:
    """Stage (b)+(c) for one capability/property, from executed cases only."""
    cases = blk.get("cases") or []
    fals = [k for k in cases if k.get("falsified_precondition")]
    witness = sum(1 for k in cases if not k.get("falsified_precondition")
                  and k.get("result") == "POSITIVE_WITNESS")
    ces = sum(1 for k in cases if k.get("result") == "COUNTEREXAMPLE")
    n_fals = (int(blk.get("falsifications_executed") or 0) if "falsifications_executed" in blk
              else sum(1 for k in fals if k.get("result") != "STIMULUS_NOT_ESTABLISHED"))
    verdict = blk.get("verdict", "NOT_QUALIFIED")
    not_defense = (not witness and not ces
                   and any(k.get("result") == "NOT_A_DEFENSE" for k in cases))
    if verdict == "NOT_RESOLVED":
        status, basis = "NOT_RESOLVED", "CAPABILITY_NOT_RESOLVED"
    elif not_defense:
        # executed, no protected decision at all → not a defense: out of scope
        status, basis, verdict = "OUT_OF_SCOPE", "NO_PROTECTED_DECISION", "NOT_APPLICABLE"
    elif witness and n_fals > 0:
        status, basis = "ESTABLISHED", "PROTECTED_EFFECT_OBSERVED"
    elif ces and n_fals > 0:
        status, basis = "ESTABLISHED", "PROTECTED_EFFECT_OBSERVED_UNDER_FALSIFICATION"
    elif witness:
        status, basis = "NOT_ESTABLISHED", "POSITIVE_WITNESS_WITHOUT_FALSIFIABLE_CONDITION"
    else:
        status, basis = "NOT_ESTABLISHED", "NO_VALID_POSITIVE_CONTROL"
    in_domain = bool(witness or ces)
    if not in_domain and verdict not in ("NOT_RESOLVED", "NOT_APPLICABLE"):
        verdict = "NOT_QUALIFIED"  # auditor not qualified for this capability
    return {"property": prop, "applicability": status, "basis": basis,
            "in_tested_domain": in_domain,
            "campaign": blk.get("probe") or "NONE",
            "campaigns_attempted": int("plan" in blk),
            "campaigns_executed": int(bool(cases)),
            "positive_controls_valid": witness,
            "falsifications_executed": n_fals,
            "counterexamples": ces, "verdict": verdict,
            "declared_protected_effect_trace": decl.get("protected_effect")}


def _probe_verifier(fn: Any) -> dict[str, Any]:
    """Light INTEGRITY probe: determinism + context binding of the evidence.
    Not a fail-closed campaign. Unable to establish → NOT_QUALIFIED."""
    obs: dict[str, Any] = {"probe": "INTEGRITY_LIGHT", "cases": [], "not_executed": [],
                           "plan": ["positive_witness", "determinism_repeat",
                                    "falsify_context_binding"]}
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        obs.update(integrity="NOT_QUALIFIED", notes=["NO_SIGNATURE"])
        _skip_rest(obs, "NO_SIGNATURE")
        return obs
    base = {p: f"UHCR-{p.upper()}" for p in sig.parameters if p in ID_PARAMS}
    extra = [p for p, v in sig.parameters.items()
             if p not in base and v.default is inspect.Parameter.empty]
    if len(extra) > 2:
        obs.update(integrity="NOT_QUALIFIED", notes=["STIMULUS_NOT_ESTABLISHED"])
        _skip_rest(obs, "STIMULUS_NOT_ESTABLISHED:more_than_2_required_params")
        return obs
    import itertools
    good = None
    tries = 0
    seen: set[str] = set()
    for combo in itertools.product(_NUM_DOMAIN, repeat=len(extra)):
        kw = dict(base, **dict(zip(extra, combo)))
        tries += 1
        out, exc = _call(fn, kw)  # witness search
        seen.add(_ok_label(out, exc))
        if exc is None and getattr(out, "ok", None) is True:
            good = (kw, out)
            break
        if not extra:
            break
    obs["witness_search_tries"] = tries
    if good is None and seen == {"ok=absent"}:
        obs["cases"].append(_vcase("positive_witness",
                                   f"bounded search over {len(extra)} param(s), {tries} tries",
                                   None, "NOT_A_DEFENSE", False,
                                   "output has no ok/evidence field", observed="ok=absent"))
        obs.update(integrity="NOT_APPLICABLE", notes=["NOT_A_DEFENSE:no_evidence_field"])
        _skip_rest(obs, "NOT_A_DEFENSE:out_of_scope")
        return obs
    if good is None:
        obs["cases"].append(_vcase("positive_witness",
                                   f"bounded search over {len(extra)} param(s), {tries} tries",
                                   None, "NO_WITNESS", False, "no output with ok=True",
                                   observed=",".join(sorted(seen)) or "not executed"))
        obs.update(integrity="NOT_QUALIFIED", notes=["NO_OK_EVIDENCE_WITNESS"])
        _skip_rest(obs, "NO_OK_EVIDENCE_WITNESS")
        return obs
    kw, out1 = good
    obs["cases"].append(_vcase("positive_witness", f"inputs={sorted(kw)}", None,
                               "POSITIVE_WITNESS", False, "ok=True evidence produced",
                               observed=_ok_label(out1, None)))
    out2, exc2 = _call(fn, kw, "determinism_repeat")
    def fp(o: Any) -> str:
        pd = getattr(o, "public_dict", None)
        v = pd() if callable(pd) else repr(o)
        return hashlib.sha256(json.dumps(v, sort_keys=True, default=str).encode()).hexdigest()
    deterministic = None if exc2 else fp(out1) == fp(out2)
    obs["deterministic"] = deterministic
    obs["cases"].append(_vcase(
        "determinism_repeat", "identical inputs repeated", exc2,
        "EXCEPTION_NOT_DENY" if exc2 else
        "DETERMINISTIC" if deterministic else "COUNTEREXAMPLE", True,
        None if deterministic is not False else
        "evidence fingerprint differs across identical calls",
        observed=_ok_label(out2, exc2)))
    binding = None
    if base:
        k = sorted(base)[0]
        out3, exc3 = _call(fn, dict(kw, **{k: "UHCR-OTHER"}), "falsify_context_binding")
        binding = None if exc3 else fp(out3) != fp(out1)
        obs["binding_mutated_field"] = k
        obs["falsifications_executed"] = 1
        obs["cases"].append(_vcase(
            "falsify_context_binding", f"{k} mutated", exc3,
            "EXCEPTION_NOT_DENY" if exc3 else
            "BINDING_HOLDS" if binding else "COUNTEREXAMPLE", True,
            None if binding is not False else
            "evidence unchanged after context mutation",
            observed=_ok_label(out3, exc3)))
    else:
        _skip(obs, "falsify_context_binding", "NO_ID_PARAM_TO_MUTATE")
    obs["context_binding"] = binding
    # tampered inputs: perturb one numeric input's companion claim if any optional numeric exists
    if deterministic is False:
        obs["integrity"] = "FAIL"
    elif binding is False:
        obs["integrity"] = "FAIL"
    elif not base:
        obs["integrity"] = "NOT_QUALIFIED"
    elif deterministic is None or binding is None:
        obs["integrity"] = "INSUFFICIENT_EVIDENCE"  # executed; exception observed
    else:
        obs["integrity"] = "PASS"
    return obs


def _probe_state_machine(mod: Any, names: list[str]) -> dict[str, Any]:
    """STATE_TRANSITION: terminal states closed + disallowed transition rejected
    by any class exposing a `transition` method over that state space.
    (Rejection by exception is accepted here as in 1.0; recorded as observation.)"""
    obs: dict[str, Any] = {"maps": names, "cases": [], "not_executed": [],
                           "plan": ["falsify_illegal_transition"]}
    for n in names:
        m = getattr(mod, n, None)
        if not isinstance(m, dict) or not m:
            continue
        states = set(m)
        for v in m.values():
            try:
                states |= set(v)
            except TypeError:
                pass
        missing = sorted(str(s) for s in states if s not in m)
        obs["unmapped_states"] = missing
        for cls in vars(mod).values():
            if not (inspect.isclass(cls) and callable(getattr(cls, "transition", None))):
                continue
            try:
                inst = cls()
            except Exception as e:
                if _REC is not None:
                    _REC.log(None, e)
                continue
            cur = next((getattr(inst, a) for a in vars(inst) if getattr(inst, a) in m), None)
            if cur is None:
                continue
            illegal = next((s for s in sorted(states, key=str) if s not in m[cur] and s != cur), None)
            if illegal is None:
                continue
            obs["falsifications_executed"] = 1
            stim = f"{getattr(cur, 'name', cur)}->{getattr(illegal, 'name', illegal)}"
            try:
                inst.transition(illegal)
                obs.update(state_transition="FAIL",
                           counterexample=f"{cur}->{illegal} accepted")
                obs["cases"].append(_vcase("falsify_illegal_transition", stim, None,
                                           "COUNTEREXAMPLE", True,
                                           "illegal transition accepted"))
                return obs
            except Exception as exc:
                if _REC is not None:
                    _REC.log("falsify_illegal_transition", exc)
                after = next((getattr(inst, a) for a in vars(inst)
                              if getattr(inst, a) in m), None)
                ok = after == cur
                obs.update(state_transition="PASS" if ok and not missing else
                           ("FAIL" if not ok else "INSUFFICIENT_EVIDENCE"),
                           rejected=stim,
                           rejection=type(exc).__name__)
                obs["cases"].append(_vcase(
                    "falsify_illegal_transition", stim, type(exc).__name__,
                    "REJECTED_STATE_PRESERVED" if ok else "COUNTEREXAMPLE", True,
                    None if ok else "state changed although transition was rejected"))
                return obs
    obs["state_transition"] = "NOT_QUALIFIED"
    obs["falsifications_executed"] = 0
    _skip_rest(obs, "NO_INSTANTIABLE_TRANSITION_CLASS_WITH_MAPPED_STATE")
    return obs


# ===========================================================================
# Declared plane
# ===========================================================================

def _declared(seg: dict[str, Any], cap: str) -> dict[str, Any]:
    """Return the semantic contract DECLARED by SEGURIDAD for ``cap``.

    This is the authoritative semantic plane.  The auditor may derive an
    independent structural hypothesis from AST, but that hypothesis MUST NOT
    replace or manufacture target semantics.

    Accepted declaration containers (Spanish/English, same meaning):
      semantica / semantic / semanticas / semantics
      protecciones / protege / protections

    A capability entry may declare:
      rol|role, propiedad|property, propiedades|properties,
      activo|asset, efecto|effect|protected_effect,
      politica_fallo|failure_policy, forma|shape.
    """
    containers = ("semantica", "semantic", "semanticas", "semantics",
                  "protecciones", "protege", "protections")
    item = None
    for key in containers:
        block = seg.get(key)
        if isinstance(block, dict):
            candidate = block.get(cap)
            if isinstance(candidate, dict):
                item = candidate; break
        elif isinstance(block, list):
            candidate = next((x for x in block if isinstance(x, dict) and
                              cap in (x.get("capacidad"), x.get("capability"),
                                      x.get("name"), x.get("nombre"))), None)
            if isinstance(candidate, dict):
                item = candidate; break
    if not isinstance(item, dict):
        return {}

    aliases = {
        "rol": "role", "role": "role",
        "propiedad": "property", "property": "property",
        "propiedades": "properties", "properties": "properties",
        "activo": "asset", "asset": "asset",
        "efecto": "protected_effect", "effect": "protected_effect",
        "protected_effect": "protected_effect",
        "politica_fallo": "failure_policy", "failure_policy": "failure_policy",
        "forma": "shape", "shape": "shape",
    }
    out: dict[str, Any] = {}
    for src, dst in aliases.items():
        if src in item:
            out[dst] = item[src]
    props = out.get("properties")
    if isinstance(props, str):
        props = [props]
    if isinstance(props, (list, tuple, set)):
        out["properties"] = [str(x).upper() for x in props]
        if "property" not in out and len(out["properties"]) == 1:
            out["property"] = out["properties"][0]
    if out.get("property") is not None:
        out["property"] = str(out["property"]).upper()
    if out.get("role") is not None:
        out["role"] = str(out["role"]).upper()
    return out


def _semantic_authority(declared: dict[str, Any], derived: dict[str, Any]) -> dict[str, Any]:
    """Build the effective semantic contract.

    DECLARED semantics are authoritative. DERIVED semantics are retained only
    as an independent consistency measurement.  No declaration => no invented
    semantic role/property.
    """
    if not declared:
        return {
            "role": "UNKNOWN", "property": "NOT_RESOLVED",
            "confidence": "NOT_RESOLVED", "asset": None,
            "protected_effect": None, "failure_policy": None, "shape": None,
            "reason": "DECLARED_SEMANTICS_MISSING",
        }
    role = str(declared.get("role") or "UNKNOWN").upper()
    prop = declared.get("property")
    props = declared.get("properties") or ([] if prop is None else [prop])
    props = [str(x).upper() for x in props]
    if prop is None and len(props) == 1:
        prop = props[0]
    prop = str(prop).upper() if prop is not None else "NOT_RESOLVED"
    return {
        "role": role if role in ROLES else "UNKNOWN",
        "property": prop,
        "properties": props,
        "confidence": "DECLARED" if role in ROLES and prop != "NOT_RESOLVED" else "NOT_RESOLVED",
        "asset": declared.get("asset"),
        "protected_effect": declared.get("protected_effect"),
        "failure_policy": declared.get("failure_policy"),
        "shape": declared.get("shape") or derived.get("shape"),
        "reason": None if role in ROLES and prop != "NOT_RESOLVED" else "DECLARED_SEMANTICS_INCOMPLETE",
    }

def _alignment(declared: dict, derived: dict, observed: dict) -> str:
    role = derived.get("role")
    if role == "UNKNOWN":
        return "SEMANTIC_NOT_RESOLVED"
    if declared.get("role"):
        return ("CONVERGENT_SEMANTIC_EVIDENCE"
                if str(declared["role"]).upper() == role else "SEMANTIC_DIVERGENCE")
    # No declared role: converge only if observation corroborates derivation.
    cases = observed.get("cases") or []
    if role == "ENFORCEMENT_GATE" and any(c["decision"] in ("ALLOW", "DENY") for c in cases):
        return "CONVERGENT_SEMANTIC_EVIDENCE"
    if role == "VERIFIER" and observed.get("integrity") in ("PASS", "FAIL"):
        return "CONVERGENT_SEMANTIC_EVIDENCE"
    return "SEMANTIC_NOT_RESOLVED"


# ===========================================================================
# Public API
# ===========================================================================

def _empty_verdict(reason: str) -> dict[str, str]:
    # No semantic/applicability evidence means NOT_RESOLVED.  This is not a
    # target failure and not a measured "insufficient evidence" result.
    return {"FAIL_CLOSED": "NOT_RESOLVED", "INTEGRITY": "NOT_RESOLVED",
            "STATE_TRANSITION": "NOT_RESOLVED",
            "OBSERVABILITY": "NOT_RESOLVED",
            "DECLARATION_TRACEABILITY": "NOT_RESOLVED",
            "PROVENANCE": "NOT_RESOLVED",  # compat key: see PROVENANCE_COMPAT_NOTE
            "OVERALL_RESOURCE_EVALUATION": reason}


def _empty_ledger() -> dict[str, dict]:
    """Zero-evidence ledger (every base property, nothing executed)."""
    return {p: {"applicability": "NOT_RESOLVED", "basis": ["NO_CAPABILITY_ENUMERABLE"],
                "capabilities_applicable": 0, "campaigns_executed": 0,
                "positive_controls_valid": 0, "falsifications_executed": 0,
                "counterexamples": 0, "evidence_kind": "NONE"} for p in PROPERTIES_BASE}


def _resolve_root(target: str | Path, root: Path | None) -> tuple[Path, str]:
    """Discover the tree root that contains TARGET (no fixed layout assumed).
    Order: explicit root, UHCR_ROOT env, ancestors of this motor's folder,
    then the current working directory and its ancestors. The first
    candidate under which TARGET exists wins; otherwise the first candidate
    is kept and the target is reported ABSENT (never guessed)."""
    import os
    if root is not None:
        return Path(root).resolve(), "EXPLICIT"
    env = os.environ.get("UHCR_ROOT")
    if env:
        return Path(env).resolve(), "ENV_UHCR_ROOT"
    if Path(target).is_absolute():
        return ROOT, "TARGET_ABSOLUTE"
    cands: list[tuple[Path, str]] = []
    for base, tag in ((ROOT, "MOTOR_ANCESTOR"), (Path.cwd().resolve(), "CWD_ANCESTOR")):
        for anc in (base, *base.parents):
            if all(anc != c for c, _ in cands):
                cands.append((anc, tag))
    for cand, tag in cands:
        if (cand / target).is_file():
            return cand, tag
    return ROOT, "NOT_RESOLVED"


def _audit_core(target: str | Path, root: Path | None, exp: dict) -> None:
    """Pipeline body; fills `exp` in place so a crash never loses what was
    already measured (audit_resource guards it)."""
    root, root_source = _resolve_root(target, root)
    path = Path(target) if Path(target).is_absolute() else (root / target)
    mod_name = _module_name(path, root)
    exp.update({
        "audit_scope": "ISOLATED_RESOURCE",
        "root": str(root),
        "root_source": root_source,
        "system_perimeter_bypassed_for_measurement": "YES",
        "system_perimeter_bypass_meaning": (
            "measurement isolation only: target loaded directly with ROOT on "
            "sys.path; no production perimeter was disabled"),
        "system_wide_claim": "NO",
        "target_file": Path(target).as_posix(),
        "target_module": mod_name,
        "declaration_id": None,
        "declared_security": False,
        "status": "OK",
        "import_status": None,
        "capabilities": [],
        "undeclared_gate_candidates": [],
        "ast_inventory": {},
        "verdict": {},
        "declared_capabilities": [],
        "target_path_resolved": str(path),
    })
    if not path.is_file():
        exp["status"] = "ABSENT"
        exp["verdict"] = _empty_verdict("TARGET_ABSENT: no evidence obtainable")
        exp["property_evidence"] = _empty_ledger()
        return
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except Exception as exc:
        exp["status"] = "PARSE_FAILED"
        exp["verdict"] = _empty_verdict(f"PARSE_FAILED:{type(exc).__name__}")
        exp["property_evidence"] = _empty_ledger()
        return

    # ---- Step B: SEGURIDAD (AST first, runtime enrichment) ----
    seg = _extract_seguridad_ast(tree)
    seg_source = "AST_LITERAL" if seg else None
    mod, err = _import_isolated(path, root, mod_name)
    exp["import_status"] = "IMPORTED" if mod is not None else err
    if mod is None:
        exp["status"] = "IMPORT_FAILED"  # AST inventory still published below
    elif isinstance(getattr(mod, "SEGURIDAD", None), dict):
        for k, v in mod.SEGURIDAD.items():
            if k not in seg or (isinstance(seg[k], str) and seg[k].startswith("<ref:")):
                seg[k] = v
        seg_source = seg_source or "RUNTIME"
    key = seg.get("clave_declaracion", "capacidades_recurso")
    caps = seg.get(key) if isinstance(seg.get(key), (list, tuple)) else \
        seg.get("capacidades_recurso", [])
    caps = [str(c) for c in caps] if isinstance(caps, (list, tuple)) else []
    exp["declared_capabilities"] = list(caps)
    exp["declaration_id"] = seg.get("id")
    exp["declared_security"] = bool(seg)
    exp["seguridad_source"] = seg_source
    exp["declaration_key"] = key
    conceptos = seg.get("conceptos") if isinstance(seg.get("conceptos"), list) else []

    inv = _Inventory(tree)
    exp["ast_inventory"] = inv.public()
    # SEGURIDAD is traceability, not a gate: with no declared capability list
    # the public module-level functions are enumerated and searched anyway.
    exp["capability_source"] = "DECLARED" if caps else "DISCOVERED_PUBLIC_FUNCTIONS"
    if not caps:
        caps = sorted(n for n in inv.functions if not n.startswith("_"))
    exp["audited_capabilities"] = list(caps)

    # ---- Stage (a): semantic description (descriptive metadata only) ----
    # Independent structural hypothesis (never authoritative).
    derived = {c: _derive(inv.functions.get(c), inv, conceptos, frozenset(caps))
               for c in caps}
    declared_semantics = {c: _declared(seg, c) for c in caps}
    effective = {c: _semantic_authority(declared_semantics[c], derived[c]) for c in caps}
    # Producer link (structural, role-independent, deterministic): consumer
    # param `pre: X` ↔ another capability returning X; candidates exposing a
    # precondition-carrier signature first, then by name.
    for c, d in derived.items():
        pre_t = (d.get("param_annotations") or {}).get("pre")
        if not pre_t:
            continue
        cands = sorted((o for o, od in derived.items()
                        if o != c and od.get("return_annotation") == pre_t),
                       key=lambda o: (derived[o].get("shape") != "COMPOSITE_CHECKS", o))
        if cands:
            d["producer"], d["producer_confidence"] = cands[0], "DERIVED"
    # Undeclared structural gate candidates (descriptive only, reported not audited).
    for name, fn in inv.functions.items():
        if name.startswith("_") or name in derived or name in inv.deny_helpers:
            continue
        if _derive(fn, inv, conceptos)["role"] == "ENFORCEMENT_GATE":
            exp["undeclared_gate_candidates"].append(name)

    # ---- Stage (c): measurement — every capability, every measured property ----
    # Campaign machinery is selected by runtime signature shape only; role,
    # declared property and SEGURIDAD never decide whether we look.
    order = sorted(caps, key=lambda c: 1 if derived[c].get("producer") else 0)
    symbols = _module_symbols(inv)
    campaigns: dict[str, dict[str, dict]] = {c: {} for c in caps}
    for c in order:
        d = derived[c]
        fn_rt = getattr(mod, c, None) if mod is not None else None
        for prop in MEASURED_PROPERTIES:
            if _REC is not None:
                _REC.current = f"capability:{c}#{prop}"
            if c not in symbols:
                blk: dict[str, Any] = {"verdict": "NOT_RESOLVED",
                                       "notes": ["CAPABILITY_NOT_RESOLVED:no module-level symbol"]}
            elif not callable(fn_rt):
                blk = {"verdict": "NOT_QUALIFIED",
                       "notes": ["NOT_EXECUTABLE:" + str(exp["import_status"])]}
            elif prop == "FAIL_CLOSED":
                if d.get("shape") == "COMPOSITE_CHECKS":
                    blk = _probe_composite(fn_rt, mod)
                elif d.get("shape") == "POSTCONDITION":
                    p = d.get("producer")
                    blk = _probe_postcondition(
                        fn_rt, mod, getattr(mod, p, None) if p else None,
                        campaigns.get(p, {}).get("FAIL_CLOSED") if p else None)
                else:
                    blk = _probe_decision_generic(fn_rt)
                blk["verdict"] = blk.get("fail_closed", "NOT_QUALIFIED")
            else:
                blk = _probe_verifier(fn_rt)
                blk["verdict"] = blk.get("integrity", "NOT_QUALIFIED")
            blk["property"] = prop
            blk["campaign_shape"] = d.get("shape") or "GENERIC"
            campaigns[c][prop] = blk

    # ---- Stage (b): applicability, from measurement only ----
    for c in caps:
        d, sem, camp = derived[c], effective[c], campaigns[c]
        decl = declared_semantics[c]
        meas = {p: _capability_measurement(p, camp[p], decl) for p in MEASURED_PROPERTIES}
        conf_fields = {f: ("DECLARED" if decl.get(f) is not None else "NOT_RESOLVED")
                       for f in ("role", "asset", "protected_effect", "property")}
        if meas["FAIL_CLOSED"]["in_tested_domain"]:
            conf_fields["protected_effect"] = "OBSERVED"
        if d.get("producer"):
            conf_fields["producer"] = d["producer_confidence"]
        pub = {p: {k: v for k, v in b.items() if k != "witness_kwargs"}
               for p, b in camp.items()}
        exp["capabilities"].append({
            "capability": c,
            # -- descriptive plane (explanatory metadata, feeds nothing below) --
            "role": sem["role"],
            "confidence": sem["confidence"],
            "confidence_fields": conf_fields,
            "property": sem.get("property") or "NOT_RESOLVED",
            "asset": sem.get("asset"),
            "shape": sem.get("shape"),
            "failure_policy": sem.get("failure_policy"),
            "protected_effect": sem.get("protected_effect"),
            "producer": d.get("producer"),
            "signals": d.get("signals"),
            "scores": d.get("scores"),
            "declared": decl,
            "derived": {k: d.get(k) for k in ("role", "asset", "protected_effect",
                                               "failure_policy", "shape", "confidence")},
            "semantic_alignment": _alignment(decl, d, {
                "cases": camp["FAIL_CLOSED"].get("cases") or [],
                "integrity": camp["INTEGRITY"].get("verdict")}),
            "reason": sem.get("reason"),
            # -- applicability / measurement / verdict planes --
            "applicability": {p: {"status": m["applicability"], "basis": m["basis"]}
                              for p, m in meas.items()},
            "fail_closed_applicability": meas["FAIL_CLOSED"]["applicability"],
            "measurement": meas,
            "campaigns": pub,
            "fail_closed": meas["FAIL_CLOSED"]["verdict"],
            "integrity": meas["INTEGRITY"]["verdict"],
        })

    # ---- STATE_TRANSITION (only if a transition map exists) ----
    if inv.transition_maps:
        if _REC is not None:
            _REC.current = "state_machine"
        if mod is not None:
            exp["state_machine"] = _probe_state_machine(mod, inv.transition_maps)
        else:
            exp["state_machine"] = {"state_transition": "NOT_QUALIFIED",
                                    "maps": list(inv.transition_maps),
                                    "plan": ["falsify_illegal_transition"],
                                    "cases": [], "not_executed": []}
            _skip_rest(exp["state_machine"], "NOT_EXECUTABLE:" + str(exp["import_status"]))
    exp["verdict"] = _verdict(exp, caps, inv)
    return

def audit_resource(target: str | Path, *, root: Path | None = None,
                   _calibrate: bool = True) -> dict:
    """Isolated resource audit. target = relative path like
    'modules/<package>/<resource>.py' (resolved under root, default ROOT).
    Always returns an expediente with 'accounting' and 'audit_record'.
    Exceptions raised by the auditor itself are captured as
    instrument_exceptions (origin AUDITOR_INTERNAL) → AUDITOR_QUALIFICATION=FAIL."""
    global _REC
    prev, _REC = _REC, _CallRecorder()
    exp: dict[str, Any] = {"instrument_exceptions": []}
    try:
        try:
            _audit_core(target, root, exp)
        except Exception as exc:
            tb = traceback.extract_tb(exc.__traceback__)
            last = tb[-1] if tb else None
            exp["instrument_exceptions"].append({
                "origin": "AUDITOR_INTERNAL", "type": type(exc).__name__,
                "where": (f"{Path(last.filename).name}:{last.name}:{last.lineno}"
                          if last else "unknown"),
                "message": str(exc)[:300]})
            exp.setdefault("target_file", Path(target).as_posix())
            exp.setdefault("status", "OK")
            exp["verdict"] = _empty_verdict(
                f"INSTRUMENT_EXCEPTION:{type(exc).__name__}: measurement incomplete")
            exp["property_evidence"] = _empty_ledger()
        exp["target_exception_log"] = {
            "case_calls": list(_REC.case_exceptions),
            "search_calls": dict(sorted(_REC.search_exceptions.items()))}
        # Qualification is symmetric: the instrument must reject a known
        # fail-open control AND approve a known fail-closed control.  This is
        # measured for every real audit; calibration audits disable recursion.
        if _calibrate:
            exp["require_calibration"] = True
            exp["auditor_controls"] = _calibrate_fail_closed_instrument()
        _finalize(exp)
    finally:
        _REC = prev
    return exp


def _agg(values: list[str]) -> str:
    if not values:
        return "NOT_APPLICABLE"
    if "FAIL" in values:
        return "FAIL"
    if all(v == "PASS" for v in values):
        return "PASS"
    if "NOT_QUALIFIED" in values:
        return "NOT_QUALIFIED"
    if "NOT_RESOLVED" in values:
        return "NOT_RESOLVED"
    # INSUFFICIENT_EVIDENCE only arrives from a qualified campaign whose
    # executed evidence fell below threshold (never a generic fallback).
    if "INSUFFICIENT_EVIDENCE" in values:
        return "INSUFFICIENT_EVIDENCE"
    return "NOT_QUALIFIED"


def _enforce_evidence_rule(results: dict[str, str],
                           ledger: dict[str, dict]) -> dict[str, str]:
    """REPORT = f(EVIDENCE): a property with zero executed falsifications can
    never be PASS (or FAIL). Demote to NOT_QUALIFIED (applicable, unmeasured)."""
    out = dict(results)
    for prop, val in results.items():
        n = (ledger.get(prop) or {}).get("falsifications_executed", 0)
        if val in ("PASS", "FAIL") and n <= 0:
            out[prop] = "NOT_QUALIFIED"
    return out


def _module_symbols(inv: _Inventory) -> set[str]:
    return set(inv.functions) | {n.name for n in inv.tree.body
                                 if isinstance(n, ast.ClassDef)} | {
        t.id for n in inv.tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
        for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
        if isinstance(t, ast.Name)}


def _declaration_traceability(exp: dict, caps: list[str], inv: _Inventory) -> str:
    """STATIC_CROSSCHECK: each declared capability name is looked up among the
    module-level AST symbols. A missing name is a counterexample (the check can
    fail). Measures declaration↔code trace only — NOT authentic provenance."""
    names = _module_symbols(inv)
    blk: dict[str, Any] = {"evidence_kind": "STATIC_CROSSCHECK",
                           "plan": [f"crosscheck:{c}" for c in caps],
                           "cases": [], "not_executed": []}
    for c in caps:
        found = c in names
        rec = _vcase(
            f"crosscheck:{c}", f"declared name '{c}' looked up in module-level AST symbols",
            None, "SYMBOL_PRESENT" if found else "COUNTEREXAMPLE", True,
            None if found else "declared capability has no module-level symbol",
            kind="STATIC_CROSSCHECK")
        rec["capability"] = c
        blk["cases"].append(rec)
    blk["checks_executed"] = len(blk["cases"])
    exp["declaration_traceability"] = blk
    if not exp["declared_security"] or not caps:
        return "NOT_RESOLVED"
    return ("FAIL" if any(k["result"] == "COUNTEREXAMPLE" for k in blk["cases"])
            else "PASS")


def _verdict(exp: dict, caps: list[str], inv: _Inventory) -> dict[str, str]:
    recs = exp["capabilities"]
    trace = _declaration_traceability(exp, list(exp.get("declared_capabilities") or []), inv)
    if not recs:
        why = ("NO_SEGURIDAD_DECLARED" if not exp["declared_security"]
               else "NO_DECLARED_CAPABILITIES_RESOLVED")
        v = _empty_verdict(f"{why}: no capability inventory; nothing classified; "
                           f"undeclared_gate_candidates={exp['undeclared_gate_candidates']}; "
                           "scope=ISOLATED_RESOURCE; SYSTEM_WIDE_CLAIM=NO")
        exp["property_evidence"] = _empty_ledger()
        if not inv.transition_maps:
            v["STATE_TRANSITION"] = "NOT_APPLICABLE"
            exp["property_evidence"]["STATE_TRANSITION"].update(
                applicability="NOT_APPLICABLE", basis=["NO_TRANSITION_MAP_DISCOVERED"])
        exp["provenance_note"] = PROVENANCE_COMPAT_NOTE
        return v
    # ---- Stage (d): verdict from measurement only (no role anywhere) ----
    def _measured(prop: str) -> tuple[str, dict]:
        ms = [r["measurement"][prop] for r in recs]
        domain = [m for m in ms if m["in_tested_domain"]]
        resolved = [m for m in ms if m["applicability"] not in ("NOT_RESOLVED", "OUT_OF_SCOPE")]
        oos = [m for m in ms if m["applicability"] == "OUT_OF_SCOPE"]
        est = [m for m in ms if m["applicability"] == "ESTABLISHED"]
        if domain:
            v = _agg([m["verdict"] for m in domain])
        elif resolved:
            v = "NOT_QUALIFIED"  # a defense in scope yielded no valid positive control
        elif oos:
            v = "NOT_APPLICABLE"  # zero defenses in scope in this target
        else:
            v = "NOT_RESOLVED"   # no capability could even be resolved
        app = ("ESTABLISHED" if est else "NOT_ESTABLISHED" if resolved
               else "NOT_APPLICABLE" if oos else "NOT_RESOLVED")
        led = {"applicability": app,
               "basis": (["NO_PROTECTED_DECISION_IN_TARGET"] if app == "NOT_APPLICABLE"
                         else sorted({m["basis"] for m in (est or resolved or ms)})),
               "capabilities_total": len(ms),
               "capabilities_applicable": len(est),
               "capabilities_in_tested_domain": len(domain),
               "capabilities_not_established": sum(m["applicability"] == "NOT_ESTABLISHED" for m in ms),
               "capabilities_not_applicable": sum(m["applicability"] == "NOT_APPLICABLE" for m in ms),
               "capabilities_not_resolved": sum(m["applicability"] == "NOT_RESOLVED" for m in ms),
               "capabilities_out_of_scope": len(oos),
               "capabilities_not_qualified": sum(m["verdict"] == "NOT_QUALIFIED" for m in ms),
               "campaigns_attempted": sum(m["campaigns_attempted"] for m in ms),
               "campaigns_executed": sum(m["campaigns_executed"] for m in ms),
               "positive_controls_valid": sum(m["positive_controls_valid"] for m in ms),
               # falsifications that count toward the verdict (tested domain)
               "falsifications_executed": sum(m["falsifications_executed"] for m in domain),
               "falsifications_executed_outside_domain": sum(
                   m["falsifications_executed"] for m in ms if not m["in_tested_domain"]),
               "counterexamples": sum(m["counterexamples"] for m in ms),
               "evidence_kind": "DYNAMIC_FALSIFICATION"}
        return v, led

    fc, fc_led = _measured("FAIL_CLOSED")
    integ, integ_led = _measured("INTEGRITY")
    st = (exp.get("state_machine", {}).get("state_transition", "NOT_QUALIFIED")
          if inv.transition_maps else "NOT_APPLICABLE")

    def _other(app: str, basis: str, campaigns: int, fals: int, kind: str, **kw: Any) -> dict:
        d = {"applicability": app, "basis": [basis], "capabilities_applicable": 0,
             "campaigns_executed": campaigns, "positive_controls_valid": 0,
             "falsifications_executed": fals, "counterexamples": 0, "evidence_kind": kind}
        d.update(kw)
        return d
    smb = exp.get("state_machine", {})
    dtb = exp["declaration_traceability"]
    ledger = {
        "FAIL_CLOSED": fc_led,
        "INTEGRITY": integ_led,
        "STATE_TRANSITION": _other(
            "ESTABLISHED" if inv.transition_maps else "NOT_APPLICABLE",
            "TRANSITION_MAP_DISCOVERED" if inv.transition_maps else "NO_TRANSITION_MAP_DISCOVERED",
            int("falsifications_executed" in smb), smb.get("falsifications_executed", 0),
            "DYNAMIC_FALSIFICATION",
            counterexamples=sum(k.get("result") == "COUNTEREXAMPLE" for k in smb.get("cases") or [])),
        # No dedicated observability / provenance campaign is implemented.
        "OBSERVABILITY": _other(
            "ESTABLISHED" if fc_led["capabilities_in_tested_domain"] else "NOT_ESTABLISHED",
            "PROTECTED_DECISIONS_OBSERVED" if fc_led["capabilities_in_tested_domain"]
            else "NO_PROTECTED_DECISION_OBSERVED", 0, 0, "NONE",
            note="no observability campaign implemented"),
        # Declaration↔code trace: each cross-check is an executed attempt to
        # falsify "declared symbol exists" (static, can fail).
        "DECLARATION_TRACEABILITY": _other(
            "ESTABLISHED" if exp["declared_security"] and dtb["cases"] else "NOT_RESOLVED",
            "CAPABILITIES_DECLARED" if exp["declared_security"] and dtb["cases"]
            else "NO_DECLARED_CAPABILITY_LIST",
            int(bool(dtb["cases"])), len(dtb["cases"]), "STATIC_CROSSCHECK",
            checks_executed=dtb["checks_executed"],
            counterexamples=sum(k.get("result") == "COUNTEREXAMPLE" for k in dtb["cases"])),
        "PROVENANCE": _other("ESTABLISHED", "CAPABILITIES_ENUMERATED", 0, 0, "NONE",
                             note=PROVENANCE_COMPAT_NOTE),
    }
    # OBSERVABILITY: unmeasured (no campaign) → NOT_QUALIFIED whenever there is
    # anything to measure. Reason-code presence seen during fail-closed
    # falsifications is published as a NOTE, not a verdict.
    denies = [k for r in recs for k in (r["campaigns"].get("FAIL_CLOSED") or {}).get("cases", [])
              if k["falsified_precondition"] and k["decision"] == "DENY"]
    obs = "NOT_QUALIFIED"
    exp["observability_note"] = (
        f"incidental: {sum(bool(k['reason_codes']) for k in denies)}/{len(denies)} "
        "DENY outputs from FAIL_CLOSED falsifications carried reason codes "
        "(no observability campaign executed)")
    # Static declaration↔code trace (kept; now also the DECLARATION_TRACEABILITY input).
    module_names = _module_symbols(inv)
    unresolved = [c for c in caps if c not in module_names]
    exp["provenance_static_trace"] = {
        "declared_capabilities": len(caps), "unresolved_symbols": unresolved,
        "status": "RESOLVED" if not unresolved else "UNRESOLVED_SYMBOLS"}
    # PROVENANCE (compat key): authentic provenance is not measured.
    prov = "NOT_QUALIFIED"
    exp["provenance_note"] = PROVENANCE_COMPAT_NOTE
    results = {"FAIL_CLOSED": fc, "INTEGRITY": integ, "STATE_TRANSITION": st,
               "OBSERVABILITY": obs, "DECLARATION_TRACEABILITY": trace,
               "PROVENANCE": prov}
    results = _enforce_evidence_rule(results, ledger)
    exp["property_evidence"] = ledger
    parts = []
    for k in PROPERTIES_BASE:
        led = ledger[k]
        parts.append(f"{k}={results[k]} [applicability={led['applicability']}, "
                     f"capabilities_applicable={led['capabilities_applicable']}, "
                     f"falsifications_executed={led['falsifications_executed']}, "
                     f"counterexamples={led['counterexamples']}]")
    overall = ("MULTI_PROPERTY (not collapsed): " + "; ".join(parts)
               + f"; capability_source={exp.get('capability_source')}"
               + "; scope=ISOLATED_RESOURCE; SYSTEM_WIDE_CLAIM=NO")
    out = dict(results)
    out["OVERALL_RESOURCE_EVALUATION"] = overall
    return out


def report_resource(expediente: dict) -> str:
    e = expediente
    bar = "=" * 48
    L = [bar, "UHCR — RESOURCE FAIL-CLOSED AUDIT", bar,
         f"TARGET_FILE={e.get('target_file')}",
         f"TARGET_MODULE={e.get('target_module')}",
         f"ROOT={e.get('root')}  ROOT_SOURCE={e.get('root_source')}",
         f"DECLARATION_ID={e.get('declaration_id')}",
         f"AUDIT_SCOPE={e.get('audit_scope')}",
         f"SYSTEM_PERIMETER_BYPASSED_FOR_MEASUREMENT={e.get('system_perimeter_bypassed_for_measurement')}"
         "  # measurement isolation only",
         f"SYSTEM_WIDE_CLAIM={e.get('system_wide_claim')}",
         f"DECLARED_SECURITY={e.get('declared_security')}",
         f"STATUS={e.get('status')}",
         f"IMPORT_STATUS={e.get('import_status')}",
         f"CAPABILITY_SOURCE={e.get('capability_source')}",
         "", "SEMANTIC DESCRIPTION (descriptive metadata only: feeds no "
         "applicability, campaign or verdict)",
         f"CAPABILITIES_DISCOVERED={len(e.get('capabilities') or [])}"]
    for c in e.get("capabilities") or []:
        L += [c["capability"],
              f"    ROLE={c['role']}  (descriptive)",
              f"    DECLARED_PROPERTY={c['property']}",
              f"    CONFIDENCE={c['confidence']}"]
        if c.get("asset"):
            L.append(f"    ASSET={c['asset']}")
        if c.get("shape"):
            L.append(f"    SHAPE={c['shape']}")
        if c.get("producer"):
            L.append(f"    PRODUCER={c['producer']} (DERIVED)")
        L.append(f"    SEMANTIC_ALIGNMENT={c['semantic_alignment']}")
        if c.get("reason"):
            L.append(f"    REASON={c['reason']}")
    if e.get("undeclared_gate_candidates"):
        L.append(f"UNDECLARED_GATE_CANDIDATES={e['undeclared_gate_candidates']}  (descriptive)")
    L += ["", "CAPABILITY MEASUREMENT (applicability + campaigns; role-independent)"]
    for c in e.get("capabilities") or []:
        L.append(c["capability"])
        for p, m in (c.get("measurement") or {}).items():
            L.append(f"    {p}: APPLICABILITY={m['applicability']} BASIS={m['basis']} "
                     f"CAMPAIGN={m['campaign']} POSITIVE_CONTROLS_VALID={m['positive_controls_valid']} "
                     f"FALSIFICATIONS_EXECUTED={m['falsifications_executed']} "
                     f"COUNTEREXAMPLES={m['counterexamples']} VERDICT={m['verdict']}")
            for k in (c.get("campaigns") or {}).get(p, {}).get("cases", []):
                L.append(f"      - {k['case']}: {k['decision']} → {k['result']}"
                         + (" (out of scope)" if k["result"] == "NOT_A_DEFENSE" else ""))
    L += ["", "RESOURCE VERDICT"]
    ledger = e.get("property_evidence") or {}
    verdict = e.get("verdict") or {}
    for k in discovered_property_families(e):
        ev = ledger.get(k) or {}
        L += [k,
              f"    APPLICABILITY={ev.get('applicability')}",
              f"    BASIS={','.join(ev.get('basis') or []) or None}",
              f"    CAPABILITIES_APPLICABLE={ev.get('capabilities_applicable')}"]
        if "capabilities_total" in ev:
            L.append(f"    CAPABILITIES_NOT_QUALIFIED={ev.get('capabilities_not_qualified')}"
                     f"  CAPABILITIES_OUT_OF_SCOPE={ev.get('capabilities_out_of_scope')}"
                     f"  CAPABILITIES_NOT_RESOLVED={ev.get('capabilities_not_resolved')}"
                     f"  (of {ev.get('capabilities_total')})")
        if "campaigns_attempted" in ev:
            L.append(f"    CAMPAIGNS_ATTEMPTED={ev.get('campaigns_attempted')}")
        L += [f"    CAMPAIGNS_EXECUTED={ev.get('campaigns_executed')}",
              f"    POSITIVE_CONTROLS_VALID={ev.get('positive_controls_valid')}",
              f"    FALSIFICATIONS_EXECUTED={ev.get('falsifications_executed')}",
              f"    COUNTEREXAMPLES={ev.get('counterexamples')}",
              f"    EVIDENCE_KIND={ev.get('evidence_kind', 'NONE')}",
              f"    VERDICT={verdict.get(k)}"]
    for k in discovered_property_families(e):
        L.append(f"{k}={verdict.get(k)}")
        if verdict.get(k) == "PASS":
            L.append(f"{k}=PASS — {PASS_MEANING}")
    L.append(f"OVERALL_RESOURCE_EVALUATION={verdict.get('OVERALL_RESOURCE_EVALUATION')}")
    if e.get("observability_note"):
        L.append(f"NOTE_OBSERVABILITY={e['observability_note']}")
    if e.get("provenance_static_trace"):
        L.append(f"NOTE_PROVENANCE_STATIC_TRACE={e['provenance_static_trace']}")
    if e.get("provenance_note"):
        L.append(f"NOTE_PROVENANCE={e['provenance_note']}")
    if e.get("state_machine"):
        sm = e["state_machine"]
        L.append(f"NOTE_STATE_TRANSITION=rejected={sm.get('rejected')} "
                 f"rejection={sm.get('rejection')} counterexample={sm.get('counterexample')}")
    if e.get("accounting"):
        L += _report_accounting(e)
    if e.get("audit_record"):
        L += _report_audit_record(e)
    return "\n".join(L)


def semantic_fingerprint(expediente: dict) -> str:
    rows = sorted(({k: c.get(k) for k in ("capability", "role", "property", "asset",
                                          "applicability", "producer")}
                   for c in expediente.get("capabilities") or []),
                  key=lambda r: str(r["capability"]))
    payload = {"target_file": expediente.get("target_file"),
               "declaration_id": expediente.get("declaration_id"),
               "declared_security": expediente.get("declared_security"),
               "capabilities": rows}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str)
                          .encode("utf-8")).hexdigest()


# ===========================================================================
# Property families, accounting, auditor/target separation, audit record
# ===========================================================================

def discovered_property_families(exp: dict) -> list[str]:
    """Property families actually present in this expediente's verdict
    (base vocabulary + any family the motor emits), OVERALL excluded."""
    return [k for k in (exp.get("verdict") or {}) if k != "OVERALL_RESOURCE_EVALUATION"]


def _case_blocks(exp: dict) -> list[tuple[str, str, Optional[str], dict]]:
    """Every structure that owns a probe plan / case records:
    (where, property, capability, block)."""
    out: list[tuple[str, str, Optional[str], dict]] = []
    for c in exp.get("capabilities") or []:
        if c.get("campaigns") is not None:  # 1.4: one block per measured property
            for prop, o in c["campaigns"].items():
                if "plan" in o or o.get("cases") or o.get("not_executed"):
                    out.append((f"capability:{c.get('capability')}#{prop}", prop,
                                c.get("capability"), o))
            continue
        o = c.get("observed") or {}
        if "plan" in o or o.get("cases") or o.get("not_executed"):
            out.append((f"capability:{c.get('capability')}", c.get("property"),
                        c.get("capability"), o))
    sm = exp.get("state_machine") or {}
    if "plan" in sm or sm.get("cases") or sm.get("not_executed"):
        out.append(("state_machine", "STATE_TRANSITION", None, sm))
    dt = exp.get("declaration_traceability") or {}
    if "plan" in dt or dt.get("cases") or dt.get("not_executed"):
        out.append(("declaration_traceability", "DECLARATION_TRACEABILITY", None, dt))
    return out


def _executed_evidence(entry: dict) -> int:
    return int((entry or {}).get("falsifications_executed", 0) or 0)


def _accounting(exp: dict) -> dict[str, Any]:
    """Zero-loss invariants. Raw counts come from distinct structures
    (declaration list vs capability records; plan vs cases vs not_executed;
    verdict vs property_evidence; case records vs _call exception log), so
    every equation below can fail."""
    acc: dict[str, Any] = {}
    # ---- capabilities ----
    declared = Counter(str(c) for c in (exp.get("audited_capabilities")
                                        or exp.get("declared_capabilities") or []))
    recs = exp.get("capabilities") or []
    rec_names = Counter(str(r.get("capability")) for r in recs)
    unresolved = [r.get("capability") for r in recs
                  if r.get("role") == "UNKNOWN" or r.get("confidence") == "NOT_RESOLVED"]
    classified = [r.get("capability") for r in recs
                  if r.get("capability") not in unresolved and r.get("role") in ROLES]
    invalid = [r.get("capability") for r in recs
               if r.get("capability") not in unresolved and r.get("role") not in ROLES]
    missing = sorted((declared - rec_names).elements())
    extra = sorted((rec_names - declared).elements())
    acc.update({
        "capabilities_discovered": sum(declared.values()),
        "capabilities_classified": len(classified),
        "capabilities_unresolved": len(unresolved),
        "capabilities_unaccounted": len(missing) + len(extra) + len(invalid),
        "capabilities_unaccounted_detail": {"declared_without_record": missing,
                                            "record_not_declared": extra,
                                            "role_outside_vocabulary": invalid},
        "capabilities_unresolved_definition":
            "role == UNKNOWN or confidence == NOT_RESOLVED",
    })
    acc["capabilities_equation_holds"] = (
        acc["capabilities_discovered"] == acc["capabilities_classified"]
        + acc["capabilities_unresolved"] + len(missing) and not extra and not invalid)
    # ---- cases ----
    gen = ex_raw = ne_raw = 0
    lost: list[str] = []
    unplanned: list[str] = []
    for where, _prop, _cap, blk in _case_blocks(exp):
        plan = list(blk.get("plan") or [])
        cases = list(blk.get("cases") or [])
        skipped = list(blk.get("not_executed") or [])
        gen, ex_raw, ne_raw = gen + len(plan), ex_raw + len(cases), ne_raw + len(skipped)
        ex = Counter(k.get("case") for k in cases)
        ne = Counter(k.get("case") for k in skipped)
        for name in plan:
            if ex[name] > 0:
                ex[name] -= 1
            elif ne[name] > 0:
                ne[name] -= 1
            else:
                lost.append(f"{where}/{name}")
        unplanned += [f"{where}/{n}" for n in (ex + ne).elements()]
        unplanned += [f"{where}/{k.get('case')}:NO_REASON" for k in skipped
                      if not k.get("reason")]
    acc.update({
        "cases_generated": gen,
        "cases_executed": ex_raw,
        "cases_not_executed_accounted": ne_raw,
        "cases_unaccounted": len(lost) + len(unplanned),
        "cases_unaccounted_detail": {"planned_without_record": lost,
                                     "record_not_planned_or_no_reason": unplanned},
    })
    acc["cases_equation_holds"] = (gen == ex_raw + ne_raw + len(lost)) and not unplanned
    # ---- properties ----
    verdict = exp.get("verdict") or {}
    led = exp.get("property_evidence") or {}
    fams = discovered_property_families(exp)
    applicable = [p for p in fams if verdict.get(p) != "NOT_APPLICABLE"]
    qualified = [p for p in applicable if verdict.get(p) in ("PASS", "FAIL")
                 and _executed_evidence(led.get(p)) > 0]
    not_qualified = [p for p in applicable
                     if verdict.get(p) in ("NOT_RESOLVED", "NOT_QUALIFIED",
                                           "INSUFFICIENT_EVIDENCE")]
    p_lost = [p for p in applicable if p not in qualified and p not in not_qualified]
    acc.update({
        "properties_discovered": len(fams),
        "properties_not_applicable": len(fams) - len(applicable),
        "properties_applicable": len(applicable),
        "properties_qualified": len(qualified),
        "properties_not_qualified": len(not_qualified),
        "properties_unaccounted": len(p_lost),
        "properties_detail": {"qualified": qualified, "not_qualified": not_qualified,
                              "unaccounted": p_lost},
    })
    acc["properties_equation_holds"] = (
        len(applicable) == len(qualified) + len(not_qualified) + len(p_lost)
        and len(fams) == len(applicable) + sum(verdict.get(p) == "NOT_APPLICABLE"
                                               for p in fams))
    # ---- measurement: per measured property, every capability is placed in
    # exactly one applicability state and ledger counts equal case records ----
    m_lost: list[str] = []
    for prop in MEASURED_PROPERTIES:
        e = led.get(prop) or {}
        if "capabilities_total" not in e:
            continue
        states = (e["capabilities_applicable"] + e["capabilities_not_established"]
                  + e["capabilities_not_applicable"] + e["capabilities_not_resolved"]
                  + e.get("capabilities_out_of_scope", 0))
        if not (states == e["capabilities_total"] == len(recs)):
            m_lost.append(f"{prop}:capability_states={states}/{len(recs)}")
        ce_cases = sum(1 for _w, p, _c, blk in _case_blocks(exp) if p == prop
                       for k in blk.get("cases") or [] if k.get("result") == "COUNTEREXAMPLE")
        if ce_cases != e["counterexamples"]:
            m_lost.append(f"{prop}:counterexamples={e['counterexamples']}!={ce_cases}")
        pw = sum(1 for _w, p, _c, blk in _case_blocks(exp) if p == prop
                 for k in blk.get("cases") or []
                 if not k.get("falsified_precondition") and k.get("result") == "POSITIVE_WITNESS")
        if pw != e["positive_controls_valid"]:
            m_lost.append(f"{prop}:positive_controls={e['positive_controls_valid']}!={pw}")
    acc["measurement_unaccounted"] = len(m_lost)
    acc["measurement_unaccounted_detail"] = m_lost
    acc["measurement_equation_holds"] = not m_lost
    # ---- exceptions: case records vs independent _call log ----
    in_cases = Counter((w, k.get("case"), k.get("exception"))
                       for w, _p, _c, blk in _case_blocks(exp)
                       for k in blk.get("cases") or [] if k.get("exception"))
    log = Counter((e.get("where"), e.get("case"), e.get("type"))
                  for e in (exp.get("target_exception_log") or {}).get("case_calls") or [])
    acc.update({
        "exceptions_in_case_records": sum(in_cases.values()),
        "exceptions_in_call_log": sum(log.values()),
        "exceptions_unreconciled": sum((in_cases - log).values()) + sum((log - in_cases).values()),
    })
    return acc


def _exceptions(exp: dict) -> list[dict]:
    out: list[dict] = []
    for w, _p, _c, blk in _case_blocks(exp):
        for k in blk.get("cases") or []:
            if k.get("exception"):
                out.append({"origin": "TARGET_OBSERVED_IN_CASE", "type": k["exception"],
                            "where": f"{w}/{k.get('case')}", "count": 1})
    for t, n in ((exp.get("target_exception_log") or {}).get("search_calls") or {}).items():
        out.append({"origin": "TARGET_OBSERVED_IN_SEARCH", "type": t,
                    "where": "witness_search", "count": n})
    ist = str(exp.get("import_status") or "")
    if ist.startswith("IMPORT_FAILED"):
        parts = ist.split(":")
        out.append({"origin": "TARGET_IMPORT", "type": parts[1] if len(parts) > 1 else ist,
                    "where": "import", "count": 1})
    for e in exp.get("instrument_exceptions") or []:
        out.append(dict(e, count=1))
    return out


def _observations(exp: dict) -> list[dict]:
    return [{"where": w, "case": k.get("case"), "decision": k.get("decision"),
             "result": k.get("result"), "exception": k.get("exception"),
             "reason_codes": k.get("reason_codes"),
             "kind": ("STATIC_CHECK" if k.get("check_kind") == "STATIC_CROSSCHECK" else
                      "EXCEPTION_OBSERVED" if k.get("exception") else "OUTPUT_OBSERVED")}
            for w, _p, _c, blk in _case_blocks(exp) for k in blk.get("cases") or []]


def _counterexamples(exp: dict) -> list[dict]:
    out = []
    for w, prop, cap, blk in _case_blocks(exp):
        for k in blk.get("cases") or []:
            if k.get("result") != "COUNTEREXAMPLE":
                continue
            effect = k.get("observed_effect") or (
                f"decision={k.get('decision')} under falsified precondition "
                "(compromise verified, execution observed, protected effect produced)")
            out.append({"capability": k.get("capability") or cap or w, "property": prop,
                        "case": k.get("case"), "input": k.get("stimulus"),
                        "observed_effect": effect, "where": w})
    return out


def _positive_controls(exp: dict) -> list[dict]:
    return [{"where": w, "case": k.get("case"), "stimulus": k.get("stimulus"),
             "result": k.get("result")}
            for w, _p, _c, blk in _case_blocks(exp) for k in blk.get("cases") or []
            if not k.get("falsified_precondition")]


def _falsifications(exp: dict) -> list[dict]:
    out = []
    for w, prop, _c, blk in _case_blocks(exp):
        for k in blk.get("cases") or []:
            if k.get("falsified_precondition"):
                out.append({"where": w, "property": prop, "status": "EXECUTED",
                            "kind": k.get("check_kind", "DYNAMIC_FALSIFICATION"),
                            "case": k.get("case"), "stimulus": k.get("stimulus"),
                            "result": k.get("result")})
        for k in blk.get("not_executed") or []:
            out.append({"where": w, "property": prop, "status": "NOT_EXECUTED",
                        "case": k.get("case"), "reason": k.get("reason")})
    return out


def _divergences(exp: dict) -> list[dict]:
    out = []
    for c in exp.get("capabilities") or []:
        if c.get("semantic_alignment") != "SEMANTIC_DIVERGENCE":
            continue
        o = (c.get("campaigns") or {}).get("FAIL_CLOSED") or c.get("observed") or {}
        out.append({"capability": c.get("capability"),
                    "DECLARED": (c.get("declared") or {}).get("role"),
                    "DERIVED": (c.get("derived") or {}).get("role", c.get("role")),
                    "OBSERVED": {"fail_closed": c.get("fail_closed"),
                                 "integrity": c.get("integrity"),
                                 "decisions": sorted({k.get("decision") for k in o.get("cases") or []
                                                      if k.get("decision")})}})
    return out


def _unresolved(exp: dict) -> list[dict]:
    out = []
    for c in exp.get("capabilities") or []:
        if c.get("role") == "UNKNOWN" or c.get("confidence") == "NOT_RESOLVED":
            out.append({"kind": "CAPABILITY", "item": c.get("capability"),
                        "reason": c.get("reason") or
                        f"role={c.get('role')} confidence={c.get('confidence')}"})
        for prop, o in (c.get("campaigns") or {}).items():
            if "plan" not in o:
                out.append({"kind": "CAMPAIGN_NOT_GENERATED",
                            "item": f"{c.get('capability')}#{prop}",
                            "reason": "; ".join(o.get("notes") or ["no probe plan"])})
    verdict, led = exp.get("verdict") or {}, exp.get("property_evidence") or {}
    for p in discovered_property_families(exp):
        if verdict.get(p) in ("NOT_RESOLVED", "NOT_QUALIFIED", "INSUFFICIENT_EVIDENCE"):
            e = led.get(p) or {}
            out.append({"kind": "PROPERTY", "item": p,
                        "reason": f"verdict={verdict[p]}; falsifications_executed="
                                  f"{_executed_evidence(e)}; evidence_kind="
                                  f"{e.get('evidence_kind', 'NONE')}"
                                  + (f"; {e['note']}" if e.get("note") else "")})
    for w, _p, _c, blk in _case_blocks(exp):
        for k in blk.get("not_executed") or []:
            out.append({"kind": "CASE_NOT_EXECUTED", "item": f"{w}/{k.get('case')}",
                        "reason": k.get("reason")})
    for g in exp.get("undeclared_gate_candidates") or []:
        out.append({"kind": "UNDECLARED_GATE_CANDIDATE", "item": g,
                    "reason": "structural gate not in declaration; reported, not audited"})
    return out


def _qualify(exp: dict) -> dict[str, Any]:
    """AUDITOR_QUALIFICATION (instrument) vs TARGET_SECURITY_RESULT (resource).
    Target counterexamples are observations: they never disqualify the auditor."""
    acc = exp["accounting"]
    reasons: list[str] = []
    st = exp.get("status")
    if st not in CLEAN_STATUSES:
        reasons.append(f"TARGET_NOT_CLEANLY_REPORTED:status={st}")
    if st == "ABSENT" and not exp.get("root"):
        reasons.append("TARGET_ABSENT_WITHOUT_SEARCH_ROOT")
    for k in ("capabilities", "cases", "properties"):
        if acc.get(f"{k}_unaccounted", 0) != 0:
            reasons.append(f"{k.upper()}_UNACCOUNTED={acc[f'{k}_unaccounted']}:"
                           f"{acc.get(f'{k}_unaccounted_detail', acc.get(f'{k}_detail'))}")
        if not acc.get(f"{k}_equation_holds", False):
            reasons.append(f"{k.upper()}_EQUATION_BROKEN")
    if not acc.get("measurement_equation_holds", True):
        reasons.append(f"MEASUREMENT_EQUATION_BROKEN:{acc.get('measurement_unaccounted_detail')}")
    if acc.get("exceptions_unreconciled", 0) != 0:
        reasons.append(f"EXCEPTIONS_UNRECONCILED={acc['exceptions_unreconciled']}")
    for e in exp.get("instrument_exceptions") or []:
        reasons.append(f"INSTRUMENT_EXCEPTION:{e.get('type')}@{e.get('where')}")
    # Identidad del instrumento: sin hash de plantilla o de motor no se
    # puede demostrar que las copias usan el mismo auditor.
    if _template_sha256(__file__) is None:
        reasons.append("TEMPLATE_IDENTITY_NOT_RESOLVED:linea TARGET ausente o no unica")
    if _engine_sha256(__file__) is None:
        reasons.append("ENGINE_IDENTITY_NOT_RESOLVED:marcadores de la seccion M ausentes")
    try:
        semantic_fingerprint(exp)
    except Exception as e:  # pragma: no cover - defensive
        reasons.append(f"FINGERPRINT_NOT_COMPUTABLE:{type(e).__name__}")
    verdict = exp.get("verdict") or {}
    fams = discovered_property_families(exp)
    for p in fams:
        if verdict.get(p) not in PROPERTY_RESULTS:
            reasons.append(f"VERDICT_OUTSIDE_VOCABULARY:{p}={verdict.get(p)}")
    for p in verdict_respects_evidence(exp):
        reasons.append(f"VERDICT_WITHOUT_EVIDENCE:{p}")
    # A real audit cannot call the instrument qualified from one-sided
    # sensitivity. Both directions are mandatory and explicitly evidenced.
    if exp.get("require_calibration"):
        ctl = exp.get("auditor_controls") or {}
        required_controls = (
            "NEGATIVE_CONTROL", "POSITIVE_CONTROL",
            "MUTATION_SENSITIVITY", "EVIDENCE_CONSISTENCY",
        )
        for name in required_controls:
            if ctl.get(name) != "PASS":
                reasons.append(f"AUDITOR_CONTROL_NOT_APPROVED:{name}={ctl.get(name)}")
    ces = exp.get("counterexamples") or []
    for p in fams:
        if verdict.get(p) == "FAIL" and not any(c["property"] == p for c in ces):
            reasons.append(f"FAIL_WITHOUT_COUNTEREXAMPLE_RECORD:{p}")
    for c in ces:
        if verdict.get(c["property"]) != "FAIL":
            reasons.append(f"COUNTEREXAMPLE_NOT_REFLECTED_IN_VERDICT:{c['property']}")
    auditor = "FAIL" if reasons else "PASS"

    applicable = [p for p in fams if verdict.get(p) != "NOT_APPLICABLE"]
    qualified = set(acc.get("properties_detail", {}).get("qualified") or [])
    details: list[Any]
    if auditor == "FAIL":
        target, details = "NOT_EVALUATED", ["verdict withheld: auditor not qualified"]
        security = "WITHHELD_INSTRUMENT_NOT_QUALIFIED"
    elif any(verdict.get(p) == "FAIL" for p in fams):
        target, details = "FAIL", list(ces)
        security = "FAIL"
    else:
        pending = [f"{p}={verdict.get(p)}" for p in applicable
                   if not (verdict.get(p) == "PASS" and p in qualified)]
        if st != "OK":
            pending.insert(0, f"STATUS={st}")
        if not applicable:
            pending.append("NO_APPLICABLE_PROPERTY")
        # 1.4: capabilities the instrument could not qualify are listed too,
        # so a PASS over the tested domain never hides them.
        led = exp.get("property_evidence") or {}
        nq_caps = [f"{p}:CAPABILITIES_NOT_QUALIFIED={led[p]['capabilities_not_qualified']}"
                   f"/{led[p].get('capabilities_total')}" for p in MEASURED_PROPERTIES
                   if (led.get(p) or {}).get("capabilities_not_qualified")]
        pending += nq_caps
        # Instrument gap is reported as such, never as target INCOMPLETE.
        target = ("INSTRUMENT_NOT_QUALIFIED_FOR_PROPERTY"
                  if any(verdict.get(p) == "NOT_QUALIFIED" for p in applicable) or nq_caps
                  else "INCOMPLETE" if pending else "PASS")
        details = pending
        security = target
    return {"auditor": auditor, "auditor_reasons": reasons, "target": target,
            "target_details": details, "security_verdict": security}


def _sha256_file(p: Any) -> Optional[str]:
    try:
        pp = Path(p)
        return hashlib.sha256(pp.read_bytes()).hexdigest() if pp.is_file() else None
    except Exception:
        return None


def _engine_source(path=None) -> str:
    """Texto de la sección M (MOTOR) de este archivo: excluye la línea TARGET
    y las pruebas del recurso. Es lo que inspecciona el anti-hardcode."""
    txt = Path(path or __file__).read_text(encoding="utf-8")
    # Marcadores = líneas de comentario al inicio de línea (no literales).
    m_ini = re.search(r"^# M\. MOTOR UHCR", txt, re.M)
    m_fin = re.search(r"^# PRUEBAS DEL RECURSO", txt, re.M)
    if not m_ini or not m_fin or m_fin.start() <= m_ini.start():
        # Estricto: sin marcadores no se inspecciona "otra cosa" en silencio.
        raise ValueError("ENGINE_SECTION_NOT_RESOLVED: marcadores de la sección M ausentes")
    return txt[m_ini.start():m_fin.start()]


# Línea TARGET: asignación de nivel superior, exactamente una.
_TARGET_LINE_RE = re.compile(r"^TARGET\s*=\s*[\"'].*[\"']\s*(#.*)?$")


def _template_sha256(path) -> Optional[str]:
    """AUDITOR_TEMPLATE_SHA256 = H(archivo completo − la línea TARGET).
    Igual en dos copias ⇔ difieren únicamente en TARGET.
    None si la línea TARGET no existe o no es única."""
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    idx = [i for i, l in enumerate(lines) if _TARGET_LINE_RE.match(l)]
    if len(idx) != 1:
        return None
    kept = lines[:idx[0]] + lines[idx[0] + 1:]
    return hashlib.sha256("\n".join(kept).encode("utf-8")).hexdigest()


def _engine_sha256(path) -> Optional[str]:
    """AUDITOR_ENGINE_SHA256 = H(sección M exclusivamente).
    Igual en dos copias ⇔ mismo motor. None si la sección no se resuelve."""
    try:
        sec = _engine_source(path)
    except (OSError, ValueError):
        return None
    return hashlib.sha256(sec.encode("utf-8")).hexdigest()


def run_identity(target_sha256: Optional[str], auditor_sha256: Optional[str],
                 spec: str, run_id: str) -> str:
    """sha256 over TARGET_SHA256|AUDITOR_SHA256|SPEC|RUN_ID."""
    return hashlib.sha256(f"{target_sha256}|{auditor_sha256}|{spec}|{run_id}"
                          .encode("utf-8")).hexdigest()


def _finalize(exp: dict) -> dict:
    """Derive accounting, evidence sections, qualification and AUDIT RECORD
    from the structures of THIS expediente (re-callable on a constructed exp)."""
    for k, v in (("capabilities", []), ("verdict", {}), ("declared_capabilities", []),
                 ("undeclared_gate_candidates", []), ("instrument_exceptions", []),
                 ("declared_security", False), ("system_wide_claim", "NO")):
        exp.setdefault(k, v)
    exp["accounting"] = _accounting(exp)
    exp["positive_controls"] = _positive_controls(exp)
    exp["falsifications"] = _falsifications(exp)
    exp["observations"] = _observations(exp)
    exp["exceptions"] = _exceptions(exp)
    exp["counterexamples"] = _counterexamples(exp)
    exp["semantic_divergences"] = _divergences(exp)
    exp["unresolved"] = _unresolved(exp)
    q = _qualify(exp)
    prev = exp.get("audit_record") or {}
    now = datetime.now(timezone.utc)
    run_id = prev.get("RUN_ID") or uuid.uuid4().hex
    ts = prev.get("UTC_TIMESTAMP") or now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    tsha = _sha256_file(exp.get("target_path_resolved")) if exp.get("target_path_resolved") else None
    asha = _sha256_file(__file__)
    esha = _engine_sha256(__file__)
    tpsha = _template_sha256(__file__)
    acc = exp["accounting"]
    try:
        fpr = semantic_fingerprint(exp)
    except Exception:  # pragma: no cover
        fpr = None
    exp["audit_record"] = {
        "TARGET_FILE": exp.get("target_file"),
        "TARGET_SHA256": tsha,
        "AUDITOR": Path(__file__).name,
        "AUDITOR_SHA256": asha,
        "AUDITOR_TEMPLATE_SHA256": tpsha,
        "AUDITOR_ENGINE_SHA256": esha,
        "SPEC": SPEC_VERSION,
        "SPEC_EVOLUTION": SPEC_EVOLUTION,
        "RUN_ID": run_id,
        "UTC_TIMESTAMP": ts,
        "RUN_IDENTITY": run_identity(tsha, asha, SPEC_VERSION, run_id),
        "RESOURCE_DISCOVERED": "YES" if tsha is not None else "NO",
        "SEGURIDAD_DECLARED": "YES" if exp.get("declared_security") else "NO",
        "CAPABILITIES_DISCOVERED": acc["capabilities_discovered"],
        "CAPABILITIES_CLASSIFIED": acc["capabilities_classified"],
        "CAPABILITIES_UNRESOLVED": acc["capabilities_unresolved"],
        "PROPERTIES_DISCOVERED": acc["properties_discovered"],
        "PROPERTIES_APPLICABLE": acc["properties_applicable"],
        "PROPERTIES_QUALIFIED": acc["properties_qualified"],
        "PROPERTIES_NOT_QUALIFIED": acc["properties_not_qualified"],
        "PROPERTIES_UNACCOUNTED": acc["properties_unaccounted"],
        "CAPABILITY_SOURCE": exp.get("capability_source"),
        "PROPERTY_MEASUREMENT": {
            p: dict((exp.get("property_evidence") or {}).get(p) or {},
                    verdict=(exp.get("verdict") or {}).get(p))
            for p in discovered_property_families(exp)},
        "MEASUREMENT_EQUATION_HOLDS": acc.get("measurement_equation_holds", True),
        "CASES_GENERATED": acc["cases_generated"],
        "CASES_EXECUTED": acc["cases_executed"],
        "CASES_ACCOUNTED_NON_EXEC": acc["cases_not_executed_accounted"],
        "CASES_UNACCOUNTED": acc["cases_unaccounted"],
        "POSITIVE_CONTROLS": len(exp["positive_controls"]),
        "POSITIVE_CONTROLS_WITNESSED": sum(p["result"] == "POSITIVE_WITNESS"
                                           for p in exp["positive_controls"]),
        "COUNTEREXAMPLES": len(exp["counterexamples"]),
        "COUNTEREXAMPLE_LIST": exp["counterexamples"],
        "EXCEPTIONS": sum(e.get("count", 1) for e in exp["exceptions"]),
        "EXCEPTION_LIST": exp["exceptions"],
        "EXCEPTIONS_RECONCILED": acc["exceptions_unreconciled"] == 0,
        "SEMANTIC_DIVERGENCES": exp["semantic_divergences"],
        "UNRESOLVED": exp["unresolved"],
        "AUDITOR_CONTROLS": exp.get("auditor_controls"),
        "NEGATIVE_CONTROL": (exp.get("auditor_controls") or {}).get("NEGATIVE_CONTROL"),
        "POSITIVE_CONTROL": (exp.get("auditor_controls") or {}).get("POSITIVE_CONTROL"),
        "MUTATION_SENSITIVITY": (exp.get("auditor_controls") or {}).get("MUTATION_SENSITIVITY"),
        "EVIDENCE_CONSISTENCY": (exp.get("auditor_controls") or {}).get("EVIDENCE_CONSISTENCY"),
        "AUDITOR_QUALIFICATION": q["auditor"],
        "AUDITOR_QUALIFICATION_REASONS": q["auditor_reasons"],
        "TARGET_SECURITY_RESULT": q["target"],
        "TARGET_SECURITY_DETAILS": q["target_details"],
        "SECURITY_VERDICT": q["security_verdict"],
        "RESOURCE_EVALUATION": (exp.get("verdict") or {}).get("OVERALL_RESOURCE_EVALUATION"),
        "SYSTEM_WIDE_CLAIM": exp.get("system_wide_claim", "NO"),
        "SEMANTIC_FINGERPRINT": fpr,
        "RECORD_PATH": prev.get("RECORD_PATH"),
    }
    return exp


def _record_document(exp: dict) -> dict:
    return {
        "STATIC_DISCOVERY": {k: exp.get(k) for k in (
            "target_file", "target_module", "root", "root_source", "status",
            "import_status", "seguridad_source", "declaration_id", "declaration_key",
            "declared_security", "declared_capabilities", "ast_inventory",
            "undeclared_gate_candidates", "provenance_static_trace",
            "declaration_traceability")},
        "SEMANTIC_CLASSIFICATION": exp.get("capabilities"),
        "POSITIVE_CONTROLS": exp.get("positive_controls"),
        "FALSIFICATIONS": exp.get("falsifications"),
        "OBSERVATIONS": exp.get("observations"),
        "EXCEPTIONS": {"list": exp.get("exceptions"),
                       "target_exception_log": exp.get("target_exception_log"),
                       "instrument_exceptions": exp.get("instrument_exceptions")},
        "COUNTEREXAMPLES": exp.get("counterexamples"),
        "PROPERTY_VERDICTS": {"verdict": exp.get("verdict"),
                              "property_evidence": exp.get("property_evidence"),
                              "property_families": discovered_property_families(exp),
                              "properties_base": list(PROPERTIES_BASE),
                              "provenance_note": exp.get("provenance_note"),
                              "observability_note": exp.get("observability_note"),
                              "state_machine": exp.get("state_machine")},
        "UNRESOLVED": exp.get("unresolved"),
        "ACCOUNTING": exp.get("accounting"),
        "AUDIT_RECORD": exp.get("audit_record"),
        "EXPEDIENTE": exp,
    }


def default_record_dir(exp: dict) -> Path:
    env = os.environ.get("UHCR_RECORD_DIR")
    if env:
        return Path(env)
    stem = Path(str(exp.get("target_file") or "unknown_target")).stem
    return Path(exp.get("root") or ROOT) / "diagnostics" / "uhcr_resources" / stem


def persist_record(exp: dict, out_dir: Path | str | None = None) -> Path:
    """Write the full expediente (evidence sections + AUDIT_RECORD) as JSON.
    Never overwrites (exclusive create); appends one line to index.jsonl."""
    rec = exp["audit_record"]
    d = Path(out_dir) if out_dir is not None else default_record_dir(exp)
    d.mkdir(parents=True, exist_ok=True)
    compact = "".join(ch for ch in rec["UTC_TIMESTAMP"] if ch not in "-:.")
    path = d / f"{compact}_{rec['RUN_ID']}.json"
    if path.exists():
        raise FileExistsError(f"audit record already exists (never overwritten): {path}")
    rec["RECORD_PATH"] = str(path)
    exp["record_path"] = str(path)
    try:
        data = json.dumps(_record_document(exp), indent=2, default=repr,
                          ensure_ascii=False)
        with open(path, "x", encoding="utf-8") as fh:
            fh.write(data)
    except BaseException:
        rec["RECORD_PATH"] = None
        exp["record_path"] = None
        raise
    line = {"run_id": rec["RUN_ID"], "timestamp": rec["UTC_TIMESTAMP"],
            "target_file": rec["TARGET_FILE"], "target_sha256": rec["TARGET_SHA256"],
            "auditor_sha256": rec["AUDITOR_SHA256"],
            "auditor_template_sha256": rec.get("AUDITOR_TEMPLATE_SHA256"),
            "auditor_engine_sha256": rec.get("AUDITOR_ENGINE_SHA256"), "spec": rec["SPEC"],
            "run_identity": rec["RUN_IDENTITY"],
            "auditor_qualification": rec["AUDITOR_QUALIFICATION"],
            "target_security_result": rec["TARGET_SECURITY_RESULT"],
            "record": str(path)}
    with open(d / "index.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(line, default=repr, ensure_ascii=False) + "\n")
    return path


def _report_accounting(e: dict) -> list[str]:
    a = e.get("accounting") or {}
    bar = "=" * 48
    L = ["", bar, "ACCOUNTING", bar]
    L.append(f"CAPABILITIES: discovered={a.get('capabilities_discovered')} = "
             f"classified={a.get('capabilities_classified')} + "
             f"unresolved={a.get('capabilities_unresolved')} + "
             f"unaccounted={a.get('capabilities_unaccounted')}  "
             f"EQUATION_HOLDS={a.get('capabilities_equation_holds')}")
    L.append(f"CASES: generated={a.get('cases_generated')} = "
             f"executed={a.get('cases_executed')} + "
             f"not_executed_accounted={a.get('cases_not_executed_accounted')} + "
             f"unaccounted={a.get('cases_unaccounted')}  "
             f"EQUATION_HOLDS={a.get('cases_equation_holds')}")
    L.append(f"PROPERTIES: applicable={a.get('properties_applicable')} = "
             f"qualified={a.get('properties_qualified')} + "
             f"not_qualified={a.get('properties_not_qualified')} + "
             f"unaccounted={a.get('properties_unaccounted')}  "
             f"(discovered={a.get('properties_discovered')}, "
             f"not_applicable={a.get('properties_not_applicable')})  "
             f"EQUATION_HOLDS={a.get('properties_equation_holds')}")
    L.append(f"EXCEPTIONS: in_case_records={a.get('exceptions_in_case_records')} "
             f"in_call_log={a.get('exceptions_in_call_log')} "
             f"unreconciled={a.get('exceptions_unreconciled')}")
    return L


def _report_audit_record(e: dict) -> list[str]:
    r = e.get("audit_record") or {}
    bar = "=" * 48
    L = ["", bar, "AUDIT RECORD", bar]
    ctl = r.get("AUDITOR_CONTROLS") or {}
    if ctl:
        L.extend([
            "AUDITOR CALIBRATION — FAIL_CLOSED",
            f"NEGATIVE_CONTROL_EXPECTED={ctl.get('NEGATIVE_CONTROL_EXPECTED')}",
            f"NEGATIVE_CONTROL_OBSERVED={ctl.get('NEGATIVE_CONTROL_OBSERVED')}",
            f"NEGATIVE_CONTROL={ctl.get('NEGATIVE_CONTROL')}",
            f"POSITIVE_CONTROL_EXPECTED={ctl.get('POSITIVE_CONTROL_EXPECTED')}",
            f"POSITIVE_CONTROL_OBSERVED={ctl.get('POSITIVE_CONTROL_OBSERVED')}",
            f"POSITIVE_CONTROL={ctl.get('POSITIVE_CONTROL')}",
            f"MUTATION_SENSITIVITY={ctl.get('MUTATION_SENSITIVITY')}",
            f"EVIDENCE_CONSISTENCY={ctl.get('EVIDENCE_CONSISTENCY')}",
        ])
    lists = {"COUNTEREXAMPLE_LIST", "EXCEPTION_LIST", "SEMANTIC_DIVERGENCES",
             "UNRESOLVED", "AUDITOR_QUALIFICATION_REASONS", "TARGET_SECURITY_DETAILS"}
    for k in AUDIT_RECORD_FIELDS:
        if k == "SPEC_EVOLUTION":
            continue
        v = r.get(k)
        if k in lists:
            L.append(f"{k}={len(v or [])}")
            for item in v or []:
                L.append(f"    - {item}")
        else:
            L.append(f"{k}={v}")
    return L


def run_target(target: str | Path, *, root: Path | None = None,
               skip_if_absent: bool = False) -> dict:
    """Wrapper helper: audit + print report; asserts only structural invariants.
    With skip_if_absent, an ABSENT target skips (pytest) instead of failing."""
    exp = audit_resource(target, root=root)
    if skip_if_absent and exp["status"] == "ABSENT":
        import pytest
        pytest.skip(f"target absent under root: {target}")
    print(report_resource(exp))
    assert exp["audit_scope"] == "ISOLATED_RESOURCE"
    assert exp["system_wide_claim"] == "NO"
    assert not verdict_respects_evidence(exp), verdict_respects_evidence(exp)
    for c in exp["capabilities"]:
        assert c["role"] in ROLES and c["confidence"] in CONFIDENCE
        m = (c.get("measurement") or {}).get("FAIL_CLOSED") or {}
        if not m.get("in_tested_domain"):
            assert not m.get("counterexamples"), "counterexample outside tested domain"
    return exp


# ===========================================================================
# Motor self-tests (collected when pytest targets this file)
# ===========================================================================

def test_motor_absent_target_does_not_crash():
    exp = audit_resource("modules/__uhcr_absent__/nope.py")
    assert exp["status"] == "ABSENT" and exp["verdict"]["FAIL_CLOSED"] == "NOT_RESOLVED"


def test_motor_anti_hardcode():
    forbid = ["perimeter_" + "precheck", "perimeter_" + "postcheck", "OMEGA_" + "PERIMETER",
              "classify_" + "uis", "verify_" + "omega_fast", "omega_" + "self_test",
              "kill" + "dog", "Kill" + "dog", "politica_" + "permite"]
    src = _engine_source()
    assert not [f for f in forbid if f in src]


def test_motor_zero_falsification_property_never_pass():
    ledger = {k: {"campaigns_executed": 0, "falsifications_executed": 0}
              for k in ("FAIL_CLOSED", "INTEGRITY", "STATE_TRANSITION",
                        "OBSERVABILITY", "PROVENANCE")}
    res = _enforce_evidence_rule({k: "PASS" for k in ledger}, ledger)
    assert all(v == "NOT_QUALIFIED" for v in res.values())


def test_motor_fail_closed_states_are_non_ambiguous():
    """Unknown applicability, unqualified campaign and measured verdict are
    distinct states; generic fallbacks must never manufacture evidence."""
    assert _empty_verdict("synthetic")["FAIL_CLOSED"] == "NOT_RESOLVED"
    assert _fold_fail_closed([], witness=True) == "NOT_QUALIFIED"
    assert _fold_fail_closed([], witness=False) == "NOT_QUALIFIED"
    denied = [{"falsified_precondition": True, "result": "PROTECTED_EFFECT_ABSENT"}]
    assert _fold_fail_closed(denied, witness=True) == "PASS"
    ce = [{"falsified_precondition": True, "result": "COUNTEREXAMPLE"}]
    assert _fold_fail_closed(ce, witness=True) == "FAIL"
    assert _fold_fail_closed(denied, witness=False) == "NOT_QUALIFIED"
    unest = [{"falsified_precondition": True, "result": "STIMULUS_NOT_ESTABLISHED"}]
    assert _fold_fail_closed(denied + unest, witness=True) == "NOT_QUALIFIED"
    for r in ("EXCEPTION_NOT_DENY", "NOT_OBSERVABLE"):
        low = [{"falsified_precondition": True, "result": r}]
        assert _fold_fail_closed(denied + low, witness=True) == "INSUFFICIENT_EVIDENCE"
        assert _fold_fail_closed(unest + low, witness=True) == "NOT_QUALIFIED"


def test_motor_insufficient_evidence_is_not_generic_fallback():
    """INSUFFICIENT_EVIDENCE only propagates from a qualified campaign whose
    executed evidence fell below threshold; it is never synthesized as a
    fallback for unknown/unqualified states."""
    assert _agg(["NOT_RESOLVED"]) == "NOT_RESOLVED"
    assert _agg(["NOT_QUALIFIED"]) == "NOT_QUALIFIED"
    assert _agg(["PASS", "INSUFFICIENT_EVIDENCE"]) == "INSUFFICIENT_EVIDENCE"
    assert _agg(["NOT_QUALIFIED", "INSUFFICIENT_EVIDENCE"]) == "NOT_QUALIFIED"
    assert _agg(["UHCR_UNMAPPED"]) == "NOT_QUALIFIED"


# ---- 1.1 self-tests: accounting, auditor/target separation, persistence ----

def _constructed_exp(plan: list, cases: list, fc: str, fals: int,
                     log: Optional[list] = None) -> dict:
    """Minimal hand-built expediente (no target) for invariant tests."""
    return {"status": "OK", "root": "/constructed", "root_source": "EXPLICIT",
            "target_file": "constructed/synthetic.py", "declared_security": True,
            "declared_capabilities": ["cap_a"], "system_wide_claim": "NO",
            "capabilities": [{"capability": "cap_a", "role": "ENFORCEMENT_GATE",
                              "confidence": "DERIVED", "property": "FAIL_CLOSED",
                              "fail_closed_applicability": "APPLICABLE",
                              "observed": {"plan": plan, "cases": cases,
                                           "not_executed": []}}],
            "verdict": {"FAIL_CLOSED": fc, "OVERALL_RESOURCE_EVALUATION": "constructed"},
            "property_evidence": {"FAIL_CLOSED": {"campaigns_executed": 1,
                                                  "falsifications_executed": fals,
                                                  "evidence_kind": "DYNAMIC_FALSIFICATION"}},
            "target_exception_log": {"case_calls": log or [], "search_calls": {}}}


def test_motor_accounting_missing_case_disqualifies_auditor():
    plan = ["positive_witness", "falsify_x", "falsify_y"]
    cases = [_case("positive_witness", "ok", "ALLOW", None, False, True),
             _case("falsify_x", "x=False", "DENY", None, True, True)]  # falsify_y lost
    exp = _finalize(_constructed_exp(plan, cases, "PASS", 1))
    acc, rec = exp["accounting"], exp["audit_record"]
    assert acc["cases_unaccounted"] == 1
    assert acc["cases_unaccounted_detail"]["planned_without_record"] == ["capability:cap_a/falsify_y"]
    assert rec["AUDITOR_QUALIFICATION"] == "FAIL"
    assert any(r.startswith("CASES_UNACCOUNTED") for r in rec["AUDITOR_QUALIFICATION_REASONS"])
    assert rec["TARGET_SECURITY_RESULT"] == "NOT_EVALUATED"
    assert rec["SECURITY_VERDICT"] == "WITHHELD_INSTRUMENT_NOT_QUALIFIED"
    # control: same exp with the case accounted as not executed → auditor PASS
    ok = _constructed_exp(plan, cases, "PASS", 1)
    ok["capabilities"][0]["observed"]["not_executed"] = [{"case": "falsify_y",
                                                          "reason": "constructed"}]
    assert _finalize(ok)["audit_record"]["AUDITOR_QUALIFICATION"] == "PASS"


def test_motor_unplanned_case_breaks_equation():
    cases = [_case("positive_witness", "ok", "ALLOW", None, False, True),
             _case("falsify_ghost", "g", "DENY", None, True, True)]
    exp = _finalize(_constructed_exp(["positive_witness"], cases, "PASS", 1))
    assert not exp["accounting"]["cases_equation_holds"]
    assert exp["audit_record"]["AUDITOR_QUALIFICATION"] == "FAIL"


def test_motor_counterexample_separates_auditor_from_target():
    plan = ["positive_witness", "falsify_x"]
    cases = [_case("positive_witness", "ok", "ALLOW", None, False, True),
             _case("falsify_x", "x=False", "ALLOW", None, True, True)]
    assert cases[1]["result"] == "COUNTEREXAMPLE"
    exp = _finalize(_constructed_exp(plan, cases, "FAIL", 1))
    rec = exp["audit_record"]
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert rec["TARGET_SECURITY_RESULT"] == "FAIL"
    ce = rec["COUNTEREXAMPLE_LIST"]
    assert len(ce) == 1 and ce[0]["capability"] == "cap_a" and ce[0]["property"] == "FAIL_CLOSED"
    assert ce[0]["case"] == "falsify_x" and ce[0]["input"] == "x=False" and ce[0]["observed_effect"]


def test_motor_fail_without_counterexample_record_disqualifies_auditor():
    cases = [_case("positive_witness", "ok", "ALLOW", None, False, True)]
    exp = _finalize(_constructed_exp(["positive_witness"], cases, "FAIL", 1))
    assert exp["audit_record"]["AUDITOR_QUALIFICATION"] == "FAIL"


def test_motor_exception_reconciliation():
    plan = ["positive_witness"]
    cases = [_case("positive_witness", "ok", None, "ValueError", False, True)]
    bad = _finalize(_constructed_exp(plan, cases, "NOT_QUALIFIED", 0))
    assert bad["accounting"]["exceptions_unreconciled"] == 1
    assert bad["audit_record"]["AUDITOR_QUALIFICATION"] == "FAIL"
    log = [{"where": "capability:cap_a", "case": "positive_witness", "type": "ValueError"}]
    good = _finalize(_constructed_exp(plan, cases, "NOT_QUALIFIED", 0, log))
    assert good["accounting"]["exceptions_unreconciled"] == 0
    assert good["audit_record"]["AUDITOR_QUALIFICATION"] == "PASS"
    assert good["audit_record"]["TARGET_SECURITY_RESULT"] == "INSTRUMENT_NOT_QUALIFIED_FOR_PROPERTY"


def test_motor_persist_never_overwrites(tmp_path):
    exp = _finalize(_constructed_exp(["positive_witness"],
                                     [_case("positive_witness", "ok", "ALLOW", None,
                                            False, True)], "NOT_QUALIFIED", 0))
    p = persist_record(exp, tmp_path)
    first = p.read_bytes()
    doc = json.loads(first)
    assert set(RECORD_SECTIONS) <= set(doc)
    assert set(AUDIT_RECORD_FIELDS) <= set(doc["AUDIT_RECORD"])
    import pytest
    with pytest.raises(FileExistsError):
        persist_record(exp, tmp_path)
    assert p.read_bytes() == first
    exp2 = _finalize(_constructed_exp(["positive_witness"],
                                      [_case("positive_witness", "ok", "ALLOW", None,
                                             False, True)], "NOT_QUALIFIED", 0))
    p2 = persist_record(exp2, tmp_path)
    assert p2 != p and p.read_bytes() == first
    idx = [json.loads(x) for x in (tmp_path / "index.jsonl").read_text().splitlines()]
    assert [i["run_id"] for i in idx] == [exp["audit_record"]["RUN_ID"],
                                          exp2["audit_record"]["RUN_ID"]]


_SYNTHETIC_GATE = """
import enum
from dataclasses import dataclass


class Veredicto(enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class Decision:
    decision: Veredicto
    request_id: str
    reason_codes: tuple = ()


@dataclass(frozen=True)
class Comprobaciones:
    contract_ok: bool
    integrity_ok: bool
    authentication_ok: bool
    authorization_ok: bool
    state_ok: bool


class Regla:
    require_all = True


REGLAS = {"leer": Regla()}


def _denegar(request_id: str) -> Decision:
    return Decision(Veredicto.DENY, request_id, ("DENIED",))


def compuerta_sintetica(request_id: str, context_id: str, resource_id: str,
                        operation: str, checks: Comprobaciones) -> Decision:
    if operation not in REGLAS:
        return _denegar(request_id)
    if not (checks.contract_ok and checks.authentication_ok
            and checks.authorization_ok and checks.state_ok@@INTEGRITY@@):
        return _denegar(request_id)
    return Decision(Veredicto.ALLOW, request_id)


SEGURIDAD = {
    "id": "SINTETICO",
    "capacidades_recurso": ["compuerta_sintetica"@@EXTRA@@],
    "semantica": {
        "compuerta_sintetica": {
            "role": "ENFORCEMENT_GATE",
            "property": "FAIL_CLOSED",
            "asset": "AUTHORIZATION_DECISION",
            "protected_effect": "ALLOW",
            "failure_policy": "DENY",
            "shape": "COMPOSITE_CHECKS",
        }
    },
}
"""


def _synthetic_target(tmp_path: Path, integrity: bool, extra: str = "") -> Path:
    name = f"uhcr_synth_{uuid.uuid4().hex}.py"
    src = (_SYNTHETIC_GATE.replace("@@INTEGRITY@@", " and checks.integrity_ok" if integrity else "")
           .replace("@@EXTRA@@", extra))
    (tmp_path / name).write_text(src, encoding="utf-8")
    return Path(name)


def _calibrate_fail_closed_instrument() -> dict[str, Any]:
    """Symmetric metrological calibration for FAIL_CLOSED.

    Negative control: a deliberately fail-open gate MUST be diagnosed FAIL.
    Positive control: a deliberately closed gate MUST be diagnosed PASS.
    The controls are synthetic, declarative, and disjoint from the TARGET.
    """
    import tempfile
    with tempfile.TemporaryDirectory(prefix="uhcr_cal_") as td:
        root = Path(td)
        neg = audit_resource(_synthetic_target(root, integrity=False), root=root, _calibrate=False)
        pos = audit_resource(_synthetic_target(root, integrity=True), root=root, _calibrate=False)

    neg_obs = (neg.get("verdict") or {}).get("FAIL_CLOSED")
    pos_obs = (pos.get("verdict") or {}).get("FAIL_CLOSED")
    neg_aud = (neg.get("audit_record") or {}).get("AUDITOR_QUALIFICATION")
    pos_aud = (pos.get("audit_record") or {}).get("AUDITOR_QUALIFICATION")
    neg_ce = len(neg.get("counterexamples") or [])
    pos_ce = len(pos.get("counterexamples") or [])

    neg_ok = neg_obs == "FAIL" and neg_aud == "PASS" and neg_ce > 0
    pos_ok = pos_obs == "PASS" and pos_aud == "PASS" and pos_ce == 0
    sensitivity_ok = neg_obs == "FAIL" and pos_obs == "PASS"
    consistency_ok = neg_aud == "PASS" and pos_aud == "PASS"

    return {
        "NEGATIVE_CONTROL_EXPECTED": "FAIL",
        "NEGATIVE_CONTROL_OBSERVED": neg_obs,
        "NEGATIVE_CONTROL": "PASS" if neg_ok else "FAIL",
        "NEGATIVE_CONTROL_COUNTEREXAMPLES": neg_ce,
        "POSITIVE_CONTROL_EXPECTED": "PASS",
        "POSITIVE_CONTROL_OBSERVED": pos_obs,
        "POSITIVE_CONTROL": "PASS" if pos_ok else "FAIL",
        "POSITIVE_CONTROL_COUNTEREXAMPLES": pos_ce,
        "MUTATION_SENSITIVITY": "PASS" if sensitivity_ok else "FAIL",
        "EVIDENCE_CONSISTENCY": "PASS" if consistency_ok else "FAIL",
    }


def test_motor_synthetic_fail_open_gate_is_target_fail_not_auditor_fail(tmp_path):
    exp = audit_resource(_synthetic_target(tmp_path, integrity=False), root=tmp_path)
    rec = exp["audit_record"]
    assert exp["verdict"]["FAIL_CLOSED"] == "FAIL"
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert rec["TARGET_SECURITY_RESULT"] == "FAIL"
    assert [c["case"] for c in rec["COUNTEREXAMPLE_LIST"]] == ["falsify_integrity_ok"]
    assert rec["CASES_UNACCOUNTED"] == 0 and rec["TARGET_SHA256"]


def test_motor_synthetic_closed_gate_passes_fail_closed(tmp_path):
    exp = audit_resource(_synthetic_target(tmp_path, integrity=True), root=tmp_path)
    rec = exp["audit_record"]
    assert exp["verdict"]["FAIL_CLOSED"] == "PASS"
    assert exp["verdict"]["DECLARATION_TRACEABILITY"] == "PASS"
    assert rec["AUDITOR_QUALIFICATION"] == "PASS" and rec["COUNTEREXAMPLES"] == 0
    # OBSERVABILITY / PROVENANCE unmeasured → instrument gap, never a global PASS
    assert rec["TARGET_SECURITY_RESULT"] == "INSTRUMENT_NOT_QUALIFIED_FOR_PROPERTY"
    assert set(PROPERTIES_BASE) <= set(discovered_property_families(exp))
    assert verdict_respects_evidence(exp) == []


def test_motor_calibracion_fail_closed_es_simetrica_y_aprobada():
    ctl = _calibrate_fail_closed_instrument()
    assert ctl["NEGATIVE_CONTROL_EXPECTED"] == "FAIL"
    assert ctl["NEGATIVE_CONTROL_OBSERVED"] == "FAIL"
    assert ctl["NEGATIVE_CONTROL"] == "PASS"
    assert ctl["POSITIVE_CONTROL_EXPECTED"] == "PASS"
    assert ctl["POSITIVE_CONTROL_OBSERVED"] == "PASS"
    assert ctl["POSITIVE_CONTROL"] == "PASS"
    assert ctl["MUTATION_SENSITIVITY"] == "PASS"
    assert ctl["EVIDENCE_CONSISTENCY"] == "PASS"


def _synthetic_variant(tmp_path: Path, old: str, new: str) -> Path:
    t = _synthetic_target(tmp_path, integrity=True)
    src = (tmp_path / t).read_text(encoding="utf-8")
    assert src.count(old) == 1
    (tmp_path / t).write_text(src.replace(old, new), encoding="utf-8")
    return t


_ROLE_LINE = '"role": "ENFORCEMENT_GATE",'


def _fc_measure(exp: dict) -> tuple:
    return exp["verdict"]["FAIL_CLOSED"], exp["property_evidence"]["FAIL_CLOSED"]


def test_motor_pass_fail_closed_helper_is_exact():
    """PASS_FC = witness ∧ falsifications>0 ∧ stimuli verified ∧ decisions
    observable ∧ 0 counterexamples (no role argument exists)."""
    ok = [{"falsified_precondition": False, "result": "POSITIVE_WITNESS"},
          {"falsified_precondition": True, "result": "PROTECTED_EFFECT_ABSENT"}]
    assert pass_fail_closed(ok, True)
    assert not pass_fail_closed(ok, False)                       # no witness
    assert not pass_fail_closed(ok[:1], True)                    # no falsification
    for bad in ("STIMULUS_NOT_ESTABLISHED", "NOT_OBSERVABLE",
                "EXCEPTION_NOT_DENY", "COUNTEREXAMPLE"):
        assert not pass_fail_closed(ok + [{"falsified_precondition": True, "result": bad}], True)
    gap = [{"case": "falsify_x", "reason": "STIMULUS_CONSTRUCTION_FAILED:TypeError"}]
    assert not pass_fail_closed(ok, True, gap)
    assert _fold_fail_closed(ok, True, gap) == "NOT_QUALIFIED"
    assert "role" not in inspect.signature(pass_fail_closed).parameters


def test_motor_role_invariance(tmp_path, monkeypatch):
    """Same target, different role labels (declared or forced): FAIL_CLOSED
    verdict and every measurement count are identical."""
    for integrity in (True, False):
        seen = []
        for role_line in ("", '"role": "ORCHESTRATOR",', '"role": "CLASSIFIER",', _ROLE_LINE):
            t = _synthetic_target(tmp_path, integrity)
            src = (tmp_path / t).read_text(encoding="utf-8").replace(_ROLE_LINE, role_line)
            (tmp_path / t).write_text(src, encoding="utf-8")
            exp = audit_resource(t, root=tmp_path, _calibrate=False)
            assert exp["audit_record"]["AUDITOR_QUALIFICATION"] == "PASS"
            seen.append(_fc_measure(exp))
        orig = _semantic_authority
        for forced in ("UNKNOWN", "VERIFIER"):
            monkeypatch.setattr(sys.modules[__name__], "_semantic_authority",
                                lambda dcl, der, _r=forced: dict(orig(dcl, der), role=_r))
            exp = audit_resource(_synthetic_target(tmp_path, integrity), root=tmp_path,
                                 _calibrate=False)
            assert {c["role"] for c in exp["capabilities"]} == {forced}
            seen.append(_fc_measure(exp))
            monkeypatch.setattr(sys.modules[__name__], "_semantic_authority", orig)
        assert all(x == seen[0] for x in seen), seen
        assert seen[0][0] == ("PASS" if integrity else "FAIL")


def test_motor_unknown_role_closed_control_passes(tmp_path):
    """ROLE=UNKNOWN (no declared semantics) + executed falsifications + 0 CE → PASS."""
    exp = audit_resource(_synthetic_variant(tmp_path, '"semantica": {', '"sin_semantica": {'),
                         root=tmp_path)
    v, led, rec = exp["verdict"], exp["property_evidence"]["FAIL_CLOSED"], exp["audit_record"]
    assert [c["role"] for c in exp["capabilities"]] == ["UNKNOWN"]
    assert v["FAIL_CLOSED"] == "PASS" and led["falsifications_executed"] > 0
    assert led["applicability"] == "ESTABLISHED" and led["basis"] == ["PROTECTED_EFFECT_OBSERVED"]
    assert led["positive_controls_valid"] == 1 and led["counterexamples"] == 0
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert f"FAIL_CLOSED=PASS — {PASS_MEANING}" in report_resource(exp).splitlines()


def test_motor_unknown_role_fail_open_fails(tmp_path):
    """ROLE=UNKNOWN fail-open control → FAIL with a counterexample record."""
    t = _synthetic_target(tmp_path, integrity=False)
    src = (tmp_path / t).read_text(encoding="utf-8").replace('"semantica": {', '"sin_semantica": {')
    (tmp_path / t).write_text(src, encoding="utf-8")
    exp = audit_resource(t, root=tmp_path)
    rec = exp["audit_record"]
    assert [c["role"] for c in exp["capabilities"]] == ["UNKNOWN"]
    assert exp["verdict"]["FAIL_CLOSED"] == "FAIL"
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert [c["case"] for c in rec["COUNTEREXAMPLE_LIST"]] == ["falsify_integrity_ok"]


def test_motor_gate_role_without_falsifiable_condition_never_passes(tmp_path):
    """ROLE=ENFORCEMENT_GATE, ALLOW observable, but no executable falsification → NOT_QUALIFIED."""
    src = _SYNTHETIC_GATE.replace("@@INTEGRITY@@", "").replace("@@EXTRA@@", "") + (
        "\n\ndef compuerta_sin_condiciones(request_id: str) -> Decision:\n"
        "    return Decision(Veredicto.ALLOW, request_id)\n")
    src = src.replace('"capacidades_recurso": ["compuerta_sintetica"]',
                      '"capacidades_recurso": ["compuerta_sin_condiciones"]')
    src = src.replace('"compuerta_sintetica": {', '"compuerta_sin_condiciones": {')
    (tmp_path / "uhcr_synth_nocond.py").write_text(src, encoding="utf-8")
    exp = audit_resource(Path("uhcr_synth_nocond.py"), root=tmp_path, _calibrate=False)
    c = exp["capabilities"][0]
    assert c["role"] == "ENFORCEMENT_GATE"
    m = c["measurement"]["FAIL_CLOSED"]
    assert m["positive_controls_valid"] == 1 and m["falsifications_executed"] == 0
    assert m["basis"] == "POSITIVE_WITNESS_WITHOUT_FALSIFIABLE_CONDITION"
    assert exp["verdict"]["FAIL_CLOSED"] == "NOT_QUALIFIED"
    assert exp["audit_record"]["AUDITOR_QUALIFICATION"] == "PASS"


def test_motor_no_protected_decision_is_out_of_scope_and_unresolvable_is_not_resolved(tmp_path):
    """Executed output with no protected decision → NOT_A_DEFENSE /
    OUT_OF_SCOPE, never counted as NOT_QUALIFIED; a declared name with no
    symbol cannot be resolved at all → NOT_RESOLVED."""
    (tmp_path / "uhcr_synth_label.py").write_text(
        "def etiqueta(n: int) -> str:\n    return 'PAR' if n % 2 == 0 else 'IMPAR'\n\n"
        "SEGURIDAD = {'id': 'SINTETICO_ETIQUETA', 'capacidades_recurso': ['etiqueta']}\n",
        encoding="utf-8")
    exp = audit_resource(Path("uhcr_synth_label.py"), root=tmp_path, _calibrate=False)
    led = exp["property_evidence"]["FAIL_CLOSED"]
    m = exp["capabilities"][0]["measurement"]["FAIL_CLOSED"]
    cases = exp["capabilities"][0]["campaigns"]["FAIL_CLOSED"]["cases"]
    assert [(k["decision"], k["result"]) for k in cases] == [("NO_PROTECTED_DECISION", "NOT_A_DEFENSE")]
    assert (m["applicability"], m["basis"], m["verdict"]) == ("OUT_OF_SCOPE", "NO_PROTECTED_DECISION",
                                                              "NOT_APPLICABLE")
    assert exp["verdict"]["FAIL_CLOSED"] == "NOT_APPLICABLE"
    assert led["basis"] == ["NO_PROTECTED_DECISION_IN_TARGET"]
    assert led["capabilities_not_qualified"] == 0 and led["capabilities_out_of_scope"] == 1
    assert exp["verdict"]["INTEGRITY"] == "NOT_APPLICABLE"
    rec = exp["audit_record"]
    assert rec["AUDITOR_QUALIFICATION"] == "PASS"
    assert not [d for d in rec["TARGET_SECURITY_DETAILS"] if "CAPABILITIES_NOT_QUALIFIED" in d]
    assert "- positive_witness: NO_PROTECTED_DECISION → NOT_A_DEFENSE (out of scope)" in report_resource(exp)
    (tmp_path / "uhcr_synth_ghost.py").write_text(
        "SEGURIDAD = {'id': 'SINTETICO_FANTASMA', 'capacidades_recurso': ['no_existe']}\n",
        encoding="utf-8")
    exp = audit_resource(Path("uhcr_synth_ghost.py"), root=tmp_path, _calibrate=False)
    assert exp["verdict"]["FAIL_CLOSED"] == "NOT_RESOLVED"
    assert exp["verdict"]["INTEGRITY"] == "NOT_RESOLVED"


def test_motor_deny_only_defense_stays_not_qualified(tmp_path):
    """A real defense whose decision is readable but only DENY is reachable
    (no ALLOW witness) is NOT_QUALIFIED; OUT_OF_SCOPE never hides it."""
    src = _SYNTHETIC_GATE.replace("@@INTEGRITY@@", "").replace("@@EXTRA@@", "").replace(
        "    if operation not in REGLAS:\n", "    return _denegar(request_id)\n    if operation not in REGLAS:\n")
    (tmp_path / "uhcr_synth_denyonly.py").write_text(src, encoding="utf-8")
    exp = audit_resource(Path("uhcr_synth_denyonly.py"), root=tmp_path, _calibrate=False)
    m = exp["capabilities"][0]["measurement"]["FAIL_CLOSED"]
    pos = exp["capabilities"][0]["campaigns"]["FAIL_CLOSED"]["cases"][0]
    assert (pos["decision"], pos["result"]) == ("DENY", "NO_WITNESS")
    assert m["applicability"] == "NOT_ESTABLISHED" and m["verdict"] == "NOT_QUALIFIED"
    assert exp["verdict"]["FAIL_CLOSED"] == "NOT_QUALIFIED"
    assert exp["property_evidence"]["FAIL_CLOSED"]["capabilities_not_qualified"] == 1


def test_motor_integrity_cases_show_observed_value(tmp_path):
    """INTEGRITY case 'decision' is the value actually observed (ok=...,
    exception), never a hardcoded NOT_OBSERVABLE."""
    (tmp_path / "uhcr_synth_ver.py").write_text(
        "class Evidencia:\n"
        "    def __init__(self, ok, ctx):\n        self.ok, self.ctx = ok, ctx\n"
        "    def public_dict(self):\n        return {'ok': self.ok, 'ctx': self.ctx}\n\n"
        "def verificar(context_id: str, n: int) -> Evidencia:\n"
        "    return Evidencia(n > 0, context_id)\n\n"
        "SEGURIDAD = {'id': 'SINTETICO_VERIFICADOR', 'capacidades_recurso': ['verificar']}\n",
        encoding="utf-8")
    exp = audit_resource(Path("uhcr_synth_ver.py"), root=tmp_path, _calibrate=False)
    cases = exp["capabilities"][0]["campaigns"]["INTEGRITY"]["cases"]
    assert [k["decision"] for k in cases] == ["ok=True", "ok=True", "ok=True"]
    assert exp["verdict"]["INTEGRITY"] == "PASS"
    closed = audit_resource(_synthetic_target(tmp_path, True), root=tmp_path, _calibrate=False)
    for c in closed["capabilities"]:
        for k in c["campaigns"]["INTEGRITY"].get("cases", []):
            assert k["decision"] != "NOT_OBSERVABLE", k
    assert closed["capabilities"][0]["measurement"]["INTEGRITY"]["applicability"] == "OUT_OF_SCOPE"


def test_motor_missing_seguridad_does_not_prevent_search(tmp_path):
    """No SEGURIDAD: public functions are enumerated and measured; SEGURIDAD
    grants nothing and its absence blocks nothing."""
    src = _SYNTHETIC_GATE.replace("@@INTEGRITY@@", " and checks.integrity_ok").replace("@@EXTRA@@", "")
    src = src[:src.index("SEGURIDAD = {")]
    (tmp_path / "uhcr_synth_nodecl.py").write_text(src, encoding="utf-8")
    exp = audit_resource(Path("uhcr_synth_nodecl.py"), root=tmp_path, _calibrate=False)
    assert exp["capability_source"] == "DISCOVERED_PUBLIC_FUNCTIONS"
    assert exp["verdict"]["FAIL_CLOSED"] == "PASS"
    assert exp["verdict"]["DECLARATION_TRACEABILITY"] == "NOT_RESOLVED"
    assert exp["audit_record"]["AUDITOR_QUALIFICATION"] == "PASS", \
        exp["audit_record"]["AUDITOR_QUALIFICATION_REASONS"]


def test_motor_report_has_no_role_defined_universe(tmp_path):
    """No report phrases the measurement universe by role ('gate(s)')."""
    exps = [audit_resource(_synthetic_target(tmp_path, i), root=tmp_path, _calibrate=False)
            for i in (True, False)]
    exps.append(audit_resource("modules/__uhcr_absent__/nope.py", _calibrate=False))
    for e in exps:
        txt = report_resource(e)
        assert "gate(s)" not in txt and "verifier(s)" not in txt
        for k in PROPERTIES_BASE:
            assert f"{k}=" in txt


def test_motor_campaign_cannot_execute_is_not_qualified(tmp_path):
    """Protected effect declared (ROLE=ENFORCEMENT_GATE) but no stimulus can
    be built → NOT_QUALIFIED; the declaration grants nothing."""
    exp = audit_resource(_synthetic_variant(tmp_path, "require_all", "exige_todo"),
                         root=tmp_path)
    v, rec = exp["verdict"], exp["audit_record"]
    assert exp["capabilities"][0]["role"] == "ENFORCEMENT_GATE"
    assert exp["capabilities"][0]["protected_effect"] == "ALLOW"
    assert v["FAIL_CLOSED"] == "NOT_QUALIFIED"
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert rec["TARGET_SECURITY_RESULT"] == "INSTRUMENT_NOT_QUALIFIED_FOR_PROPERTY"
    assert "FAIL_CLOSED=NOT_QUALIFIED" in rec["TARGET_SECURITY_DETAILS"]


def test_motor_exception_under_qualified_campaign_is_insufficient(tmp_path):
    """Qualified campaign executed; exception instead of DENY → INSUFFICIENT_EVIDENCE."""
    exp = audit_resource(_synthetic_variant(
        tmp_path, "    if operation not in REGLAS:\n",
        "    if not checks.integrity_ok:\n        raise ValueError(request_id)\n"
        "    if operation not in REGLAS:\n"), root=tmp_path)
    rec = exp["audit_record"]
    assert exp["verdict"]["FAIL_CLOSED"] == "INSUFFICIENT_EVIDENCE"
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert rec["COUNTEREXAMPLES"] == 0


def test_motor_declaration_traceability_can_fail(tmp_path):
    exp = audit_resource(_synthetic_target(tmp_path, True, ', "nombre_inexistente"'),
                         root=tmp_path)
    assert exp["verdict"]["DECLARATION_TRACEABILITY"] == "FAIL"
    assert exp["property_evidence"]["DECLARATION_TRACEABILITY"]["evidence_kind"] == "STATIC_CROSSCHECK"
    rec = exp["audit_record"]
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert rec["TARGET_SECURITY_RESULT"] == "FAIL"
    assert any(c["property"] == "DECLARATION_TRACEABILITY" for c in rec["COUNTEREXAMPLE_LIST"])


def test_motor_instrument_exception_disqualifies_auditor(tmp_path, monkeypatch):
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("instrument fault injected")
    monkeypatch.setattr(sys.modules[__name__], "_derive", boom)
    exp = audit_resource(_synthetic_target(tmp_path, integrity=True), root=tmp_path)
    rec = exp["audit_record"]
    assert exp["instrument_exceptions"] and rec["AUDITOR_QUALIFICATION"] == "FAIL"
    assert rec["TARGET_SECURITY_RESULT"] == "NOT_EVALUATED"
    assert any(e["origin"] == "AUDITOR_INTERNAL" for e in rec["EXCEPTION_LIST"])


def test_motor_fingerprint_independent_of_run_identity(tmp_path):
    t = _synthetic_target(tmp_path, integrity=True)
    a, b = audit_resource(t, root=tmp_path), audit_resource(t, root=tmp_path)
    assert a["audit_record"]["RUN_ID"] != b["audit_record"]["RUN_ID"]
    assert a["audit_record"]["RUN_IDENTITY"] != b["audit_record"]["RUN_IDENTITY"]
    assert semantic_fingerprint(a) == semantic_fingerprint(b)
    r = a["audit_record"]
    assert r["RUN_IDENTITY"] == run_identity(r["TARGET_SHA256"], r["AUDITOR_SHA256"],
                                             r["SPEC"], r["RUN_ID"])


def test_motor_absent_target_is_cleanly_reported():
    exp = audit_resource("modules/__uhcr_absent__/nope.py")
    rec = exp["audit_record"]
    assert rec["RESOURCE_DISCOVERED"] == "NO" and rec["TARGET_SHA256"] is None
    assert rec["AUDITOR_QUALIFICATION"] == "PASS", rec["AUDITOR_QUALIFICATION_REASONS"]
    assert rec["TARGET_SECURITY_RESULT"] == "INCOMPLETE"


def verdict_respects_evidence(exp: dict) -> list[str]:
    """Properties published PASS/FAIL without executed falsifications (should be empty)."""
    led = exp.get("property_evidence") or {}
    return [k for k, v in (exp.get("verdict") or {}).items()
            if k != "OVERALL_RESOURCE_EVALUATION" and v in ("PASS", "FAIL")
            and (led.get(k) or {}).get("falsifications_executed", 0) <= 0]




def test_motor_identidad_plantilla_y_motor(tmp_path):
    """Metrología de identidad sobre copias sintéticas de este archivo:
    solo TARGET distinto ⇒ plantilla y motor iguales; cambio en pruebas ⇒
    plantilla distinta, motor igual; cambio en motor ⇒ ambos distintos;
    TARGET duplicado ⇒ plantilla None; sin marcadores ⇒ motor None."""
    src = Path(__file__).read_text(encoding="utf-8")
    lines = src.splitlines()
    i_t = [i for i, l in enumerate(lines) if _TARGET_LINE_RE.match(l)]
    assert len(i_t) == 1
    def escribe(nombre, ls):
        f = tmp_path / nombre
        f.write_text("\n".join(ls), encoding="utf-8")
        return f
    base = escribe("a.py", lines)
    otro = list(lines); otro[i_t[0]] = 'TARGET = "otro/recurso.py"'
    b = escribe("b.py", otro)
    assert _template_sha256(base) == _template_sha256(b) is not None
    assert _engine_sha256(base) == _engine_sha256(b) is not None
    i_pr = next(i for i, l in enumerate(lines) if re.match(r"^# PRUEBAS DEL RECURSO", l))
    cambio_pruebas = list(lines); cambio_pruebas.insert(i_pr + 1, "# cambio en pruebas")
    c = escribe("c.py", cambio_pruebas)
    assert _template_sha256(c) != _template_sha256(base)
    assert _engine_sha256(c) == _engine_sha256(base)
    i_m = next(i for i, l in enumerate(lines) if re.match(r"^# M\. MOTOR UHCR", l))
    cambio_motor = list(lines); cambio_motor.insert(i_m + 1, "# cambio en motor")
    d = escribe("d.py", cambio_motor)
    assert _template_sha256(d) != _template_sha256(base)
    assert _engine_sha256(d) != _engine_sha256(base)
    dup = list(lines); dup.insert(i_t[0] + 1, lines[i_t[0]])
    assert _template_sha256(escribe("e.py", dup)) is None
    sin_m = [l for l in lines if not re.match(r"^# M\. MOTOR UHCR", l)]
    assert _engine_sha256(escribe("f.py", sin_m)) is None


# =============================================================================
# PRUEBAS DEL RECURSO (secciones 2–9)
#   M es este mismo módulo: las pruebas llaman al motor definido arriba.
# =============================================================================
import sys as _sys
M = _sys.modules[__name__]

import ast
import hashlib
import json
import os
import time
from functools import lru_cache
from pathlib import Path

import pytest


# -----------------------------------------------------------------------------
# 2. LLAMADA AL MOTOR
#    Una sola auditoría por módulo de test; todos los tests leen el mismo
#    expediente (misma evidencia, mismo informe). El fixture autouse la
#    ejecuta y PERSISTE el registro ANTES de cualquier aserción.
# -----------------------------------------------------------------------------
PROPIEDADES_BASE = tuple(M.PROPERTIES_BASE)


@lru_cache(maxsize=1)
def expediente() -> dict:
    return M.audit_resource(TARGET)


def _emitir_al_log(pytestconfig, texto: str) -> str:
    """Escribe el informe en el log de la corrida AUNQUE pytest capture stdout.
    El CI corre `pytest -v` sin `-s`: un print() normal queda capturado y solo
    aparece si el test falla. Aquí se suspende la captura para que el informe
    completo salga SIEMPRE en el log (PASS o FAIL). Devuelve el canal usado."""
    capman = pytestconfig.pluginmanager.getplugin("capturemanager")
    if capman is not None:
        with capman.global_and_fixture_disabled():
            print("\n" + texto, flush=True)
        return "PYTEST_LOG_UNCAPTURED"
    print(texto, flush=True)
    return "STDOUT"


def _persistir_informe_txt(exp: dict, texto: str):
    """Copia textual del informe junto al JSON (<record>.report.txt), sin
    sobrescribir nunca (creación exclusiva). Queda como artefacto auditable."""
    rp = exp.get("record_path")
    if not rp:
        return None
    path = Path(rp).with_suffix(".report.txt")
    with open(path, "x", encoding="utf-8") as fh:
        fh.write(texto + "\n")
    return str(path)


# -----------------------------------------------------------------------------
# 2b. PUBLICACIÓN PARA EL OMEGA DIARY (diagnostics/test_evidence.json)
#    omega_diary_publisher.py lee test_evidence.json como OBJETO con lista
#    "cases" y cruza cada caso con el JUnit por "file::name" o
#    "classname::name". Sin esas claves el caso queda NO CORRELACIONADO y el
#    informe no aparece en el diario.
#    - nodeid / file / classname / name salen de la corrida (request.node),
#      nunca escritos a mano: cada copia publica su propio caso.
#    - Fusión sin pérdida: se conservan TODOS los casos de otros productores;
#      solo se reemplaza el caso con el mismo nodeid. Un archivo previo en
#      forma de lista se envuelve como {"cases": [...]}; un JSON ilegible se
#      conserva aparte (.unreadable_<ts>) antes de escribir, nunca se borra.
#    - No se declara el resultado del test: el estado lo aporta el JUnit.
#    - Escritura atómica (archivo temporal + os.replace).
# -----------------------------------------------------------------------------
def _ci_identity() -> dict:
    """Identidad de corrida de CI (mismo esquema que el falsificador)."""
    return {"github_sha": os.environ.get("GITHUB_SHA"),
            "github_run_id": os.environ.get("GITHUB_RUN_ID"),
            "github_run_number": os.environ.get("GITHUB_RUN_NUMBER"),
            "spec": M.SPEC_VERSION}


def _diary_evidence_path(exp: dict) -> Path:
    return Path(exp["root"]) / "diagnostics" / "test_evidence.json"


def _publish_diary(exp: dict, nodeid: str, name: str, texto: str) -> dict:
    path = _diary_evidence_path(exp)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if path.exists():
        raw = path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except ValueError:
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            path.with_name(path.name + f".unreadable_{stamp}").write_text(
                raw, encoding="utf-8")
            data = {}
        existing = ({"cases": data} if isinstance(data, list)
                    else data if isinstance(data, dict) else {})
    cases = existing.get("cases") if isinstance(existing.get("cases"), list) else []
    norm = nodeid.replace("\\", "/")
    file_part = norm.split("::", 1)[0]
    classname = (file_part[:-3] if file_part.endswith(".py") else file_part).replace("/", ".")
    r = exp["audit_record"]
    ci = _ci_identity()
    case = {
        "nodeid": norm, "test_id": norm, "test": name, "name": name,
        "originalname": name.split("[", 1)[0],
        "file": file_part, "path": file_part,
        "classname": classname, "class_name": classname,
        "location": {"file": file_part, "line": None},
        "parameters": {},
        "phases": {"call": {"when": "call", "stdout": texto}},
        "stdout": texto, "output": texto, "report": texto,
        "runtime_assertions": [], "events": [],
        "spec": M.SPEC_VERSION,
        "run_identity": ci,
        "github_sha": ci["github_sha"], "github_run_id": ci["github_run_id"],
        "github_run_number": ci["github_run_number"],
        "audit_run_id": r.get("RUN_ID"),
        "audit_run_identity": r.get("RUN_IDENTITY"),
        "target_file": r.get("TARGET_FILE"),
        "target_sha256": r.get("TARGET_SHA256"),
        "auditor_sha256": r.get("AUDITOR_SHA256"),
        "auditor_template_sha256": r.get("AUDITOR_TEMPLATE_SHA256"),
        "auditor_engine_sha256": r.get("AUDITOR_ENGINE_SHA256"),
        "auditor_qualification": r.get("AUDITOR_QUALIFICATION"),
        "target_security_result": r.get("TARGET_SECURITY_RESULT"),
        "record_path": exp.get("record_path"),
        "report_path": exp.get("report_path"),
        "provenance": "SELF_PUBLISHED_BY_TEST",
    }
    otros = [c for c in cases if not (isinstance(c, dict) and
             str(c.get("nodeid") or "").replace("\\", "/") == norm)]
    # Reemplazo por nodeid SIN pérdida (regla común a todos los productores):
    #   SameNodeid ∧ SameRun            => SAME_RUN_SUPERSEDED (se conserva)
    #   SameNodeid ∧ DifferentRun       => PREVIOUS_RUN (ARCHIVE_OLD + INSERT_NEW)
    #   SameNodeid ∧ OldRunUnresolved   => IDENTITY_UNRESOLVED (PRESERVE_OLD +
    #                                      INSERT_NEW; no se reinterpreta como
    #                                      corrida anterior)
    # El caso previo se guarda ÍNTEGRO en diagnostics/test_evidence_history/
    # (creación exclusiva) ANTES de reemplazarlo. No queda vigente para no
    # duplicar file::name en el diario (AMBIGUOUS).
    reemplazados = [c for c in cases if isinstance(c, dict) and
                    str(c.get("nodeid") or "").replace("\\", "/") == norm]
    assert len(otros) + len(reemplazados) == len(cases), "contabilidad de casos rota"
    if reemplazados:
        run_keys = ("github_sha", "github_run_id", "github_run_number")

        def _rid(c):
            for src in (c.get("run_identity"), c, c.get("provenance")):
                if isinstance(src, dict) and any(src.get(k) for k in run_keys):
                    return {k: (src.get(k) or None) for k in run_keys}
            return None

        cur = {k: (ci.get(k) or None) for k in run_keys}
        entradas = []
        for c in reemplazados:
            old = _rid(c)
            motivo = ("IDENTITY_UNRESOLVED" if old is None or not any(cur.values())
                      else "SAME_RUN_SUPERSEDED" if old == cur else "PREVIOUS_RUN")
            entradas.append({"reason": motivo, "old_run_identity": old,
                             "case_sha256": hashlib.sha256(json.dumps(
                                 c, sort_keys=True, ensure_ascii=False,
                                 default=repr).encode("utf-8")).hexdigest(),
                             "case": c})
        destino = path.parent / "test_evidence_history"
        destino.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        stem = Path(file_part).stem
        arch = destino / f"{stamp}_{stem}_{r.get('RUN_ID')}_replaced.json"
        with open(arch, "x", encoding="utf-8") as fh:
            fh.write(json.dumps({"producer": file_part,
                                 "replaced_by_audit_run_id": r.get("RUN_ID"),
                                 "current_run_identity": cur,
                                 "entries": entradas},
                                indent=2, ensure_ascii=False, default=repr))
        case["replaced_previous_archived_at"] = str(arch)
    payload = dict(existing)
    payload.setdefault("schema_version", "1.0")
    payload["generated_utc"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    payload.setdefault("run_identity", ci)
    payload["cases"] = otros + [case]
    tmp = path.with_name(path.name + f".tmp_{os.getpid()}")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=repr),
                   encoding="utf-8")
    os.replace(tmp, path)
    return case


@pytest.fixture(scope="module", autouse=True)
def _registro_persistido_antes_de_asertar(pytestconfig):
    """Auditoría única + persistencia del expediente + informe (una vez).
    Orden: 1) JSON en disco, 2) informe .txt en disco, 3) informe en el log."""
    exp = expediente()
    M.persist_record(exp)                  # la evidencia queda en disco primero
    texto = M.report_resource(exp)         # informe único (incluye RECORD_PATH)
    exp["report_path"] = _persistir_informe_txt(exp, texto)
    if exp["report_path"]:
        texto += f"\nREPORT_PATH={exp['report_path']}"
    exp["report_channel"] = _emitir_al_log(pytestconfig, texto)
    yield exp


def propiedades() -> list:
    """Familias de propiedad presentes en ESTA corrida (base + nuevas)."""
    return M.discovered_property_families(expediente())


def registro() -> dict:
    return expediente()["audit_record"]


def capacidades() -> dict:
    return {c["capability"]: c for c in expediente()["capabilities"]}


def evidencia_de(prop: str) -> dict:
    return (expediente().get("property_evidence") or {}).get(prop) or {}


def ruta_registro() -> str:
    return str(registro().get("RECORD_PATH"))


# -----------------------------------------------------------------------------
# 3. RESOLUCIÓN DEL RECURSO
# -----------------------------------------------------------------------------
def test_01_target_resuelto():
    """El .py debe existir bajo la raíz descubierta; si no, se dice dónde
    se buscó (ROOT / ROOT_SOURCE) en lugar de adivinar."""
    exp = expediente()
    assert exp["status"] != "ABSENT", (
        f"TARGET no encontrado: {TARGET} "
        f"(ROOT={exp.get('root')}, ROOT_SOURCE={exp.get('root_source')}, "
        f"RECORD_PATH={ruta_registro()})")


# -----------------------------------------------------------------------------
# 4. INFORME Y ESTRUCTURA DEL EXPEDIENTE
# -----------------------------------------------------------------------------
def test_02_informe_y_estructura():
    """El informe (ya impreso una vez por el fixture) contiene las secciones
    obligatorias y el encabezado del expediente es el esperado."""
    exp = expediente()
    informe = M.report_resource(exp)
    for seccion in ("RESOURCE FAIL-CLOSED AUDIT", "RESOURCE VERDICT",
                    "ACCOUNTING", "AUDIT RECORD", "RECORD_PATH="):
        assert seccion in informe, seccion
    assert exp["audit_scope"] == "ISOLATED_RESOURCE"
    assert exp["system_perimeter_bypassed_for_measurement"] == "YES"
    assert exp["system_wide_claim"] == "NO"
    assert registro()["SYSTEM_WIDE_CLAIM"] == "NO"
    for c in exp["capabilities"]:
        assert c["role"] in M.ROLES, (c["capability"], c["role"])
        assert c["confidence"] in M.CONFIDENCE, (c["capability"], c["confidence"])


# -----------------------------------------------------------------------------
# 5. VEREDICTO POR PROPIEDAD (AUDITOR vs RECURSO)
# -----------------------------------------------------------------------------
def test_03_veredicto_por_propiedad_no_colapsado():
    """Cada propiedad tiene su propio veredicto y el resumen no las mezcla.
    Las familias base del motor deben estar presentes en lo descubierto."""
    exp = expediente()
    v = exp["verdict"]
    assert "OVERALL_RESOURCE_EVALUATION" in v
    for p in propiedades():
        assert v[p] in M.PROPERTY_RESULTS, (p, v[p])
    if exp["status"] == "OK" and exp["declared_security"]:
        assert set(PROPIEDADES_BASE) <= set(propiedades()), (
            sorted(set(PROPIEDADES_BASE) - set(propiedades())))
        # El resumen multi-propiedad solo existe si hubo inventario que evaluar.
        assert "not collapsed" in v["OVERALL_RESOURCE_EVALUATION"]


def test_04a_auditor_calificado():
    """El INSTRUMENTO está calificado: recurso resuelto o reportado limpio,
    contabilidad sin pérdidas, sin excepciones internas, huella computable."""
    r = registro()
    assert r["AUDITOR_QUALIFICATION"] == "PASS", (
        f"AUDITOR_QUALIFICATION=FAIL; REASONS={r['AUDITOR_QUALIFICATION_REASONS']}; "
        f"SECURITY_VERDICT={r['SECURITY_VERDICT']}; RECORD_PATH={ruta_registro()}")


def test_04b_target_sin_contraejemplo():
    """Falla solo si el RECURSO tiene un contraejemplo real (FAIL). Con el
    auditor no calificado el veredicto queda retenido (NOT_EVALUATED) y lo
    reporta test_04a."""
    r = registro()
    v = expediente()["verdict"]
    fallos = {p: v[p] for p in propiedades() if v.get(p) == "FAIL"}
    assert r["TARGET_SECURITY_RESULT"] != "FAIL" and not fallos, (
        f"AUDITOR_QUALIFICATION={r['AUDITOR_QUALIFICATION']}; "
        f"TARGET_SECURITY_RESULT={r['TARGET_SECURITY_RESULT']}; "
        f"COUNTEREXAMPLE={r['COUNTEREXAMPLE_LIST']}; FAILED_PROPERTIES={fallos}; "
        f"RECORD_PATH={ruta_registro()}")


def test_05_ningun_pass_sin_falsificacion_ejecutada():
    """Ninguna propiedad sale PASS si no se ejecutó al menos una
    falsificación que la respalde (NOT_QUALIFIED en su lugar)."""
    exp = expediente()
    assert M.verdict_respects_evidence(exp) == []
    for p in propiedades():
        if evidencia_de(p).get("falsifications_executed", 0) == 0:
            assert exp["verdict"][p] != "PASS", (p, exp["verdict"][p])
    # TARGET_SECURITY_RESULT=PASS exige que TODA propiedad aplicable sea PASS calificada.
    if registro()["TARGET_SECURITY_RESULT"] == "PASS":
        aplicables = [p for p in propiedades() if exp["verdict"][p] != "NOT_APPLICABLE"]
        assert all(exp["verdict"][p] == "PASS" for p in aplicables), aplicables


def test_06_sin_declaracion_no_hay_pass():
    """SEGURIDAD no concede PASS y su ausencia no impide medir: sin
    declaración, DECLARATION_TRACEABILITY no puede salir PASS y todo PASS
    medido exige falsificación ejecutada (test_05)."""
    exp = expediente()
    if exp["declared_security"]:
        return
    assert exp["verdict"].get("DECLARATION_TRACEABILITY") != "PASS"
    assert M.verdict_respects_evidence(exp) == []


def test_07_state_transition_coherente_con_mapa():
    """STATE_TRANSITION es NOT_APPLICABLE solo si no se descubrió mapa de
    transiciones; si hay mapa, debe haberse intentado falsificar."""
    exp = expediente()
    sm = exp.get("state_machine") or {}
    st = exp["verdict"]["STATE_TRANSITION"]
    if sm.get("maps"):
        assert st != "NOT_APPLICABLE", (st, sm)
    if st == "PASS":
        assert sm.get("rejected") and sm.get("rejection"), sm


# -----------------------------------------------------------------------------
# 6. DESCRIPCIÓN ≠ APLICABILIDAD ≠ MEDICIÓN ≠ VEREDICTO (el rol no decide nada)
#    Reglas generales: valen para cualquier recurso sin nombrar funciones.
# -----------------------------------------------------------------------------
def test_07b_semantica_efectiva_es_la_declarada():
    """El auditor no fabrica semántica: role/property efectivos salen de SEGURIDAD.
    La derivación AST es únicamente un plano independiente de contraste."""
    for n, c in capacidades().items():
        decl = c.get("declared") or {}
        if not decl:
            assert c["role"] == "UNKNOWN" and c["property"] == "NOT_RESOLVED", (n, c)
            continue
        if decl.get("role") is not None:
            assert c["role"] == str(decl["role"]).upper(), (n, decl, c["role"])
        if decl.get("property") is not None:
            assert c["property"] == str(decl["property"]).upper(), (n, decl, c["property"])


def test_08_toda_capacidad_recibe_campana():
    """Toda capacidad resoluble recibe intento de campaña por propiedad medida,
    sea cual sea su ROLE; ESTABLISHED exige testigo positivo + falsificación."""
    for n, c in capacidades().items():
        for p, m in c["measurement"].items():
            assert p in c["campaigns"], (n, p)
            if m["applicability"] == "ESTABLISHED":
                assert m["falsifications_executed"] > 0, (n, p, m)
                assert m["verdict"] != "NOT_RESOLVED", (n, p, m)


def test_09_sin_testigo_positivo_no_hay_pass_ni_fail():
    """Sin control positivo válido (ni efecto protegido observado) la
    capacidad queda NOT_QUALIFIED/NOT_RESOLVED, nunca PASS/FAIL."""
    for n, c in capacidades().items():
        for p, m in c["measurement"].items():
            if not m["in_tested_domain"]:
                assert m["verdict"] in ("NOT_QUALIFIED", "NOT_RESOLVED", "NOT_APPLICABLE"), (n, p, m)
                if m["verdict"] == "NOT_APPLICABLE":
                    assert m["applicability"] == "OUT_OF_SCOPE", (n, p, m)
                assert m["counterexamples"] == 0, (n, p, m)


def test_10_veredicto_de_propiedad_sale_de_la_medicion():
    """El veredicto por propiedad medida es la agregación de las capacidades
    del dominio probado (nunca de un subconjunto elegido por ROLE)."""
    exp = expediente()
    for p in M.MEASURED_PROPERTIES:
        if p not in exp["verdict"] or not capacidades():
            continue
        dom = [c["measurement"][p]["verdict"] for c in capacidades().values()
               if c["measurement"][p]["in_tested_domain"]]
        if dom:
            assert exp["verdict"][p] in (M._agg(dom), "NOT_QUALIFIED"), (p, dom)


def test_11_productor_derivado_existe_y_es_estructural():
    """Un enlace producer DERIVED pertenece al plano estructural (tipo de
    retorno ↔ tipo de `pre`) y se elige sin consultar ningún ROLE: el
    productor existe, es otra capacidad y la medición lo usa como fuente."""
    caps = capacidades()
    for n, c in caps.items():
        prod = c.get("producer")
        if not prod:
            continue
        assert prod in caps and prod != n, (n, prod)
        assert c["confidence_fields"].get("producer") == "DERIVED", (n, c["confidence_fields"])


def test_12_sin_divergencia_declarado_vs_derivado():
    """Lo declarado en SEGURIDAD y lo derivado del código no pueden
    contradecirse (SEMANTIC_DIVERGENCE). El mensaje trae DECLARED / DERIVED /
    OBSERVED y la ruta del registro ya persistido."""
    div = [n for n, c in capacidades().items()
           if c.get("semantic_alignment") == "SEMANTIC_DIVERGENCE"]
    detalle = [f"{d['capability']}: DECLARED={d['DECLARED']} DERIVED={d['DERIVED']} "
               f"OBSERVED={d['OBSERVED']}" for d in registro()["SEMANTIC_DIVERGENCES"]]
    assert not div and not detalle, (
        f"divergencia semántica en: {div}; {detalle}; RECORD_PATH={ruta_registro()}")


# -----------------------------------------------------------------------------
# 7. EQUIVALENCIA WRAPPER ↔ MOTOR
# -----------------------------------------------------------------------------
def test_13_equivalencia_wrapper_motor():
    """La huella semántica es la misma por este wrapper y llamando
    directamente al motor, aunque cada corrida tenga RUN_ID distinto."""
    a = M.audit_resource(TARGET)
    b = M.audit_resource(Path(TARGET))
    assert M.semantic_fingerprint(a) == M.semantic_fingerprint(b)
    assert M.semantic_fingerprint(a) == registro()["SEMANTIC_FINGERPRINT"]
    assert a["audit_record"]["RUN_ID"] != b["audit_record"]["RUN_ID"]


# -----------------------------------------------------------------------------
# 8. ANTI-HARDCODE DEL MOTOR
#    Los nombres vetados se descubren del propio TARGET (capacidades y
#    declaración); no se escriben a mano.
# -----------------------------------------------------------------------------
def test_14_motor_sin_nombres_del_recurso():
    exp = expediente()
    vetados = set(capacidades())
    if exp.get("declaration_id"):
        vetados.add(exp["declaration_id"])
    # Solo la sección M (motor): la línea TARGET y estas pruebas no cuentan.
    _arbol_motor = ast.parse(M._engine_source())
    usados = set()
    for n in ast.walk(_arbol_motor):
        if isinstance(n, ast.Name):
            usados.add(n.id)
        elif isinstance(n, ast.Attribute):
            usados.add(n.attr)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            usados.add(n.name)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            usados.add(n.value)
    assert not (vetados & usados), f"nombres del recurso en el motor: {sorted(vetados & usados)}"


# -----------------------------------------------------------------------------
# 9. REGISTRO DE AUDITORÍA, IDENTIDAD DE CORRIDA Y CONTABILIDAD
# -----------------------------------------------------------------------------
def test_15_registro_persistido():
    """El JSON existe, carga, tiene todas las secciones/campos, está en el
    index.jsonl y sus sha256 coinciden con los bytes reales."""
    exp, r = expediente(), registro()
    ruta = Path(r["RECORD_PATH"])
    assert ruta.is_file(), ruta
    doc = json.loads(ruta.read_text(encoding="utf-8"))
    faltan = [s for s in M.RECORD_SECTIONS if s not in doc]
    assert not faltan, f"secciones ausentes: {faltan}"
    faltan = [f for f in M.AUDIT_RECORD_FIELDS if f not in doc["AUDIT_RECORD"]]
    assert not faltan, f"campos ausentes: {faltan}"
    assert doc["AUDIT_RECORD"]["RUN_ID"] == r["RUN_ID"]
    assert doc["AUDIT_RECORD"]["RECORD_PATH"] == str(ruta)
    indice = [json.loads(x) for x in
              (ruta.parent / "index.jsonl").read_text(encoding="utf-8").splitlines() if x]
    linea = [i for i in indice if i["run_id"] == r["RUN_ID"]]
    assert len(linea) == 1 and linea[0]["record"] == str(ruta), linea
    objetivo = Path(exp["root"]) / TARGET
    esperado = (hashlib.sha256(objetivo.read_bytes()).hexdigest()
                if objetivo.is_file() else None)
    assert r["TARGET_SHA256"] == esperado == linea[0]["target_sha256"]
    motor = hashlib.sha256(Path(M.__file__).read_bytes()).hexdigest()
    assert r["AUDITOR_SHA256"] == motor == linea[0]["auditor_sha256"]
    assert r["AUDITOR"] == Path(M.__file__).name and r["SPEC"] == M.SPEC_VERSION


def test_16_identidad_de_corrida():
    """RUN_IDENTITY = sha256(TARGET_SHA256|AUDITOR_SHA256|SPEC|RUN_ID)."""
    r = registro()
    recalculada = hashlib.sha256(
        f"{r['TARGET_SHA256']}|{r['AUDITOR_SHA256']}|{r['SPEC']}|{r['RUN_ID']}"
        .encode("utf-8")).hexdigest()
    assert r["RUN_IDENTITY"] == recalculada


def test_17_contabilidad_cero_perdida():
    """LostEvidence=0: nada descubierto, generado o aplicable queda sin
    contabilizar, y las tres ecuaciones cuadran."""
    a = expediente()["accounting"]
    sin_contar = {k: v for k, v in a.items() if k.endswith("_unaccounted") and v != 0}
    assert not sin_contar, f"{sin_contar}; RECORD_PATH={ruta_registro()}"
    assert a["exceptions_unreconciled"] == 0, a
    assert a["capabilities_discovered"] == (a["capabilities_classified"]
                                            + a["capabilities_unresolved"])
    assert a["cases_generated"] == (a["cases_executed"]
                                    + a["cases_not_executed_accounted"])
    assert a["properties_applicable"] == (a["properties_qualified"]
                                          + a["properties_not_qualified"])
    assert a["capabilities_equation_holds"] and a["cases_equation_holds"] \
        and a["properties_equation_holds"], a




def test_18_identidad_plantilla_y_motor():
    """Recalcula AUDITOR_TEMPLATE_SHA256 y AUDITOR_ENGINE_SHA256 de forma
    independiente (sin usar los helpers del motor) y los compara con el
    registro y el index.jsonl. Así se demuestra, copia contra copia, que
    solo cambió TARGET y que el motor es el mismo."""
    r = registro()
    txt = Path(M.__file__).read_text(encoding="utf-8")
    ls = txt.splitlines()
    t_idx = [i for i, l in enumerate(ls) if l.startswith("TARGET =")]
    assert len(t_idx) == 1, f"línea TARGET no única: {t_idx}"
    plantilla = hashlib.sha256(
        "\n".join(ls[:t_idx[0]] + ls[t_idx[0] + 1:]).encode("utf-8")).hexdigest()
    ini = [i for i, l in enumerate(ls) if l.startswith("# M. MOTOR UHCR")]
    fin = [i for i, l in enumerate(ls) if l.startswith("# PRUEBAS DEL RECURSO")]
    assert len(ini) == 1 and len(fin) == 1 and ini[0] < fin[0], (ini, fin)
    a = sum(len(l) + 1 for l in ls[:ini[0]])
    b = sum(len(l) + 1 for l in ls[:fin[0]])
    motor = hashlib.sha256(txt[a:b].encode("utf-8")).hexdigest()
    assert r["AUDITOR_TEMPLATE_SHA256"] == plantilla, "plantilla: hash no coincide"
    assert r["AUDITOR_ENGINE_SHA256"] == motor, "motor: hash no coincide"
    indice = [json.loads(x) for x in
              (Path(r["RECORD_PATH"]).parent / "index.jsonl").read_text(
                  encoding="utf-8").splitlines() if x]
    linea = [i for i in indice if i["run_id"] == r["RUN_ID"]]
    assert linea[0]["auditor_template_sha256"] == plantilla
    assert linea[0]["auditor_engine_sha256"] == motor


# -----------------------------------------------------------------------------
# 19. EL INFORME SALE EN EL LOG Y QUEDA EN DISCO (aunque todo pase)
# -----------------------------------------------------------------------------
def test_19_informe_visible_y_persistido():
    exp = expediente()
    assert exp.get("report_channel") in ("PYTEST_LOG_UNCAPTURED", "STDOUT")
    assert exp.get("report_path"), "el informe .txt no se persistió"
    txt = Path(exp["report_path"]).read_text(encoding="utf-8")
    r = registro()
    assert f"RUN_ID={r['RUN_ID']}" in txt
    for k in M.AUDIT_RECORD_FIELDS:
        if k != "SPEC_EVOLUTION":
            assert f"{k}=" in txt, f"campo ausente del informe: {k}"
    for fam in propiedades():
        assert f"{fam}=" in txt, f"propiedad ausente del informe: {fam}"

# -----------------------------------------------------------------------------
# 99. TRAZA PARA EL OMEGA DIARY
#    Publica el informe completo en diagnostics/test_evidence.json con las
#    claves que el diario usa para cruzar con el JUnit, y verifica releyendo
#    el archivo que el caso quedó cruzable (único por file::name y por
#    classname::name) y que el informe publicado es el informe de ESTA corrida.
# -----------------------------------------------------------------------------
def test_99_traza(request):
    exp = expediente()
    texto = M.report_resource(exp)
    if exp.get("report_path"):
        texto += f"\nREPORT_PATH={exp['report_path']}"
    caso = _publish_diary(exp, request.node.nodeid, request.node.name, texto)
    print("\n" + texto + "\n")
    data = json.loads(_diary_evidence_path(exp).read_text(encoding="utf-8"))
    assert isinstance(data, dict) and isinstance(data.get("cases"), list)
    for clave in ("file", "classname", "name"):
        assert caso[clave], f"clave de cruce vacía: {clave}"
    por_file = [c for c in data["cases"] if isinstance(c, dict)
                and c.get("file") == caso["file"] and c.get("name") == caso["name"]]
    por_clase = [c for c in data["cases"] if isinstance(c, dict)
                 and c.get("classname") == caso["classname"] and c.get("name") == caso["name"]]
    assert len(por_file) == 1 and len(por_clase) == 1, "caso no cruzable o ambiguo"
    publicado = por_file[0]
    assert publicado["audit_run_id"] == registro()["RUN_ID"]
    assert publicado["report"] == texto
    assert f"RUN_ID={registro()['RUN_ID']}" in publicado["report"]

# =============================================================================
# E. EJECUCIÓN DIRECTA
# =============================================================================
if __name__ == "__main__":
    t = sys.argv[1] if len(sys.argv) > 1 else TARGET
    if not t:
        print("usage: python3 test_<recurso>_failclosed.py <relative/target.py>")
        sys.exit(2)
    e = audit_resource(t)
    print(report_resource(e))
    print("SEMANTIC_FINGERPRINT=" + semantic_fingerprint(e))
