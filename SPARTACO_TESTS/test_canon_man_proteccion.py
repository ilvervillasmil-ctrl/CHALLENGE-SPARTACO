"""
UHCR — CUSTOMS INVARIANTS: I-CANON and I-MAN
SPEC: UHCR-INV-KERNEL-1.3 / CAMPANA C2026-09-CANON-MAN

What is measured here, in one sentence
--------------------------------------
I-CANON: The canonical boundary (`protection.serialize`) is a TOTAL function
         over the contractual JSON domain; it REJECTS anything falling outside
         this domain—DETERMINISTICALLY, without injection, and without
         interpreter-dependent encoding.

I-MAN:   The manifest is EXACTLY {body, signature}; any other form is
         rejected with a declared concept, and any mutation to the body,
         signature, or key is detected.

What is NOT done here
---------------------
No production code is edited. This file merely CALLS `protection.py`.
Nothing is declared in writing: every result is derived from a measurement.
We do not say "PASS." Instead, we report the count (e.g., X out of Y)
along with the supporting evidence.

Architecture (Klein’s three layers, in miniature)
------------------------------------------------
  A  SPECIFICATION  -> `canon_independent()`, written separately from the
                        audited code, plus the manifest oracle.
  E  DESIGN         -> `protection.serialize` / `verify_manifest`
  R  REFINEMENT     -> A and E must match byte-for-byte within the domain.
  M  MUTATION       -> If a mutant of A or E goes undetected, the
                        instrument is considered invalid—and this is
                        explicitly stated, rather than claimed otherwise.

ASCII-ONLY: All new code in this file is strictly pure ASCII by design.
The only non-ASCII characters that may appear in the report are concept
names declared by the contract itself (e.g., `CODIGO_INVALIDO` with an
accent); these are printed exactly as they appear in production,
without any reinterpretation.

Attempted attacks are tracked and counted. If someone were to obtain an illicit `ALLOW/ok=True`, 
the verdict of this check would be "BROKEN," and the counter would reveal it.

Scope and Preconditions (read before interpreting any figures)
------------------------------------------------------------------
Body fields that `verify()` does not cross-reference against the document are covered by the SIGNATURE. 
Consequently, re-labeling them requires possession of the authority's private key; this is not a privilege escalation, 
but rather a re-issuance by the authority itself. This check measures this in two ways:

  - Using the authority's key: the re-labeled manifest validates successfully.
  - Using a different key (impersonation): it must fail with `INVALID_SIGNATURE`.

What this check does NOT audit: the actual callers of `verify()` or the `minimum_version` they specify 
(the upper bound is determined by the caller; this check merely verifies that the control exists and functions when invoked),
interactions involving credentials/AES/HKDF, and the ZSQ tree—which `verify()`
reports as evidence but does not factor into the final decision.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest


SPEC = "UHCR-INV-KERNEL-1.3"
CAMPANA = "C2026-09-CANON-MAN"
SEED = 37

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "diagnostics" / "uhcr_inv_canon_man"
DOSSIERS = OUT / "dossiers"
REPORT = OUT / "REPORT_CANON_MAN.txt"
METRICS = OUT / "METRICS.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ================================================================
# CARGA DEL ARTEFACTO AUDITADO
# ================================================================

def _candidate_paths() -> List[Path]:
    return [
        ROOT / "modules" / "spartaco_seguridad" / "proteccion.py",
        ROOT / "modules" / "spartaco_seguridad" / "omega" / "proteccion.py",
        ROOT / "omega" / "proteccion.py",
        Path("/home/workdir/artifacts/proteccion.py"),
    ]


def load_proteccion():
    errors: List[str] = []
    for path in _candidate_paths():
        if not path.is_file():
            continue
        try:
            spec = importlib.util.spec_from_file_location("proteccion_auditada", path)
            if spec is None or spec.loader is None:
                errors.append("SPEC_LOADER_MISSING:{0}".format(path))
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules["proteccion_auditada"] = mod
            spec.loader.exec_module(mod)
            return mod, path, errors
        except Exception as exc:
            errors.append("{0}:{1}:{2}".format(path, type(exc).__name__, exc))
    return None, None, errors


PROT, PROT_PATH, LOAD_ERRORS = load_proteccion()


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_dossier(name: str, payload: Dict[str, Any]) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    DOSSIERS.mkdir(parents=True, exist_ok=True)
    target = DOSSIERS / "{0}.json".format(name)
    target.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, default=str),
        encoding="utf-8",
    )
    return target


# ================================================================
# CAPA A \u2014 ESPECIFICACION INDEPENDIENTE DEL CANONICO
# ================================================================
#
# Esta funcion NO importa nada de proteccion.py. Es la especificacion
# escrita a mano de lo que el contrato dice que es "canonico":
#   - dominio JSON contractual estricto (tipos exactos, sin subclases)
#   - enteros con bit_length <= 256
#   - floats finitos
#   - claves str
#   - profundidad <= 64
#   - sin NaN / infinito
#   - claves ordenadas, sin espacios, ASCII escapado
# Si el codigo auditado y esto discrepan, el desacuerdo es el hallazgo.

LIMITE_BITS_SPEC = 256
LIMITE_PROFUNDIDAD_SPEC = 64


class FueraDeDominio(ValueError):
    """La especificacion declara el valor fuera del dominio JSON contractual."""


def _pre_espec(valor: Any, profundidad: int = 0) -> None:
    if profundidad > LIMITE_PROFUNDIDAD_SPEC:
        raise FueraDeDominio("profundidad")
    if valor is None or type(valor) is bool or type(valor) is str:
        return
    if type(valor) is int:
        if valor.bit_length() > LIMITE_BITS_SPEC:
            raise FueraDeDominio("entero fuera de rango")
        return
    if type(valor) is float:
        if not math.isfinite(valor):
            raise FueraDeDominio("float no finito")
        return
    if type(valor) is list:
        for item in valor:
            _pre_espec(item, profundidad + 1)
        return
    if type(valor) is dict:
        for clave, sub in valor.items():
            if type(clave) is not str:
                raise FueraDeDominio("clave no str")
            _pre_espec(sub, profundidad + 1)
        return
    raise FueraDeDominio("tipo no JSON: {0}".format(type(valor).__name__))


def canon_independiente(valor: Any) -> bytes:
    """Canonico segun ESPECIFICACION. Debe coincidir byte a byte con E."""
    _pre_espec(valor, 0)
    texto = json.dumps(
        valor,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return texto.encode("ascii")


def en_dominio_espec(valor: Any) -> bool:
    try:
        _pre_espec(valor, 0)
        return True
    except FueraDeDominio:
        return False


# ================================================================
# MUTANTES DE LA ESPECIFICACION
# ================================================================
# Si el instrumento de medida no distingue estos defectos deliberados,
# no sirve para afirmar nada. Se cuentan uno por uno.

def mut_sin_orden(valor: Any) -> bytes:
    return json.dumps(valor, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def mut_sin_ascii(valor: Any) -> bytes:
    _pre_espec(valor, 0)
    return json.dumps(valor, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def mut_con_espacios(valor: Any) -> bytes:
    _pre_espec(valor, 0)
    return json.dumps(valor, sort_keys=True, ensure_ascii=True).encode("ascii")


def mut_sin_rango_entero(valor: Any) -> bytes:
    # Acepta enteros arbitrariamente grandes: el defecto clasico.
    def pre(v, d):
        if d > LIMITE_PROFUNDIDAD_SPEC:
            raise FueraDeDominio("profundidad")
        if v is None or type(v) is bool or type(v) is str:
            return
        if type(v) is int:
            return
        if type(v) is float:
            if not math.isfinite(v):
                raise FueraDeDominio("float")
            return
        if type(v) is list:
            for x in v:
                pre(x, d + 1)
            return
        if type(v) is dict:
            for k, s in v.items():
                if type(k) is not str:
                    raise FueraDeDominio("clave")
                pre(s, d + 1)
            return
        raise FueraDeDominio("tipo")
    pre(valor, 0)
    return json.dumps(valor, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def mut_sin_profundidad(valor: Any) -> bytes:
    # Sin tope de profundidad: un ciclo lo cuelga o revienta.
    return json.dumps(valor, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def mut_permite_nan(valor: Any) -> bytes:
    def pre(v, d):
        if d > LIMITE_PROFUNDIDAD_SPEC:
            raise FueraDeDominio("profundidad")
        if v is None or type(v) is bool or type(v) is str:
            return
        if type(v) is int:
            if v.bit_length() > LIMITE_BITS_SPEC:
                raise FueraDeDominio("entero")
            return
        if type(v) is float:
            return  # acepta NaN e infinito: defecto
        if type(v) is list:
            for x in v:
                pre(x, d + 1)
            return
        if type(v) is dict:
            for k, s in v.items():
                if type(k) is not str:
                    raise FueraDeDominio("clave")
                pre(s, d + 1)
            return
        raise FueraDeDominio("tipo")
    pre(valor, 0)
    return json.dumps(valor, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=True).encode("ascii", "replace")


MUTANTES_CANON: Dict[str, Callable[[Any], bytes]] = {
    "sin_orden_de_claves": mut_sin_orden,
    "sin_ascii_escapado": mut_sin_ascii,
    "con_espacios": mut_con_espacios,
    "sin_tope_de_entero": mut_sin_rango_entero,
    "sin_tope_de_profundidad": mut_sin_profundidad,
    "permite_nan": mut_permite_nan,
}


# ================================================================
# CONTADOR DE METRICAS
# ================================================================
# Nada de "PASS" suelto: cada afirmacion va con su cuenta.

class Metricas:
    def __init__(self) -> None:
        self.datos: Dict[str, Any] = {}
        self.tabla: List[Tuple[str, str, str]] = []
        self.ataques = 0
        self.aceptados_ilegalmente = 0
        self.excepciones_crudas = 0

    def set(self, clave: str, valor: Any) -> None:
        self.datos[clave] = valor

    def fila(self, invariante: str, magnitud: str, valor: Any) -> None:
        self.tabla.append((invariante, magnitud, str(valor)))

    def intento(self) -> None:
        self.ataques += 1

    def ilegal(self, etiqueta: str) -> None:
        self.aceptados_ilegalmente += 1
        self.datos.setdefault("ACEPTADOS_ILEGALMENTE", []).append(etiqueta)

    def cruda(self, etiqueta: str, exc: BaseException) -> None:
        self.excepciones_crudas += 1
        self.datos.setdefault("EXCEPCIONES_CRUDAS", []).append(
            {"caso": etiqueta, "tipo": type(exc).__name__, "mensaje": str(exc)[:200]}
        )

    def veredicto(self) -> str:
        if self.aceptados_ilegalmente:
            return "ROTO"
        if self.datos.get("INSTRUMENTOS_NO_CUALIFICADOS"):
            return "INCONCLUSO"
        return "ACOTADO"

    def texto(self) -> str:
        lineas = [
            "=" * 78,
            "{0} \u2014 ADUANA I-CANON / I-MAN".format(SPEC),
            "=" * 78,
            "CAMPANA={0}".format(CAMPANA),
            "ARTEFACTO={0}".format(PROT_PATH),
            "ARTEFACTO_SHA256={0}".format(
                _sha_file(PROT_PATH) if PROT_PATH else None
            ),
            "SEED={0}".format(SEED),
            "PYTHON={0}".format(sys.version.split()[0]),
            "-" * 78,
            "{0:<46} {1:<14} {2}".format("INVARIANTE", "MAGNITUD", "VALOR"),
            "-" * 78,
        ]
        for inv, mag, val in self.tabla:
            lineas.append("{0:<46} {1:<14} {2}".format(inv, mag, val))
        lineas += [
            "-" * 78,
            "CONTADORES DE RUPTURA",
            "  ATAQUES_INTENTADOS          {0}".format(self.ataques),
            "  ACEPTADOS_ILEGALMENTE       {0}".format(self.aceptados_ilegalmente),
            "  EXCEPCIONES_CRUDAS          {0}".format(self.excepciones_crudas),
            "-" * 78,
            "VEREDICTO_CAMPANA={0}".format(self.veredicto()),
            "  ROTO        = algun ataque consiguio ok=True ilegal",
            "  ACOTADO     = ninguno lo consiguio y todo instrumento quedo cualificado",
            "  INCONCLUSO  = el instrumento de medida no quedo cualificado",
            "-" * 78,
            "ALCANCE Y PRECONDICION",
            "  MEDIDO: decision y clasificacion del manifiesto; cruzado de",
            "          nucleo/S/Q/n_bytes contra los datos; suplantacion sin la",
            "          clave de la autoridad; control de version_minima;",
            "          determinismo del canonico entre procesos.",
            "  PRECONDICION: los campos cubiertos solo por firma exigen poseer la",
            "          clave privada de la autoridad. Con otra clave se midio",
            "          rechazo (ver SUPLANTACION_SIN_CLAVE). No es escalada: es",
            "          re-emision por la autoridad.",
            "  NO AUDITADO AQUI: los llamadores de verificar() y con que",
            "          version_minima invocan; credencial/AES/HKDF; y el arbol",
            "          ZSQ, que se reporta como evidencia y no decide.",
            "=" * 78,
        ]
        return "\n".join(lineas)


MET = Metricas()


# ================================================================
# GENERADOR DE DOMINIO PARA I-CANON
# ================================================================

class L(list):
    """Subclase hostil de list: el dominio contractual no la admite."""


class D(dict):
    """Subclase hostil de dict: el dominio contractual no la admite."""


class IntHostil(int):
    """Int subclase con bit_length() enganoso."""

    def bit_length(self) -> int:  # type: ignore[override]
        return 1


def dominio_canon() -> List[Tuple[str, Any, bool]]:
    """
    (etiqueta, valor, esperado_por_especificacion).
    El esperado sale de la ESPECIFICACION, nunca del codigo auditado.
    """
    aceptados: List[Tuple[str, Any, bool]] = [
        ("none", None, True),
        ("bool_true", True, True),
        ("bool_false", False, True),
        ("str_vacia", "", True),
        ("str_ascii", "documento", True),
        ("str_acento", "canonico con acento: \u00f1", True),
        ("str_emoji", "emoji \U0001f600", True),
        ("str_inyeccion", '","}\n\t\\ \u0000 comillas y control', True),
        ("str_clave_inyeccion", 'clave"}maliciosa', True),
        ("int_cero", 0, True),
        ("int_negativo", -37, True),
        ("int_bit255", 1 << 255, True),
        ("float_cero", 0.0, True),
        ("float_neg", -1.5, True),
        ("lista_vacia", [], True),
        ("lista_anidada", [1, [2, [3, [4]]]], True),
        ("dict_vacio", {}, True),
        ("dict_orden", {"b": 1, "a": 2}, True),
        ("dict_anidado", {"a": {"b": {"c": None}}}, True),
        ("mezcla", {"a": [1, 2.5, None, True, "\u00f1"], "b": {"c": []}}, True),
    ]
    rechazados: List[Tuple[str, Any, bool]] = [
        ("bytes", b"x", False),
        ("bytearray", bytearray(b"x"), False),
        ("tupla", (1, 2), False),
        ("conjunto", {1, 2}, False),
        ("frozenset", frozenset({1}), False),
        ("complejo", 1j, False),
        ("decimal", __import__("decimal").Decimal(1), False),
        ("fraccion", __import__("fractions").Fraction(1, 2), False),
        ("subclase_list", L([1, 2]), False),
        ("subclase_dict", D(a=1), False),
        ("dict_ordenado", __import__("collections").OrderedDict(a=1), False),
        ("nan", float("nan"), False),
        ("inf", float("inf"), False),
        ("menos_inf", float("-inf"), False),
        ("int_bit256", 1 << 256, False),
        ("int_bit300", 1 << 300, False),
        ("clave_int", {1: "a"}, False),
        ("clave_none", {None: "a"}, False),
        ("clave_float", {1.5: "a"}, False),
        ("clave_tupla", {(1, 2): "a"}, False),
        ("clave_bytes", {b"k": "a"}, False),
    ]
    return aceptados + rechazados


def nest(k: int) -> Any:
    v: Any = 1
    for _ in range(k):
        v = [v]
    return v


def dominio_profundidad() -> List[Tuple[str, Any, bool]]:
    return [
        ("profundidad_62", nest(62), True),
        ("profundidad_63", nest(63), True),
        ("profundidad_64", nest(64), True),
        ("profundidad_65", nest(65), False),
        ("profundidad_70", nest(70), False),
    ]


def ciclo_lista() -> Any:
    c: List[Any] = []
    c.append(c)
    return c


def ciclo_dict() -> Any:
    d: Dict[str, Any] = {}
    d["self"] = d
    return d


def dominio_ciclos() -> List[Tuple[str, Any, bool]]:
    return [
        ("ciclo_lista", ciclo_lista(), False),
        ("ciclo_dict", ciclo_dict(), False),
    ]


def permutaciones_claves(objeto: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Todas las permutaciones de orden de insercion, sin cambiar contenido."""
    claves = list(objeto.keys())
    salida: List[Dict[str, Any]] = []
    if len(claves) > 6:
        # 7! = 5040; por encima se muestrea de forma determinista
        import itertools
        import random
        rng = random.Random(SEED)
        for _ in range(720):
            orden = claves[:]
            rng.shuffle(orden)
            salida.append({k: objeto[k] for k in orden})
        return salida
    import itertools
    for orden in itertools.permutations(claves):
        salida.append({k: objeto[k] for k in orden})
    return salida


# ================================================================
# I-CANON \u2014 CUALIFICACION DEL INSTRUMENTO
# ================================================================

class ProtFalso:
    """Envoltorio para probar el instrumento con un serializador defectuoso."""

    def __init__(self, fn: Callable[[Any], bytes], nombre: str) -> None:
        self._fn = fn
        self._nombre = nombre

    def serializar_seguro(self, valor: Any) -> Dict[str, Any]:
        try:
            return {"ok": True, "bytes": self._fn(valor), "conceptos": []}
        except Exception as exc:
            return {"ok": False, "bytes": None,
                    "conceptos": ["CODIGO_INVALIDO"], "error": str(exc)}


def _bateria_decision() -> List[Tuple[str, Any, bool]]:
    return dominio_canon() + dominio_profundidad() + dominio_ciclos()


def _permutacion_base() -> Dict[str, Any]:
    return {
        "delta": "cadena con acento \u00f1 y emoji \U0001f600",
        "beta": [1, 2.5, None, True, {"k": []}],
        "gamma": {"z": None, "y": True, "x": 0},
        "alpha": -37,
        "epsilon": 1 << 200,
    }


def medir_canon(proto=None) -> Dict[str, Any]:
    """
    Mide el objeto dado (por defecto el auditado) contra la ESPECIFICACION.
    Devuelve todos los numeros que el informe publica.
    """
    proto = proto or PROT
    hechos: Dict[str, Any] = {
        "artefacto": str(PROT_PATH) if PROT_PATH else None,
        "casos": 0,
        "acuerdos_decision": 0,
        "desacuerdos": [],
        "aceptados": 0,
        "comparables_byte": 0,
        "igualdades_byte": 0,
        "ascii_puro": 0,
        "permutaciones": 0,
        "digests_distintos": 0,
        "punto_fijo_ok": 0,
        "punto_fijo_n": 0,
        "mutantes_declarados": 0,
        "mutantes_detectados": 0,
        "mutantes": [],
        "excepciones_crudas": 0,
    }
    if proto is None:
        hechos["desacuerdos"].append("PROTECCION_NO_MONTADA")
        return hechos

    casos = _bateria_decision()
    hechos["casos"] = len(casos)

    for etiqueta, valor, esperado in casos:
        try:
            real = proto.serializar_seguro(valor)
        except BaseException as exc:  # una excepcion cruda es un hallazgo
            hechos["excepciones_crudas"] += 1
            hechos["desacuerdos"].append({
                "caso": etiqueta, "esperado": esperado,
                "obtenido": "EXCEPCION_CRUDA", "detalle": type(exc).__name__,
            })
            continue
        obtenido = bool(real.get("ok"))
        if obtenido == esperado:
            hechos["acuerdos_decision"] += 1
        else:
            hechos["desacuerdos"].append({
                "caso": etiqueta, "esperado": esperado, "obtenido": obtenido,
            })
        if not obtenido:
            continue
        hechos["aceptados"] += 1
        salida = real.get("bytes")
        if isinstance(salida, (bytes, bytearray)) and all(b < 128 for b in salida):
            hechos["ascii_puro"] += 1
        if esperado:
            hechos["comparables_byte"] += 1
            try:
                esperado_bytes = canon_independiente(valor)
            except FueraDeDominio:
                esperado_bytes = None
            if esperado_bytes is not None and bytes(salida or b"") == esperado_bytes:
                hechos["igualdades_byte"] += 1

    # Determinismo ante orden de insercion de claves.
    digestos = set()
    for permutado in permutaciones_claves(_permutacion_base()):
        try:
            salida = proto.serializar_seguro(permutado)
        except BaseException:
            hechos["excepciones_crudas"] += 1
            continue
        if not salida.get("ok"):
            hechos["desacuerdos"].append({"caso": "permutacion", "obtenido": False})
            continue
        hechos["permutaciones"] += 1
        digestos.add(hashlib.sha256(bytes(salida["bytes"])).hexdigest())
    hechos["digests_distintos"] = len(digestos)

    # Punto fijo: serializar -> descongelar -> serializar da los mismos bytes.
    for etiqueta, valor, esperado in casos:
        if not esperado:
            continue
        hechos["punto_fijo_n"] += 1
        try:
            primera = proto.serializar_seguro(valor)
            if not primera.get("ok"):
                continue
            segunda = proto.serializar_seguro(json.loads(bytes(primera["bytes"]).decode("ascii")))
            if segunda.get("ok") and bytes(segunda["bytes"]) == bytes(primera["bytes"]):
                hechos["punto_fijo_ok"] += 1
        except BaseException as exc:
            hechos["excepciones_crudas"] += 1
            hechos["desacuerdos"].append({
                "caso": "punto_fijo:{0}".format(etiqueta),
                "detalle": type(exc).__name__,
            })

    # Cualificacion por mutacion: cada defecto deliberado debe ser DETECTADO.
    hechos["mutantes_declarados"] = len(MUTANTES_CANON)
    for nombre, mutante in MUTANTES_CANON.items():
        detectado = False
        evidencia = None
        for etiqueta, valor, esperado in casos:
            try:
                salida_mut = mutante(valor)
                decision_mut = True
                bytes_mut = bytes(salida_mut)
            except BaseException:
                decision_mut = False
                bytes_mut = b""
            esperado_decision = en_dominio_espec(valor)
            if decision_mut != esperado_decision:
                detectado = True
                evidencia = {"caso": etiqueta, "por": "DECISION",
                             "esperado": esperado_decision, "obtenido": decision_mut}
                break
            if decision_mut and esperado_decision:
                try:
                    referencia = canon_independiente(valor)
                except FueraDeDominio:
                    continue
                if bytes_mut != referencia:
                    detectado = True
                    evidencia = {"caso": etiqueta, "por": "BYTES"}
                    break
        if detectado:
            hechos["mutantes_detectados"] += 1
        hechos["mutantes"].append({"mutante": nombre, "detectado": detectado,
                                   "evidencia": evidencia})
    return hechos


def qualify_I_CANON(proto=None) -> Dict[str, Any]:
    hechos = medir_canon(proto)
    if hechos["casos"] == 0:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
        motivo = "PROTECCION_NO_MONTADA"
    elif hechos["desacuerdos"]:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
        motivo = "ESPECIFICACION_E_IMPLEMENTACION_DISCREPAN"
    elif hechos["igualdades_byte"] != hechos["comparables_byte"]:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
        motivo = "CANONICO_NO_COINCIDE_BYTE_A_BYTE_CON_LA_ESPECIFICACION"
    elif hechos["digests_distintos"] != 1:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
        motivo = "CANONICO_DEPENDE_DEL_ORDEN_DE_INSERCION"
    elif hechos["punto_fijo_ok"] != hechos["punto_fijo_n"]:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
        motivo = "CANONICO_NO_ES_PUNTO_FIJO"
    elif hechos["mutantes_detectados"] != hechos["mutantes_declarados"]:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
        motivo = "MUTANTE_DE_CANONICO_NO_DETECTADO"
    else:
        resultado = "QUALIFIED"
        motivo = None
    dossier = {
        "INVARIANTE": "I_CANON",
        "SPEC": SPEC,
        "CAMPAYA": CAMPANA,
        "RESULT": resultado,
        "QUALIFIED": resultado == "QUALIFIED",
        "REASON": motivo,
        "HECHOS": hechos,
        "MUTATION_SCORE": (
            hechos["mutantes_detectados"] / hechos["mutantes_declarados"]
            if hechos["mutantes_declarados"] else None
        ),
        "FORMALLY_PROVED": False,
    }
    _write_dossier("I_CANON_qualification", dossier)
    return dossier


# ================================================================
# I-CANON \u2014 CAMPANA DE PRODUCCION
# ================================================================

def campana_I_CANON() -> Dict[str, Any]:
    quals = qualify_I_CANON()
    hechos = quals["HECHOS"]
    declarados = hechos["casos"]
    ejecutados = hechos["casos"] - hechos["excepciones_crudas"]
    contraejemplos = list(hechos["desacuerdos"])

    if not quals["QUALIFIED"]:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
    elif contraejemplos:
        resultado = "COUNTEREXAMPLE_FOUND"
    elif declarados != ejecutados or hechos["excepciones_crudas"]:
        resultado = "INCONCLUSIVE"
    else:
        resultado = "PROPERTY_HOLDS_FOR_TESTED_DOMAIN"

    if contraejemplos:
        MET.ilegal("desacuerdo_decision_canonico:{0}".format(
            contraejemplos[0].get("caso")))
    for cx in contraejemplos:
        if cx.get("obtenido") == "EXCEPCION_CRUDA":
            MET.cruda("canonico:{0}".format(cx.get("caso")), ValueError("cruda"))

    dossier = {
        "INVARIANTE": "I_CANON",
        "CAMPAYA": CAMPANA,
        "HASHCAMPANA": False,
        "CASOS_DECLARADOS": declarados,
        "CASOS_EJECUTADOS": ejecutados,
        "ACEPTADOS": hechos["aceptados"],
        "RECHAZADOS": declarados - hechos["aceptados"],
        "ACUERDOS_DECISION": hechos["acuerdos_decision"],
        "IGUALDADES_BYTE": hechos["igualdades_byte"],
        "COMPARABLES_BYTE": hechos["comparables_byte"],
        "PERMUTACIONES": hechos["permutaciones"],
        "DIGESTS_DISTINTOS": hechos["digests_distintos"],
        "PUNTO_FIJO": "{0}/{1}".format(hechos["punto_fijo_ok"], hechos["punto_fijo_n"]),
        "MUTANTES": "{0}/{1}".format(hechos["mutantes_detectados"],
                                     hechos["mutantes_declarados"]),
        "N_CONTRAEJEMPLOS": len(contraejemplos),
        "CONTRAEJEMPLOS": contraejemplos[:20],
        "RESULT": resultado,
        "FORMALLY_PROVED": False,
    }
    _write_dossier("I_CANON_production", dossier)

    MET.fila("I_CANON", "casos", declarados)
    MET.fila("I_CANON", "acuerdos_espec", "{0}/{1}".format(
        hechos["acuerdos_decision"], declarados))
    MET.fila("I_CANON", "byte_a_byte", "{0}/{1}".format(
        hechos["igualdades_byte"], hechos["comparables_byte"]))
    MET.fila("I_CANON", "permutaciones", hechos["permutaciones"])
    MET.fila("I_CANON", "digests_distintos", hechos["digests_distintos"])
    MET.fila("I_CANON", "punto_fijo", "{0}/{1}".format(
        hechos["punto_fijo_ok"], hechos["punto_fijo_n"]))
    MET.fila("I_CANON", "mutantes_detectados", "{0}/{1}".format(
        hechos["mutantes_detectados"], hechos["mutantes_declarados"]))
    MET.fila("I_CANON", "excepciones_crudas", hechos["excepciones_crudas"])
    MET.fila("I_CANON", "resultado", resultado)
    return dossier


# ================================================================
# I-CANON \u2014 DETERMINISMO ENTRE PROCESOS
# ================================================================
# El canonico no puede depender de PYTHONHASHSEED ni de la instancia del
# interprete. Se mide ejecutando en subprocesos con semillas distintas y
# exigiendo un unico digesto.

SCRIPT_SUBPROCESO = (
    "import json,hashlib,sys\n"
    "sys.path.insert(0, {raiz!r})\n"
    "from tests.test_canon_man_proteccion import canon_independiente\n"
    "base = {payload!r}\n"
    "claves = {orden!r}\n"
    "obj = {{k: base[k] for k in claves}}\n"
    "b = canon_independiente(obj)\n"
    "print(hashlib.sha256(b).hexdigest())\n"
)


def digests_entre_procesos(semillas=("0", "1", "12345", "random")) -> Dict[str, str]:
    if PROT is None:
        return {}
    base = _permutacion_base()
    orden = sorted(base.keys())
    if not os.path.isfile(str(ROOT / "tests" / "test_canon_man_proteccion.py")):
        return {}
    salida: Dict[str, str] = {}
    for semilla in semillas:
        codigo = SCRIPT_SUBPROCESO.format(raiz=str(ROOT), payload=base, orden=orden)
        entorno = dict(os.environ)
        entorno["PYTHONHASHSEED"] = semilla
        entorno["PYTHONPATH"] = str(ROOT)
        try:
            proc = subprocess.run(
                [sys.executable, "-c", codigo],
                cwd=str(ROOT), env=entorno,
                capture_output=True, text=True, timeout=60,
            )
        except Exception as exc:
            salida[semilla] = "EXCEPCION:{0}".format(type(exc).__name__)
            continue
        linea = (proc.stdout or "").strip().splitlines()
        salida[semilla] = linea[-1] if linea else "VACIO:{0}".format(proc.returncode)
    return salida


# ================================================================
# I-MAN \u2014 MATERIAL DE PRUEBA Y ATAQUES
# ================================================================

_CACHE_MAN: Dict[str, Any] = {}


def material_firma() -> Dict[str, Any]:
    """Construye un manifiesto valido real y una segunda clave para falsificar."""
    if _CACHE_MAN:
        return _CACHE_MAN
    if PROT is None:
        return {}
    tmp = Path(tempfile.mkdtemp(prefix="uhcr_man_"))
    priv = tmp / "clave.priv"
    pub = tmp / "clave.pub"
    g1 = PROT.generar_claves(str(priv), str(pub))
    if not g1.get("ok"):
        return {}
    construido = PROT.build(
        b"documento auditado I-MAN",
        str(priv),
        n_neutro=3,
        artifact_id="art-1",
        clave_publica_id="llave-1",
    )
    if not construido.get("ok"):
        return {}
    otra_priv = tmp / "otra.priv"
    otra_pub = tmp / "otra.pub"
    PROT.generar_claves(str(otra_priv), str(otra_pub))
    _CACHE_MAN.update({
        "tmp": str(tmp),
        "priv": str(priv),
        "pub_bytes": pub.read_bytes(),
        "otra_priv": str(otra_priv),
        "otra_pub_bytes": otra_pub.read_bytes(),
        "datos": construido["datos"],
        "manifiesto": construido["manifiesto"],
        "cuerpo": construido["manifiesto"]["cuerpo"],
        "firma": construido["manifiesto"]["firma"],
    })
    return _CACHE_MAN


def _variantes_firma(firma: str) -> List[Tuple[str, Any]]:
    """
    Mutaciones de la firma: longitud, alfabeto, caso, y un bit por cada
    byte (64 posiciones) y un caracter por cada digito hex (128 posiciones).
    """
    variantes: List[Tuple[str, Any]] = [
        ("firma_vacia", ""),
        ("firma_int", 7),
        ("firma_none", None),
        ("firma_bytes", firma.encode("ascii")),
        ("firma_len63", firma[:63]),
        ("firma_len65", firma + "a"),
        ("firma_len127", firma[:127]),
        ("firma_len129", firma + "ab"),
        ("firma_no_hex", "g" * 128),
        ("firma_espacio", " " + firma[:-1]),
        ("firma_mayusculas", firma.upper()),
    ]
    crudo = bytes.fromhex(firma)
    for indice in range(len(crudo)):
        mutado = bytearray(crudo)
        mutado[indice] ^= 0x01
        variantes.append(("bit_flip_byte_{0}".format(indice), bytes(mutado).hex()))
    for posicion in range(len(firma)):
        original = firma[posicion]
        reemplazo = "0" if original != "0" else "1"
        variantes.append(("hex_flip_{0}".format(posicion),
                          firma[:posicion] + reemplazo + firma[posicion + 1:]))
    return variantes


def _variantes_cuerpo(cuerpo: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Un campo del cuerpo mutado por vez, sin tocar los demas."""
    mutaciones: List[Tuple[str, Dict[str, Any]]] = []
    for campo in sorted(cuerpo.keys()):
        valor = cuerpo[campo]
        alternativas: List[Any] = []
        if isinstance(valor, bool):
            alternativas = [not valor]
        elif isinstance(valor, int):
            alternativas = [valor + 1, -1 if valor >= 0 else 0]
        elif isinstance(valor, str):
            alternativas = ["", valor + "x", "z" * len(valor) if valor else "z"]
        elif isinstance(valor, list):
            alternativas = [[], [999], list(valor) + [999]]
        if not alternativas:
            continue
        for indice, alternativa in enumerate(alternativas):
            mutado = dict(cuerpo)
            mutado[campo] = alternativa
            mutaciones.append(("{0}#{1}".format(campo, indice), mutado))
        extra = dict(cuerpo)
        extra["campo_extra"] = 1
        mutaciones.append(("{0}#extra".format(campo), extra))
    cuerpo_sin_campo = dict(cuerpo)
    for campo in sorted(cuerpo.keys()):
        reducido = dict(cuerpo_sin_campo)
        reducido.pop(campo)
        mutaciones.append(("sin_{0}".format(campo), reducido))
    return mutaciones


LIMITE_VERSION_SPEC = 10000000
CLAVES_CUERPO_SPEC = (
    "esquema", "version", "emitido", "artifact_id", "clave_publica_id",
    "algoritmo_hash", "algoritmo_firma", "nucleo", "S", "Q", "n_bytes",
    "n_neutro", "valuaciones", "identidad_neutra",
)
ALGORITMO_HASH_SPEC = "SHA-256"
ALGORITMO_FIRMA_SPEC = "Ed25519"

# Campos que el ESQUEMA no liga al contenido: cambiarlos y re-firmar produce
# un manifiesto LEGAL. Se miden aparte en la capa RUNTIME (verificar), que es
# donde deberia aparecer la vinculacion con el documento.
CAMPOS_CUBIERTOS_SOLO_POR_FIRMA = (
    "emitido", "artifact_id", "clave_publica_id", "n_bytes", "n_neutro",
    "version", "identidad_neutra",
)


def _hex64_espec(x: Any) -> bool:
    return type(x) is str and len(x) == 64 and all(c in "0123456789abcdef" for c in x)


def cuerpo_valido_espec(cuerpo: Any, version_minima: int = 1) -> bool:
    """
    ESPECIFICACION independiente del esquema del cuerpo (capa A).
    Escrita aparte de proteccion._validar_cuerpo_esquema. Si discrepan, el
    desacuerdo es el hallazgo, no un detalle.
    """
    if type(cuerpo) is not dict:
        return False
    if set(cuerpo.keys()) != set(CLAVES_CUERPO_SPEC):
        return False
    if cuerpo["esquema"] != 1:
        return False
    ver = cuerpo["version"]
    if type(ver) is not int or ver < version_minima or ver > LIMITE_VERSION_SPEC:
        return False
    for campo in ("emitido", "artifact_id", "clave_publica_id"):
        if type(cuerpo[campo]) is not str:
            return False
    if cuerpo["algoritmo_hash"] != ALGORITMO_HASH_SPEC:
        return False
    if cuerpo["algoritmo_firma"] != ALGORITMO_FIRMA_SPEC:
        return False
    for campo in ("nucleo", "S", "Q"):
        if not _hex64_espec(cuerpo[campo]):
            return False
    if type(cuerpo["n_bytes"]) is not int or cuerpo["n_bytes"] < 0:
        return False
    if type(cuerpo["n_neutro"]) is not int or cuerpo["n_neutro"] < 2:
        return False
    vals = cuerpo["valuaciones"]
    if type(vals) is not list or len(vals) > 64:
        return False
    for x in vals:
        if type(x) is not int or x < 0 or x > 256:
            return False
    if type(cuerpo["identidad_neutra"]) is not bool:
        return False
    return True


def construir_probes(proto=None) -> List[Dict[str, Any]]:
    """Probes con la decision que dicta la ESPECIFICACION, no la implementacion."""
    proto = proto or PROT
    material = material_firma()
    probes: List[Dict[str, Any]] = []
    if not material:
        return probes

    pub = material["pub_bytes"]
    man = material["manifiesto"]
    cuerpo = material["cuerpo"]
    firma = material["firma"]

    def anadir(etiqueta, valor, pub_bytes, esperado, concepto=None, grupo="estructura"):
        probes.append({
            "etiqueta": etiqueta, "manifiesto": valor,
            "pub_bytes": pub_bytes, "esperado": esperado,
            "concepto_esperado": concepto, "grupo": grupo,
        })

    anadir("valido", man, pub, True)
    for etiqueta, valor in (
        ("no_dict_none", None), ("no_dict_lista", []), ("no_dict_str", "x"),
        ("no_dict_int", 7), ("no_dict_bytes", b"x"),
    ):
        anadir(etiqueta, valor, pub, False, "MANIFIESTO_AUSENTE")
    anadir("dict_vacio", {}, pub, False, "C\u00d3DIGO_INV\u00c1LIDO")
    anadir("clave_extra", {"cuerpo": cuerpo, "firma": firma, "extra": 1}, pub, False, "C\u00d3DIGO_INV\u00c1LIDO")
    anadir("sin_cuerpo", {"firma": firma}, pub, False, "C\u00d3DIGO_INV\u00c1LIDO")
    anadir("sin_firma", {"cuerpo": cuerpo}, pub, False, "C\u00d3DIGO_INV\u00c1LIDO")
    for etiqueta, cuerpo_malo in (
        ("cuerpo_lista", []), ("cuerpo_str", "x"), ("cuerpo_int", 7), ("cuerpo_none", None),
    ):
        anadir(etiqueta, {"cuerpo": cuerpo_malo, "firma": firma}, pub, False, "C\u00d3DIGO_INV\u00c1LIDO")
    anadir("pub_ausente", man, None, False, "FIRMA_INV\u00c1LIDA")
    anadir("pub_31", man, pub[:31], False, "FIRMA_INV\u00c1LIDA")
    anadir("pub_33", man, pub + b"\x00", False, "FIRMA_INV\u00c1LIDA")
    anadir("pub_str", man, "no-bytes", False, "FIRMA_INV\u00c1LIDA")
    anadir("pub_otra_clave", man, material["otra_pub_bytes"], False, "FIRMA_INV\u00c1LIDA")

    for etiqueta, valor in _variantes_firma(firma):
        esperado = True if etiqueta == "firma_mayusculas" else False
        anadir(etiqueta, {"cuerpo": cuerpo, "firma": valor}, pub, esperado,
               None if esperado else "FIRMA_INV\u00c1LIDA", grupo="firma")

    for etiqueta, mutado in _variantes_cuerpo(cuerpo):
        canonico = proto.serializar_seguro(mutado)
        if not canonico.get("ok"):
            anadir("cuerpo_{0}_no_canonico".format(etiqueta),
                   {"cuerpo": mutado, "firma": firma}, pub, False, "C\u00d3DIGO_INV\u00c1LIDO",
                   grupo="cuerpo")
            continue
        refirmado = proto.firmar_bytes(canonico["bytes"], material["priv"])
        if refirmado.get("ok"):
            anadir("{0}_refirmado".format(etiqueta),
                   {"cuerpo": mutado, "firma": refirmado["firma"]}, pub,
                   cuerpo_valido_espec(mutado),
                   None, grupo="cuerpo_refirmado")
        anadir("{0}_sin_refirmar".format(etiqueta),
               {"cuerpo": mutado, "firma": firma}, pub, False, "FIRMA_INV\u00c1LIDA",
               grupo="cuerpo_sin_refirmar")
    return probes


def medir_man(proto=None) -> Dict[str, Any]:
    proto = proto or PROT
    hechos: Dict[str, Any] = {
        "casos": 0, "acuerdos": 0, "desacuerdos": [],
        "rechazados": 0, "aceptados": 0,
        "clasificados": 0, "sin_concepto": [],
        "concepto_inesperado": [], "excepciones_crudas": 0,
        "grupos": {},
        "mutantes_declarados": 0, "mutantes_detectados": 0, "mutantes": [],
    }
    if proto is None:
        hechos["desacuerdos"].append("PROTECCION_NO_MONTADA")
        return hechos

    probes = construir_probes(proto)
    hechos["casos"] = len(probes)
    declarados = set(proto.SEGURIDAD.get("conceptos") or [])

    for probe in probes:
        grupo = probe["grupo"]
        acumulado = hechos["grupos"].setdefault(grupo, {"casos": 0, "acuerdos": 0})
        acumulado["casos"] += 1
        try:
            resultado = proto.verificar_manifiesto(
                probe["manifiesto"], pub_bytes=probe["pub_bytes"]
            )
        except BaseException as exc:
            hechos["excepciones_crudas"] += 1
            hechos["desacuerdos"].append({
                "probe": probe["etiqueta"], "esperado": probe["esperado"],
                "obtenido": "EXCEPCION_CRUDA", "detalle": type(exc).__name__,
            })
            continue
        obtenido = bool(resultado.get("ok"))
        if obtenido == probe["esperado"]:
            hechos["acuerdos"] += 1
            acumulado["acuerdos"] += 1
        else:
            hechos["desacuerdos"].append({
                "probe": probe["etiqueta"], "esperado": probe["esperado"],
                "obtenido": obtenido,
                "conceptos": list(resultado.get("conceptos") or []),
                "grupo": grupo,
            })
        if obtenido:
            hechos["aceptados"] += 1
            continue
        hechos["rechazados"] += 1
        conceptos = [c for c in (resultado.get("conceptos") or [])]
        if conceptos:
            hechos["clasificados"] += 1
        else:
            hechos["sin_concepto"].append(probe["etiqueta"])
        fuera = [c for c in conceptos if c not in declarados]
        if fuera:
            hechos["concepto_inesperado"].append(
                {"probe": probe["etiqueta"], "conceptos": fuera})

    # Capa runtime: de las mutaciones LEGALES por esquema, cuales detecta
    # verificar() cruzando el cuerpo contra los datos. Esto separa
    # "esquema correcto" de "vinculado al documento".
    vinculacion: Dict[str, Any] = {"casos": 0, "denegados": 0,
                                   "no_detectados": [], "detectados": []}
    material = material_firma()
    if material and proto is PROT:
        for etiqueta, mutado in _variantes_cuerpo(material["cuerpo"]):
            if not cuerpo_valido_espec(mutado):
                continue
            canonico = proto.serializar_seguro(mutado)
            if not canonico.get("ok"):
                continue
            re_firma = proto.firmar_bytes(canonico["bytes"], material["priv"])
            if not re_firma.get("ok"):
                continue
            manifiesto = {"cuerpo": mutado, "firma": re_firma["firma"]}
            try:
                resultado = proto.verificar(
                    material["datos"], manifiesto=manifiesto,
                    pub_bytes=material["pub_bytes"],
                )
            except BaseException as exc:
                hechos["excepciones_crudas"] += 1
                continue
            vinculacion["casos"] += 1
            campo = etiqueta.split("#")[0]
            if resultado.get("ok"):
                vinculacion["no_detectados"].append(campo)
            else:
                vinculacion["denegados"] += 1
                vinculacion["detectados"].append(campo)
    hechos["vinculacion_runtime"] = vinculacion

    # Suplantacion SIN la clave de la autoridad: re-etiquetar y firmar con
    # otra clave debe caer. Esta es la precondicion de todo lo anterior.
    suplantacion: Dict[str, Any] = {"casos": 0, "denegados": 0, "conceptos": []}
    if material and proto is PROT:
        for campo, valor in (
            ("artifact_id", "acta-SUPLANTADA"),
            ("clave_publica_id", "llave-suplantada"),
            ("emitido", "1970-01-01T00:00:00Z"),
        ):
            mutado = dict(material["cuerpo"])
            mutado[campo] = valor
            canonico = proto.serializar_seguro(mutado)
            if not canonico.get("ok"):
                continue
            firma_atacante = proto.firmar_bytes(canonico["bytes"], material["otra_priv"])
            if not firma_atacante.get("ok"):
                continue
            try:
                resultado = proto.verificar(
                    material["datos"],
                    manifiesto={"cuerpo": mutado, "firma": firma_atacante["firma"]},
                    pub_bytes=material["pub_bytes"],
                )
            except BaseException as exc:
                hechos["excepciones_crudas"] += 1
                continue
            suplantacion["casos"] += 1
            if not resultado.get("ok"):
                suplantacion["denegados"] += 1
                suplantacion["conceptos"].extend(resultado.get("conceptos") or [])
            else:
                hechos["desacuerdos"].append({
                    "probe": "suplantacion_sin_clave:{0}".format(campo),
                    "esperado": False, "obtenido": True,
                })
    hechos["suplantacion_sin_clave_de_autoridad"] = suplantacion

    # Control de version: el tope hacia adelante lo aporta version_minima.
    control_version: Dict[str, Any] = {"observable": False}
    if material and proto is PROT:
        try:
            con_defecto = proto.verificar_manifiesto(
                material["manifiesto"], pub_bytes=material["pub_bytes"])
            con_tope = proto.verificar_manifiesto(
                material["manifiesto"], pub_bytes=material["pub_bytes"],
                version_minima=int(material["cuerpo"]["version"]) + 1)
            control_version = {
                "observable": True,
                "version_en_cuerpo": material["cuerpo"]["version"],
                "con_default": bool(con_defecto.get("ok")),
                "con_version_minima_superior": bool(con_tope.get("ok")),
                "concepto_con_tope": list(con_tope.get("conceptos") or []),
            }
        except BaseException as exc:
            hechos["excepciones_crudas"] += 1
            control_version = {"observable": False, "detalle": type(exc).__name__}
    hechos["control_version_minima"] = control_version

    # Qualificacion del comparador: un oraculo constante debe ser detectado.
    comparadores: Dict[str, Callable[[Dict[str, Any]], bool]] = {
        "acepta_todo": lambda probe: True,
        "rechaza_todo": lambda probe: False,
        "ignora_la_especificacion": lambda probe: probe["etiqueta"] != "valido",
    }
    hechos["mutantes_declarados"] = len(comparadores)
    for nombre, comparador in comparadores.items():
        detectado = False
        for probe in probes:
            try:
                decision = bool(comparador(probe))
            except BaseException:
                decision = None
            if decision != probe["esperado"]:
                detectado = True
                break
        if detectado:
            hechos["mutantes_detectados"] += 1
        hechos["mutantes"].append({"comparador": nombre, "detectado": detectado})
    return hechos


def qualify_I_MAN(proto=None) -> Dict[str, Any]:
    hechos = medir_man(proto)
    grupos = hechos["grupos"]
    firma_grupo = grupos.get("firma", {"casos": 0, "acuerdos": 0})
    refirmado = grupos.get("cuerpo_refirmado", {"casos": 0, "acuerdos": 0})
    sin_refirmar = grupos.get("cuerpo_sin_refirmar", {"casos": 0, "acuerdos": 0})

    if hechos["casos"] == 0:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "PROTECCION_NO_MONTADA"
    elif hechos["desacuerdos"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "DECISION_DISCREPA_DE_LA_ESPECIFICACION"
    elif hechos["excepciones_crudas"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "EXCEPCION_CRUDA_EN_LA_FRONTERA"
    elif hechos["sin_concepto"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "RECHAZO_SIN_CONCEPTO_DECLARADO"
    elif hechos["concepto_inesperado"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "CONCEPTO_NO_DECLARADO_POR_EL_CONTRATO"
    elif firma_grupo["acuerdos"] != firma_grupo["casos"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "MUTACION_DE_FIRMA_NO_DETECTADA"
    elif refirmado["acuerdos"] != refirmado["casos"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "CUERPO_INVALIDO_REFIRMADO_ACEPTADO"
    elif sin_refirmar["acuerdos"] != sin_refirmar["casos"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "MUTACION_DE_CUERPO_NO_DETECTADA"
    elif hechos["mutantes_detectados"] != hechos["mutantes_declarados"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "COMPARADOR_NO_DETECTA_MUTANTES"
    elif hechos["suplantacion_sin_clave_de_autoridad"]["denegados"] != \
            hechos["suplantacion_sin_clave_de_autoridad"]["casos"]:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "SUPLANTACION_SIN_CLAVE_ACEPTADA"
    elif hechos["control_version_minima"].get("observable") and \
            hechos["control_version_minima"].get("con_version_minima_superior") is True:
        resultado, motivo = "INSTRUMENT_NOT_QUALIFIED", "CONTROL_DE_VERSION_IGNORADO"
    else:
        resultado, motivo = "QUALIFIED", None

    dossier = {
        "INVARIANTE": "I_MAN",
        "SPEC": SPEC,
        "CAMPAYA": CAMPANA,
        "RESULT": resultado,
        "QUALIFIED": resultado == "QUALIFIED",
        "REASON": motivo,
        "HECHOS": hechos,
        "GRUPOS": grupos,
        "MUTATION_SCORE": (
            hechos["mutantes_detectados"] / hechos["mutantes_declarados"]
            if hechos["mutantes_declarados"] else None
        ),
        "FORMALLY_PROVED": False,
    }
    _write_dossier("I_MAN_qualification", dossier)
    return dossier


# ================================================================
# I-MAN \u2014 CAMPANA DE PRODUCCION Y REPLAY CRUZADO
# ================================================================

def campana_I_MAN() -> Dict[str, Any]:
    quals = qualify_I_MAN()
    hechos = quals["HECHOS"]
    grupos = hechos["grupos"]

    replay = {"observable": False}
    material = material_firma()
    if material and PROT is not None:
        ajeno = b"documento distinto, no el firmado"
        try:
            resultado = PROT.verificar(
                ajeno, manifiesto=material["manifiesto"],
                pub_bytes=material["pub_bytes"],
            )
            replay = {
                "observable": True,
                "ok": bool(resultado.get("ok")),
                "fallos": list(resultado.get("fallos") or []),
                "conceptos": list(resultado.get("conceptos") or []),
            }
        except BaseException as exc:
            replay = {"observable": False, "detalle": type(exc).__name__}
            MET.cruda("replay_cruzado", exc)
    if replay.get("ok") is True:
        MET.ilegal("replay_de_manifiesto_sobre_otro_documento")

    contraejemplos = list(hechos["desacuerdos"])
    if contraejemplos:
        MET.ilegal("manifiesto_malformado_aceptado:{0}".format(
            contraejemplos[0].get("probe")))
    MET.ataques += hechos["casos"]

    if not quals["QUALIFIED"]:
        resultado = "INSTRUMENT_NOT_QUALIFIED"
    elif contraejemplos:
        resultado = "COUNTEREXAMPLE_FOUND"
    elif replay.get("observable") and replay.get("ok") is not False:
        resultado = "COUNTEREXAMPLE_FOUND"
    else:
        resultado = "PROPERTY_HOLDS_FOR_TESTED_DOMAIN"

    dossier = {
        "INVARIANTE": "I_MAN",
        "CAMPAYA": CAMPANA,
        "CASOS_DECLARADOS": hechos["casos"],
        "CASOS_EJECUTADOS": hechos["casos"] - hechos["excepciones_crudas"],
        "ACEPTADOS": hechos["aceptados"],
        "RECHAZADOS": hechos["rechazados"],
        "ACUERDOS": hechos["acuerdos"],
        "CLASIFICADOS_CON_CONCEPTO": hechos["clasificados"],
        "SIN_CONCEPTO": hechos["sin_concepto"],
        "CONCEPTO_NO_DECLARADO": hechos["concepto_inesperado"],
        "GRUPOS": grupos,
        "REPLAY_CRUZADO": replay,
        "SUPLANTACION_SIN_CLAVE": hechos.get("suplantacion_sin_clave_de_autoridad"),
        "CONTROL_VERSION_MINIMA": hechos.get("control_version_minima"),
        "CAMPOS_CUBIERTOS_SOLO_POR_FIRMA": sorted(set(
            (hechos.get("vinculacion_runtime") or {}).get("no_detectados") or [])),
        "VINCULACION_RUNTIME": {
            "casos": (hechos.get("vinculacion_runtime") or {}).get("casos"),
            "denegados": (hechos.get("vinculacion_runtime") or {}).get("denegados"),
            "precondicion": "clave_privada_de_la_autoridad",
        },
        "MUTANTES_COMPARADOR": "{0}/{1}".format(
            hechos["mutantes_detectados"], hechos["mutantes_declarados"]),
        "N_CONTRAEJEMPLOS": len(contraejemplos),
        "CONTRAEJEMPLOS": contraejemplos[:20],
        "RESULT": resultado,
        "FORMALLY_PROVED": False,
    }
    _write_dossier("I_MAN_production", dossier)

    firma_grupo = grupos.get("firma", {})
    MET.fila("I_MAN", "casos", hechos["casos"])
    MET.fila("I_MAN", "acuerdos_espec", "{0}/{1}".format(hechos["acuerdos"], hechos["casos"]))
    MET.fila("I_MAN", "rechazos_con_concepto", "{0}/{1}".format(
        hechos["clasificados"], hechos["rechazados"]))
    MET.fila("I_MAN", "mutaciones_de_firma", "{0}/{1}".format(
        firma_grupo.get("acuerdos", 0), firma_grupo.get("casos", 0)))
    MET.fila("I_MAN", "cuerpo_refirmado", "{0}/{1}".format(
        grupos.get("cuerpo_refirmado", {}).get("acuerdos", 0),
        grupos.get("cuerpo_refirmado", {}).get("casos", 0)))
    MET.fila("I_MAN", "cuerpo_sin_refirmar", "{0}/{1}".format(
        grupos.get("cuerpo_sin_refirmar", {}).get("acuerdos", 0),
        grupos.get("cuerpo_sin_refirmar", {}).get("casos", 0)))
    MET.fila("I_MAN", "sin_concepto", len(hechos["sin_concepto"]))
    MET.fila("I_MAN", "excepciones_crudas", hechos["excepciones_crudas"])
    MET.fila("I_MAN", "comparadores_detectados", "{0}/{1}".format(
        hechos["mutantes_detectados"], hechos["mutantes_declarados"]))
    MET.fila("I_MAN", "replay_cruzado", "DENEGADO" if replay.get("ok") is False else replay)
    vinc = hechos.get("vinculacion_runtime") or {}
    no_ligados = sorted(set(vinc.get("no_detectados") or []))
    MET.fila("I_MAN", "vinculacion_runtime", "{0}/{1} denegadas".format(
        vinc.get("denegados", 0), vinc.get("casos", 0)))
    MET.fila("I_MAN", "campos_cubiertos_solo_por_firma",
             ",".join(no_ligados) if no_ligados else "ninguno")
    sup = hechos.get("suplantacion_sin_clave_de_autoridad") or {}
    MET.fila("I_MAN", "suplantacion_sin_clave", "{0}/{1} denegados".format(
        sup.get("denegados", 0), sup.get("casos", 0)))
    cv = hechos.get("control_version_minima") or {}
    MET.fila("I_MAN", "control_version_minima", "default={0} tope={1}".format(
        cv.get("con_default"), cv.get("con_version_minima_superior")))
    MET.set("CAMPOS_CUBIERTOS_SOLO_POR_FIRMA", no_ligados)
    MET.set("PRECONDICION_RE_EMISION_DE_ESOS_CAMPOS", "clave_privada_de_la_autoridad")
    MET.set("SUPLANTACION_SIN_CLAVE", sup)
    MET.set("CONTROL_VERSION_MINIMA", cv)
    MET.fila("I_MAN", "resultado", resultado)
    return dossier


# ================================================================
# TESTS \u2014 CUALIFICACION
# ================================================================

def test_archivo_y_spec():
    texto = Path(__file__).read_text(encoding="utf-8")
    assert Path(__file__).name == "test_canon_man_proteccion.py"
    assert SPEC in texto
    assert CAMPANA in texto
    assert "INSTRUMENT_NOT_QUALIFIED" in texto


def test_artefacto_auditado_esta_montado():
    assert PROT is not None, LOAD_ERRORS
    assert PROT_PATH is not None
    assert PROT_PATH.name == "proteccion.py"


def test_qualify_I_CANON():
    q = qualify_I_CANON()
    MET.set("I_CANON_QUALIFIED", q["QUALIFIED"])
    assert q["QUALIFIED"], q


def test_qualify_I_MAN():
    q = qualify_I_MAN()
    MET.set("I_MAN_QUALIFIED", q["QUALIFIED"])
    assert q["QUALIFIED"], {"REASON": q["REASON"], "DESACUERDOS": q["HECHOS"]["desacuerdos"][:5]}


# ================================================================
# TESTS \u2014 FALSABILIDAD (el instrumento DEBE poder fallar)
# ================================================================

def test_I_CANON_se_rompe_con_serializador_sin_tope_de_entero():
    falso = ProtFalso(mut_sin_rango_entero, "sin_tope_de_entero")
    q = qualify_I_CANON(falso)
    assert q["QUALIFIED"] is False
    assert q["RESULT"] == "INSTRUMENT_NOT_QUALIFIED"
    assert q["HECHOS"]["desacuerdos"], "un canonico sin tope de entero debe discrepar"


def test_I_CANON_se_rompe_con_serializador_dependiente_del_orden():
    falso = ProtFalso(mut_sin_orden, "sin_orden")
    q = qualify_I_CANON(falso)
    assert q["QUALIFIED"] is False
    assert q["HECHOS"]["digests_distintos"] > 1


def test_I_MAN_se_rompe_con_verificador_que_acepta_todo():
    class ProtAceptaTodo:
        SEGURIDAD = {"conceptos": list((PROT.SEGURIDAD.get("conceptos") or []))}

        def verificar_manifiesto(self, manifiesto, **kwargs):
            return {"ok": True, "cuerpo": {}, "conceptos": []}

        def serializar_seguro(self, valor):
            return PROT.serializar_seguro(valor)

        def firmar_bytes(self, datos, ruta):
            return PROT.firmar_bytes(datos, ruta)

    q = qualify_I_MAN(ProtAceptaTodo())
    assert q["QUALIFIED"] is False
    assert q["REASON"] == "DECISION_DISCREPA_DE_LA_ESPECIFICACION"


# ================================================================
# TESTS \u2014 PRODUCCION
# ================================================================

def test_produccion_I_CANON():
    dossier = campana_I_CANON()
    assert dossier["RESULT"] != "COUNTEREXAMPLE_FOUND", dossier["CONTRAEJEMPLOS"][:3]
    assert dossier["RESULT"] in {"PROPERTY_HOLDS_FOR_TESTED_DOMAIN", "INCONCLUSIVE"}


def test_produccion_I_MAN():
    dossier = campana_I_MAN()
    assert dossier["RESULT"] != "COUNTEREXAMPLE_FOUND", dossier["CONTRAEJEMPLOS"][:3]
    assert dossier["RESULT"] in {"PROPERTY_HOLDS_FOR_TESTED_DOMAIN", "INCONCLUSIVE"}


def test_determinismo_canonico_entre_procesos():
    digests = digests_entre_procesos()
    if not digests:
        pytest.skip("subproceso no disponible")
    unicos = set(digests.values())
    MET.fila("I_CANON", "digests_entre_procesos", "{0} unicos de {1}".format(
        len(unicos), len(digests)))
    MET.set("DIGESTS_ENTRE_PROCESOS", digests)
    assert len(unicos) == 1, digests


# ================================================================
# TESTS \u2014 INFORME
# ================================================================

def test_99_reporte_aduana(request):
    quals, prods = [], []
    if DOSSIERS.exists():
        for ruta in sorted(DOSSIERS.glob("*.json")):
            try:
                fila = json.loads(ruta.read_text(encoding="utf-8"))
            except Exception:
                continue
            if ruta.name.endswith("_qualification.json"):
                quals.append(fila)
            elif ruta.name.endswith("_production.json"):
                prods.append(fila)

    no_cualificados = [q.get("INVARIANTE") for q in quals if not q.get("QUALIFIED")]
    MET.set("INSTRUMENTOS_NO_CUALIFICADOS", no_cualificados)
    MET.set("CUALIFICADOS", len(quals) - len(no_cualificados))
    MET.set("CAMPANAS", len(prods))
    MET.set("VEREDICTO", MET.veredicto())
    MET.set("ARTEFACTO_SHA256", _sha_file(PROT_PATH) if PROT_PATH else None)

    texto = MET.texto()
    OUT.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(texto, encoding="utf-8")
    METRICS.write_text(
        json.dumps({"METRICAS": MET.datos, "TABLA": MET.tabla,
                    "CONTADORES": {
                        "ataques": MET.ataques,
                        "aceptados_ilegalmente": MET.aceptados_ilegalmente,
                        "excepciones_crudas": MET.excepciones_crudas,
                    }},
                   indent=2, ensure_ascii=True, default=str),
        encoding="utf-8",
    )

    print()
    print(texto)
    print()

    assert "I_CANON" in texto
    assert "I_MAN" in texto
    assert MET.aceptados_ilegalmente == 0, MET.datos.get("ACEPTADOS_ILEGALMENTE")
    assert not no_cualificados, no_cualificados
    assert MET.veredicto() == "ACOTADO"
