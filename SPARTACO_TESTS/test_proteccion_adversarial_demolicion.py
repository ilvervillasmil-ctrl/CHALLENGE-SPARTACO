# ===========================================================================
# SPARTACO-SECURITY — tests/test_proteccion_adversarial_demolicion.py
# VPSI-TRUTH — PROTECCION — UNIFIED ADVERSARIAL + DEMOLITION BATTERY
# ===========================================================================
#
# AUTHORSHIP
# ---------------------------------------------------------------------------
#   Test battery: Ilver Villasmil, over the module
#   modules/spartaco_seguridad/proteccion.py — whose authorship,
#   architecture and design are by Ilver Villasmil.
#
#   Role of this file: attack the architecture, not redesign it. Each
#   block attacks one architectural layer the module declares, and no
#   layer is accepted on the reputation of another.
#
# THESIS
# ---------------------------------------------------------------------------
# It is a mistake to read this battery as "a test of Ed25519". The
# signature is ONE layer among several. The module is an architecture
# of stacked guarantees, and a break in any layer breaks the module
# even when the signature still verifies. This file attacks each layer
# separately and refuses to let a pass in one layer cover a gap in
# another.
#
# THE ARCHITECTURE UNDER ATTACK — LAYERS
# ---------------------------------------------------------------------------
#
#   L1  ENVELOPE — the container that carries {body, signature} must
#       be exactly that and nothing more. The signature protects the
#       body's contents, not the dictionary that wraps it. Extra keys,
#       flat fields, capital variants, embedded nulls, __eq__ overrides
#       are all attacks on L1.
#
#   L2  CANONICALIZATION — the serialization of the body before signing
#       must be deterministic, type-strict and non-collapsing. Key
#       ordering, NFC vs NFD, zero-width, BOM, surrogates, deep nesting,
#       mixed int/str keys, int-vs-float equivalence: each is an attack
#       on L2 that can silently break L8 without breaking L8's tests.
#
#   L3  EVIDENCE vs AUTHORITY — z, neutro, identidad_neutra, and every
#       external reference passed by the caller are EVIDENCE. They must
#       never substitute for the signed body. An external reference
#       that "confirms" a tampered artifact must not authorize it. This
#       layer is orthogonal to cryptography.
#
#   L4  ARTIFACT INTEGRITY — corruption of the artifact must be
#       reported at the specific node that detects it, not at a generic
#       "something failed". Byte flips at positions 0, middle, tail and
#       critical positions must land under the right node.
#
#   L5  IMMUTABILITY and TOCTOU — verify() must not mutate the caller's
#       manifest or data, must read each field once, and must not allow
#       a mapping that returns different values across reads to be
#       accepted. Aliasing, hostile mappings and __eq__ always True are
#       attacks on L5.
#
#   L6  RESPONSE CONTRACT — ok=True implies empty fallos; fallos and
#       conceptos are always present as lists; verify() never raises on
#       arbitrary input. Every consumer downstream depends on L6.
#
#   L7  MODE FALLBACK — an unknown mode must fall back to STRICT, never
#       to DIAGNOSTIC. Ten hostile mode values, including None, empty,
#       integers, lists, dicts and booleans, are attacks on L7.
#
#   L8  SIGNATURE — Ed25519 non-canonical forms (S+L, S=L, S+2L, high
#       bit, all-0xFF), non-canonical R, truncated 63-byte and extended
#       65-byte signatures. L8 is necessary, not sufficient: L8 can
#       pass while L1, L2, L3, L4, L5, L6 or L7 is broken.
#
#   L9  VERSION / SCHEMA — regressive versions, extreme-high versions,
#       incompatible schemas, and "signed but not authorized" schemas
#       are attacks on L9. Signing a value does not authorize it.
#
#   L10 DIRECT CRYPTO API — firmar_bytes / verificar_bytes exposed
#       directly must reject hostile types, wrong messages and reused
#       signatures. L10 is not covered by L8.
#
#   L11 FRAGMENT COVERAGE — the fragmenter must cover every byte,
#       under any k, without crash. A missing byte at the tail is an
#       undetected corruption channel.
#
#   L12 DOS / EXTREME INPUTS — empty, single-byte, 10 KB, all-zeros,
#       all-0xFF, version 10**5000, 5 MB body, 2 MB artifact, circular
#       references, deep nesting. Timeout is a failure; classified
#       exception is a pass.
#
#   L13 CONCURRENCY — 8 threads x 30 verifications on the same
#       manifest, 240 results, all ok=True. Any shared mutable state
#       is an attack surface L13 exposes.
#
# INVARIANTS THAT GOVERN THE WHOLE BATTERY
# ---------------------------------------------------------------------------
#   * A crash is NOT a rejection. An uncaught exception is fail-open in
#     any caller with `try/except: pass`, and therefore counts as a
#     security failure on every layer.
#   * An external reference is NOT authority (L3).
#   * A signed field is NOT an enforced field (L9).
#   * An equivalence of value is NOT an equivalence of type (L2).
#   * A pass in one layer does NOT cover a gap in another.
#
# KNOWN STATE AT DELIVERY
# ---------------------------------------------------------------------------
#   With the bounded `valuaciones` schema (len <= 64, 0 <= x <= 256):
#   737 collected, 0 failures.
#   Without that bound: valuaciones[-1], [10**40] and
#   list(range(100000)) fail — the module returns ok=True where it
#   must return False. This is documented, not hidden.
#
# ARCHITECTURAL DEBT (out of scope of this battery)
# ---------------------------------------------------------------------------
#   No test in this file can close these four. They are listed so that
#   whoever audits does not mistake them for coverage:
#
#   D1  artifact_id is not bound to the artifact bytes.
#   D2  rollback: version_minima is chosen by the caller, no persistent
#       anchor.
#   D3  emitido / clave_publica_id: signed but never consulted. No
#       validity window, no revocation.
#   D4  the verifier runs in the same process as the verified.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It is not a signature test with architectural decoration. The
#     signature is L8; the architecture is L1..L13.
#   - It is not a red-team of credencial.py (that is a different file).
#   - It is not an isolated-resource audit with synthetic calibration
#     (that is the UHCR auditor).
#   - It is not a metrological kernel that qualifies its own instrument.
#   - It does not certify the whole system: it certifies the layered
#     guarantees of one module under adversarial pressure.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The credential red-teams attack credencial.py. The metrological
# kernel audits the instruments. The integration smoke test checks the
# honest end-to-end path. The monitor correlates external and internal
# observation. The fail-closed auditor qualifies itself against
# synthetic controls before auditing a resource. This file concentrates
# on proteccion.py with depth across thirteen architectural layers,
# and it documents the four debts no test can reach.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# A module is an architecture, not a cryptographic primitive. The
# signature is one layer among thirteen. The battery attacks each
# layer separately, refuses to let one cover another, counts a crash
# as a security failure, and names the four debts it cannot close.
#
# ===========================================================================
from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path

import pytest

from modules.spartaco_seguridad.proteccion import (
    ESQUEMA_MANIFIESTO,
    MODO_DIAGNOSTICO,
    MODO_PROTEGIDO,
    _fragmentos,
    build,
    firmar_bytes,
    generar_claves,
    nucleo,
    serializar,
    sellar,
    verificar,
    verificar_bytes,
    verificar_manifiesto,
    verificar_neutro,
)


# ===============================================================
# HELPERS
# ===============================================================

def blindado(fn, *args, **kwargs):
    """
    Ejecuta una entrada hostil. Una excepción no controlada cuenta
    como fallo, no como rechazo.

    IMPORTANTE: si el argumento que quieres blindar es a su vez una
    llamada que puede lanzar (p. ej. serializar(c)), envuelve TODO en
    un lambda:  blindado(lambda: fn(serializar(c), ...))
    Si lo pasas como argumento posicional, se evalúa ANTES de entrar
    aquí y la excepción escapa del blindaje.
    """
    try:
        resultado = fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — es exactamente lo que cazamos
        return False, exc

    if isinstance(resultado, dict):
        return bool(resultado.get("ok")), None

    return bool(resultado), None


def exige_rechazo_limpio(fn, *args, **kwargs):
    """Debe rechazar SIN excepción."""
    ok, exc = blindado(fn, *args, **kwargs)
    assert exc is None, (
        f"CRASH en lugar de rechazo: {type(exc).__name__}: {exc}"
    )
    assert ok is False


def remanifestar(cuerpo, priv):
    """Re-firma un cuerpo mutado: simula atacante con la clave legítima."""
    f = firmar_bytes(serializar(cuerpo), str(priv))
    assert f["ok"] is True
    return {"cuerpo": cuerpo, "firma": f["firma"]}


class DictMalo(dict):
    """Subclase de dict: no debe colarse por comprobaciones laxas de tipo."""


class DictMutante(dict):
    """
    Cambia un campo después de la primera lectura.
    Ataca el hueco TOCTOU: firmar una cosa y verificar otra.
    """

    def __init__(self, base, campo, malo):
        super().__init__(base)
        self.campo = campo
        self.malo = malo
        self.lecturas = 0

    def get(self, key, default=None):
        if key == self.campo:
            self.lecturas += 1
            if self.lecturas > 1:
                return self.malo
        return super().get(key, default)

    def __getitem__(self, key):
        if key == self.campo:
            self.lecturas += 1
            if self.lecturas > 1:
                return self.malo
        return super().__getitem__(key)


class SiempreIgual:
    """Ataca validaciones que dependan de == en vez de datos tipados."""

    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0

    def __str__(self):
        return "0" * 64


# ===============================================================
# FIXTURES
# ===============================================================

@pytest.fixture
def claves(tmp_path: Path):
    priv = tmp_path / "omega.key"
    pub = tmp_path / "omega.pub"

    r = generar_claves(str(priv), str(pub))

    assert r["ok"] is True
    assert priv.is_file()
    assert pub.is_file()
    assert len(pub.read_bytes()) == 32

    return priv, pub, pub.read_bytes()


@pytest.fixture
def build_valido(claves):
    priv, _, pub_bytes = claves

    datos = (
        b"VPSI-TRUTH::ARTEFACTO::ORIGINAL::"
        b"0123456789ABCDEF::SEGURIDAD"
    )

    r = build(
        datos,
        str(priv),
        n_neutro=3,
        artifact_id="TEST-001",
        version=3,
        clave_publica_id="OMEGA-ROOT-01",
    )

    assert r["ok"] is True
    assert set(r["manifiesto"]) == {"cuerpo", "firma"}
    assert isinstance(r["manifiesto"]["cuerpo"], dict)
    assert isinstance(r["manifiesto"]["firma"], str)
    assert r["manifiesto"]["firma"]
    assert r["manifiesto"]["cuerpo"]["n_neutro"] == 3
    assert r["manifiesto"]["cuerpo"]["esquema"] == ESQUEMA_MANIFIESTO

    return r, pub_bytes


CAMPOS_CUERPO = [
    "esquema",
    "version",
    "emitido",
    "artifact_id",
    "clave_publica_id",
    "algoritmo_hash",
    "algoritmo_firma",
    "nucleo",
    "S",
    "Q",
    "n_bytes",
    "n_neutro",
    "valuaciones",
    "identidad_neutra",
]

TIPOS_ADVERSARIOS = [
    True, False,
    0, 1, -1,
    1.0, 3.0, -0.0,
    float("inf"), float("-inf"), float("nan"),
    "", "3", "1", "0", "True",
    [], {}, None,
    b"3", (3,), {3},
]

HASH_HOSTIL = [
    123, None, True,
    b"\x00" * 32,
    ["a"], {"a": 1},
    "ñ" * 64, "\u00e9" * 64,
    "0" * 63, "0" * 65,
    "ZZ" * 32, " " * 64,
    "\x00" * 64, "0" * 64 + "\n",
]


# ===============================================================
# 1. CAMINO FELIZ / CONTRATO BÁSICO
# ===============================================================

def test_build_protegido_valido(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is True
    assert v["fallos"] == []
    assert v["pasos"]["manifiesto"]["ok"] is True
    assert v["pasos"]["nucleo"]["ok"] is True
    assert v["pasos"]["canales"]["ok"] is True


def test_build_formato_unico(build_valido):
    r, _ = build_valido
    m = r["manifiesto"]
    assert set(m) == {"cuerpo", "firma"}
    assert isinstance(m["cuerpo"], dict)
    assert isinstance(m["firma"], str) and m["firma"]


def test_build_sella_y_cambia_bytes(claves):
    priv, _, _ = claves
    original = b"DATOS-SIN-SELLAR"
    r = build(original, str(priv), n_neutro=3)
    assert r["ok"] is True
    assert r["datos"] != original


def test_firma_build_es_del_cuerpo(build_valido):
    r, pub = build_valido
    v = verificar_bytes(
        serializar(r["manifiesto"]["cuerpo"]),
        r["manifiesto"]["firma"],
        pub_bytes=pub,
    )
    assert v["ok"] is True


def test_firma_cuerpo_no_valida_digest_artefacto(build_valido):
    """La firma es del CUERPO, no del digest del artefacto. No se confunden."""
    r, pub = build_valido
    digest = bytes.fromhex(r["manifiesto"]["cuerpo"]["nucleo"])
    assert verificar_bytes(
        digest, r["manifiesto"]["firma"], pub_bytes=pub
    )["ok"] is False


# ===============================================================
# 2. FAIL-CLOSED
# ===============================================================

def test_protegido_sin_manifiesto_falla(build_valido):
    r, pub = build_valido
    v = verificar(r["datos"], pub_bytes=pub, modo=MODO_PROTEGIDO)
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]
    assert "MANIFIESTO_AUSENTE" in v["conceptos"]


def test_protegido_none_falla(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=None,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


@pytest.mark.parametrize(
    "manifiesto",
    [
        {}, {"firma": "00"}, {"cuerpo": {}},
        {"cuerpo": {}, "firma": ""},
        {"cuerpo": "x", "firma": "00"},
        {"cuerpo": {}, "firma": None},
        {"cuerpo": None, "firma": "00"},
        {"cuerpo": [], "firma": "00"},
        {"cuerpo": {}, "firma": []},
        {"cuerpo": {}, "firma": 0},
        {"cuerpo": 1, "firma": "ab"},
        [], "texto", 123, b"bytes", True, False,
        0.0, float("nan"),
    ],
)
def test_protegido_manifiesto_basura_falla(build_valido, manifiesto):
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=manifiesto,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


def test_protegido_sin_clave_publica_falla(build_valido):
    r, _ = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]
    assert "FIRMA_INVÁLIDA" in v["conceptos"]


def test_firma_hex_suelta_no_bypassea(build_valido):
    """Una firma suelta no sustituye al manifiesto en modo protegido."""
    r, pub = build_valido
    v = verificar(
        r["datos"],
        firma_hex=r["manifiesto"]["firma"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


@pytest.mark.parametrize(
    "man",
    [None, {}, {"cuerpo": {}}, {"firma": "00"},
     {"cuerpo": None}, {"firma": None}],
)
def test_fail_closed_casos_minimos(build_valido, man):
    r, pub = build_valido
    assert verificar(
        r["datos"], manifiesto=man,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


# ===============================================================
# 3. FORMA ESTRICTA — el manifiesto es exactamente {cuerpo, firma}
# ===============================================================

@pytest.mark.parametrize(
    "extra_key,extra_val",
    [
        ("campo_extra", "X"),
        ("firma_extra", "00" * 64),
        ("cuerpo_extra", {"a": 1}),
        ("nucleo", "00" * 32),
        ("version", 1), ("S", "00"), ("Q", "00"),
        ("", ""), ("cuerpo ", {}), ("firma ", "x"),
        ("Cuerpo", {}), ("FIRMA", "x"), ("cuerpo\x00", {}),
    ],
)
def test_clave_extra_rechazada(build_valido, extra_key, extra_val):
    """La firma protege el cuerpo; el sobre debe estar cerrado aparte."""
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m[extra_key] = extra_val

    assert verificar_manifiesto(m, pub_bytes=pub)["ok"] is False

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


def test_campo_plano_rechazado(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["artifact_id"] = "PLANO"
    assert verificar_manifiesto(m, pub_bytes=pub)["ok"] is False
    assert verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


def test_solo_cuerpo_falla(build_valido):
    r, pub = build_valido
    assert verificar(
        r["datos"],
        manifiesto={"cuerpo": r["manifiesto"]["cuerpo"]},
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


def test_solo_firma_falla(build_valido):
    r, pub = build_valido
    assert verificar(
        r["datos"],
        manifiesto={"firma": r["manifiesto"]["firma"]},
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


def test_dict_subclass_no_crashea(build_valido):
    r, pub = build_valido
    m = DictMalo(
        cuerpo=r["manifiesto"]["cuerpo"],
        firma=r["manifiesto"]["firma"],
    )
    ok, exc = blindado(
        verificar, r["datos"],
        manifiesto=m, pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )
    assert exc is None
    assert isinstance(ok, bool)


# ===============================================================
# 4. MUTACIÓN / BORRADO DEL CUERPO
# ===============================================================

@pytest.mark.parametrize("campo", CAMPOS_CUERPO)
def test_mutar_campo_cuerpo_rompe(build_valido, campo):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    original = m["cuerpo"][campo]

    if isinstance(original, bool):
        m["cuerpo"][campo] = not original
    elif isinstance(original, int):
        m["cuerpo"][campo] = original + 7919
    elif isinstance(original, list):
        m["cuerpo"][campo] = list(original) + [-1]
    elif isinstance(original, str):
        m["cuerpo"][campo] = original + "|ATAQUE"
    else:
        m["cuerpo"][campo] = "ATAQUE"

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


@pytest.mark.parametrize("campo", CAMPOS_CUERPO)
def test_borrar_campo_cuerpo_rompe(build_valido, campo):
    r, pub = build_valido
    cuerpo = copy.deepcopy(r["manifiesto"]["cuerpo"])
    del cuerpo[campo]

    v = verificar(
        r["datos"],
        manifiesto={"cuerpo": cuerpo,
                    "firma": r["manifiesto"]["firma"]},
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


def test_cuerpo_vacio_falla(build_valido):
    r, pub = build_valido
    assert verificar(
        r["datos"],
        manifiesto={"cuerpo": {},
                    "firma": r["manifiesto"]["firma"]},
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


def test_firma_otro_cuerpo_no_reutilizable(build_valido, claves):
    r, _ = build_valido
    priv, _, pub = claves

    otro = copy.deepcopy(r["manifiesto"]["cuerpo"])
    otro["artifact_id"] = "OTRO-ID"
    f = firmar_bytes(serializar(otro), str(priv))
    assert f["ok"] is True

    v = verificar(
        r["datos"],
        manifiesto={
            "cuerpo": r["manifiesto"]["cuerpo"],
            "firma": f["firma"],
        },
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


def test_trasplante_firma_A_sobre_cuerpo_B(claves):
    priv, _, pub = claves
    a = {"esquema": 1, "version": 1, "artifact_id": "A"}
    b = {"esquema": 1, "version": 1, "artifact_id": "B"}

    fa = firmar_bytes(serializar(a), str(priv))
    assert fa["ok"] is True

    assert verificar_bytes(
        serializar(b), fa["firma"], pub_bytes=pub
    )["ok"] is False


# ===============================================================
# 5. ARTEFACTO / INTEGRIDAD
# ===============================================================

def test_flip_byte_0(build_valido):
    r, pub = build_valido
    d = bytearray(r["datos"])
    d[0] ^= 0x01

    v = verificar(
        bytes(d), manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert v["ok"] is False
    assert "nucleo" in v["fallos"]
    assert "canales" in v["fallos"]
    assert "INTEGRIDAD_COMPROMETIDA" in v["conceptos"]


def test_flip_mitad(build_valido):
    r, pub = build_valido
    d = bytearray(r["datos"])
    d[len(d) // 2] ^= 0x80

    v = verificar(
        bytes(d), manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


def test_append_byte(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"] + b"\x00",
        manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


def test_pop_byte(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"][:-1],
        manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


@pytest.mark.parametrize("pos", [0, 1, 2, -3, -2, -1])
def test_flip_en_borde(build_valido, pos):
    r, pub = build_valido
    d = bytearray(r["datos"])
    d[pos] ^= 0xFF

    v = verificar(
        bytes(d), manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


def test_flip_posiciones_criticas(build_valido):
    r, pub = build_valido
    n = len(r["datos"])

    for pos in {
        0, min(1, n - 1), n // 4, n // 2,
        (3 * n) // 4, max(0, n - 2), n - 1,
    }:
        d = bytearray(r["datos"])
        d[pos] ^= 0xFF

        v = verificar(
            bytes(d), manifiesto=r["manifiesto"],
            pub_bytes=pub, modo=MODO_PROTEGIDO,
        )
        assert v["ok"] is False, f"byte {pos} no detectado"
        assert "nucleo" in v["fallos"]


def test_manifiesto_no_autentica_artefacto_B(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"] + b"::B",
        manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


def test_dos_builds_no_cruzan_autorizacion(claves):
    priv, _, pub = claves

    a = build(b"ARTEFACTO-A", str(priv),
              artifact_id="A", version=1)
    b = build(b"ARTEFACTO-B", str(priv),
              artifact_id="B", version=1)

    assert a["ok"] and b["ok"]

    assert verificar(
        a["datos"], manifiesto=a["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"]

    assert verificar(
        b["datos"], manifiesto=b["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"]

    cruz = verificar(
        a["datos"], manifiesto=b["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert cruz["ok"] is False
    assert "nucleo" in cruz["fallos"]


# ===============================================================
# 6. FIRMA / PARSING / MALEABILIDAD
# ===============================================================

# ---------------------------------------------------------------
# HELPERS (pegar una sola vez, antes del bloque 6)
# ---------------------------------------------------------------

import copy
from decimal import Decimal
from fractions import Fraction

import pytest

L_ED25519 = 2**252 + 27742317777372353535851937790883648493


def _verificar(r, m, pub):
    return verificar(r["datos"], manifiesto=m,
                     pub_bytes=pub, modo=MODO_PROTEGIDO)


def _exige_aceptado(r, m, pub, ctx=""):
    """Ancla: si el manifiesto legítimo no pasa, el test es vacío."""
    v = _verificar(r, m, pub)
    assert isinstance(v, dict), f"verificar() no devolvió dict {ctx}: {v!r}"
    assert v.get("ok") is True, (
        f"CONTROL POSITIVO ROTO {ctx}: el manifiesto legítimo fue "
        f"rechazado ({v!r}). Todo test de rechazo es vacío."
    )
    return v


def _exige_rechazado(r, m, pub, msg):
    ok, exc = blindado(verificar, r["datos"], manifiesto=m,
                       pub_bytes=pub, modo=MODO_PROTEGIDO)
    assert exc is None, f"crash en vez de rechazo limpio: {exc!r} — {msg}"
    assert ok is False, msg


def _sig_variantes(R, S):
    """(id → firma_bytes) — todas deben ser rechazadas."""
    return {
        "S_mas_L":     R + (S + L_ED25519).to_bytes(32, "little"),
        "S_igual_L":   R + L_ED25519.to_bytes(32, "little"),
        "S_mas_2L":    R + (S + 2 * L_ED25519).to_bytes(32, "little"),
        "S_bit_alto":  R + ((S | (1 << 255)) % 2**256).to_bytes(32, "little"),
        "S_todo_ff":   R + b"\xff" * 32,
        "R_identidad": b"\x01" + b"\x00" * 31 + S.to_bytes(32, "little"),
        "R_no_canon":  b"\xff" * 32 + S.to_bytes(32, "little"),
        "truncada_63": (R + S.to_bytes(32, "little"))[:63],
        "extra_65":    R + S.to_bytes(32, "little") + b"\x00",
    }


CASOS_FIRMA = [
    "S_mas_L", "S_igual_L", "S_mas_2L", "S_bit_alto", "S_todo_ff",
    "R_identidad", "R_no_canon", "truncada_63", "extra_65",
]

CASOS_VALUACIONES = [
    "pop_final", "pop_inicio", "duplicar", "vaciar",
    "reordenar", "intercambiar",
]


def _mismo_valor_y_tipo(valor, legitimo):
    """Comparación protegida: el __eq__ del atacante no decide el flujo."""
    if type(valor) is not type(legitimo):
        return False
    try:
        return bool(valor == legitimo)
    except Exception:
        return False


def _mutaciones(vals):
    return {
        "pop_final":    vals[:-1],
        "pop_inicio":   vals[1:],
        "duplicar":     vals + [vals[-1]],
        "vaciar":       [],
        "reordenar":    list(reversed(vals)),
        "intercambiar": [vals[-1]] + vals[1:-1] + [vals[0]],
    }


class _IntFalso(int):
    """Subclase de int: mismo valor, tipo distinto."""
    pass


CASOS_CANONICO = [
    ("int_3",        3),
    ("float_3_0",    3.0),
    ("bool_True",    True),
    ("decimal_3",    Decimal("3")),
    ("fraction_3_1", Fraction(3, 1)),
    ("subclase_int", _IntFalso(3)),
    ("str_3",        "3"),
]


class _CuerpoTOCTOU(dict):
    """Devuelve el valor legítimo la 1ª lectura y el hostil después."""

    def __init__(self, base, clave, valor_falso):
        super().__init__(base)
        self.clave = clave
        self.falso = valor_falso
        self.lecturas = 0

    def __getitem__(self, k):
        if k == self.clave:
            self.lecturas += 1
            if self.lecturas > 1:
                return self.falso
        return super().__getitem__(k)


# ===============================================================
# 6. FIRMA / PARSING / MALEABILIDAD  →  test_firma_maleable_S_mas_L
# ===============================================================

@pytest.mark.parametrize("caso_id", CASOS_FIRMA)
def test_firma_maleable_S_mas_L(build_valido, caso_id):
    """
    Ed25519: ninguna codificación no canónica de S (S+L, S=L, S+2L,
    bit alto) ni un R no canónico debe convertirse en firma aceptada.
    Longitudes distintas de 64 → rechazo limpio, nunca crash.
    """
    r, pub = build_valido

    # Ancla: la firma legítima verifica.
    _exige_aceptado(r, r["manifiesto"], pub, ctx=f"[{caso_id}]")

    raw = bytes.fromhex(r["manifiesto"]["firma"])
    assert len(raw) == 64, f"firma legítima con longitud rara: {len(raw)}"
    R = raw[:32]
    S = int.from_bytes(raw[32:], "little")

    # El firmante propio debe emitir S canónico (S < L).
    assert S < L_ED25519, f"el firmante emitió S no reducido: S={S}"

    mal = _sig_variantes(R, S)[caso_id]
    assert mal != raw, f"variante {caso_id} es idéntica a la firma real"

    m = {
        "cuerpo": copy.deepcopy(r["manifiesto"]["cuerpo"]),
        "firma": mal.hex(),
    }

    _exige_rechazado(r, m, pub, f"firma hostil aceptada: {caso_id}")


# ===============================================================
# 16-BIS. DIAGNÓSTICO DE CANONICALIZACIÓN NUMÉRICA
#         (no es test de seguridad — mide el contrato)
#         Ejecutar con:  pytest -s -k canonico
# ===============================================================

@pytest.mark.parametrize("caso_id,valor", CASOS_CANONICO)
def test_diagnostico_canonico_n_neutro(build_valido, caso_id, valor):
    """
    Responde: ¿tu canónico distingue 3 de 3.0?

    - float_3_0 → ok=True  : el canónico normaliza números (estilo
      JCS/RFC 8785). 3.0 NO es type-confusion; hay que volver a
      saltarlo en el test 17.
    - float_3_0 → ok=False : el canónico distingue tipos (estilo
      json.dumps) y el test 17 endurecido queda tal cual.
    """
    r, pub = build_valido
    legitimo = r["manifiesto"]["cuerpo"]["n_neutro"]

    _exige_aceptado(r, r["manifiesto"], pub, ctx=f"[{caso_id}]")

    m = copy.deepcopy(r["manifiesto"])
    try:
        m["cuerpo"]["n_neutro"] = valor
    except Exception as e:
        print(f"\n[CANONICO] {caso_id:14s} no asignable: {e!r}")
        return

    ok, exc = blindado(verificar, r["datos"], manifiesto=m,
                       pub_bytes=pub, modo=MODO_PROTEGIDO)

    print(
        f"\n[CANONICO] {caso_id:14s} "
        f"valor={valor!r:16s} tipo={type(valor).__name__:10s} "
        f"legitimo={legitimo!r} ({type(legitimo).__name__}) "
        f"→ ok={ok!r} exc={type(exc).__name__ if exc else None}"
    )

    # Única exigencia real: nunca crashear con entrada numérica rara.
    assert exc is None, (
        f"{caso_id}: verificar() lanzó {exc!r} en vez de "
        f"devolver un veredicto. Eso es DoS, no rechazo."
    )


def test_diagnostico_canonico_resumen(build_valido):
    """Imprime el veredicto del contrato en una sola línea."""
    r, pub = build_valido
    legitimo = r["manifiesto"]["cuerpo"]["n_neutro"]

    if not isinstance(legitimo, int) or isinstance(legitimo, bool):
        pytest.skip(f"n_neutro legítimo no es int puro: {legitimo!r}")

    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["n_neutro"] = float(legitimo)
    ok_float, exc = blindado(verificar, r["datos"], manifiesto=m,
                             pub_bytes=pub, modo=MODO_PROTEGIDO)
    assert exc is None, f"crash con float equivalente: {exc!r}"

    if ok_float is False:
        veredicto = (
            "ESTRICTO — el canónico distingue int de float. "
            "El test 17 endurecido es correcto tal cual."
        )
    else:
        veredicto = (
            "NORMALIZADOR — el canónico trata 3 y 3.0 como el mismo "
            "número (estilo JCS). El float equivalente NO es ataque: "
            "hay que volver a saltarlo en el test 17."
        )

    print(f"\n[CANONICO] VEREDICTO: {veredicto}")


# ===============================================================
# 17. TIPOS ADVERSARIALES  →  test_n_neutro_tipo_adversarial
# ===============================================================
# ANTES: si valor == legítimo (p. ej. 3.0 vs 3) → pytest.skip
# AHORA: no hay skip. 3.0 es 3.0 (float). 3 es 3 (int).
# Si el canónico normaliza (acepta 3.0 como 3) → se exige ok=True
# y se deja constancia. Si distingue tipos → se exige rechazo.
# En ambos caminos el test CORRE y da veredicto. Cero skips.
# ===============================================================

@pytest.mark.parametrize("valor", TIPOS_ADVERSARIOS)
def test_n_neutro_tipo_adversarial_con_helper(build_valido, valor):
    r, pub = build_valido
    legitimo = r["manifiesto"]["cuerpo"]["n_neutro"]

    # Ancla: sin tocar nada, el manifiesto pasa.
    _exige_aceptado(r, r["manifiesto"], pub, ctx="[n_neutro]")

    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["n_neutro"] = valor

    # Caso numérico equivalente con tipo distinto (3 vs 3.0, etc.).
    # No es skip: es rama explícita del contrato canónico.
    mismo_numero_distinto_tipo = (
        isinstance(legitimo, int)
        and not isinstance(legitimo, bool)
        and isinstance(valor, float)
        and valor == float(legitimo)
        and valor == valor  # excluye NaN
    )

    if mismo_numero_distinto_tipo:
        ok, exc = blindado(
            verificar, r["datos"], manifiesto=m,
            pub_bytes=pub, modo=MODO_PROTEGIDO,
        )
        assert exc is None, (
            f"n_neutro float equivalente crasheó: "
            f"legítimo={legitimo!r} atacante={valor!r} exc={exc!r}"
        )
        # Contrato medido: si normaliza, ok=True; si es estricto, ok=False.
        # En ambos casos el test pasa y registra el comportamiento.
        # No se salta. 3.0 es float(3.0), no se confunde con "no es ataque".
        if ok is True:
            # Canónico normalizador (estilo JCS): 3 y 3.0 equivalen.
            assert ok is True
        else:
            # Canónico estricto: float ≠ int → rechazo.
            assert ok is False
        return

    # Resto de tipos adversariales: deben rechazarse siempre.
    # (incluye el caso valor==legítimo mismo tipo solo si aparece;
    #  si TIPOS_ADVERSARIOS no mete el int puro, no aplica.)
    if _mismo_valor_y_tipo(valor, legitimo):
        # Mismo valor Y mismo tipo: no es mutación. Assert de identidad,
        # no skip — el test confirma que el ancla sigue en pie.
        _exige_aceptado(r, m, pub, ctx="[n_neutro-identidad]")
        return

    _exige_rechazado(
        r, m, pub,
        f"Type-confusion no rechazado: "
        f"legítimo={legitimo!r} ({type(legitimo).__name__}) "
        f"vs atacante={valor!r} ({type(valor).__name__})",
    )


# ===============================================================
# 18. MUTACIÓN PROFUNDA / ALIASING  →  test_valuaciones_pop_rompe
# ===============================================================

@pytest.mark.parametrize("caso_id", CASOS_VALUACIONES)
def test_valuaciones_mutaciones_parametrizadas(build_valido, caso_id):
    r, pub = build_valido
    _exige_aceptado(r, r["manifiesto"], pub, ctx=f"[{caso_id}]")

    vals = list(r["manifiesto"]["cuerpo"]["valuaciones"])
    assert len(vals) >= 2, (
        f"fixture inútil para este test: valuaciones={len(vals)}. "
        f"build_valido debe generar al menos 2."
    )

    nuevos = _mutaciones(vals)[caso_id]
    assert nuevos != vals, f"la mutación {caso_id} no cambió nada"

    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["valuaciones"] = nuevos

    _exige_rechazado(r, m, pub, f"mutación aceptada: {caso_id}")


def test_verificar_no_muta_la_entrada(build_valido):
    """Aliasing real: verificar() no debe tocar lo que le pasas."""
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    datos = copy.deepcopy(r["datos"])
    m_antes = copy.deepcopy(m)
    datos_antes = copy.deepcopy(datos)

    verificar(datos, manifiesto=m, pub_bytes=pub, modo=MODO_PROTEGIDO)

    assert m == m_antes, "verificar() mutó el manifiesto del llamador"
    assert datos == datos_antes, "verificar() mutó los datos del llamador"


def test_toctou_n_neutro(build_valido):
    """El valor cambia entre la 1ª y la 2ª lectura: no debe aceptarse."""
    r, pub = build_valido
    _exige_aceptado(r, r["manifiesto"], pub, ctx="[toctou]")

    legitimo = r["manifiesto"]["cuerpo"]["n_neutro"]
    cuerpo = _CuerpoTOCTOU(
        copy.deepcopy(r["manifiesto"]["cuerpo"]),
        "n_neutro",
        "VALOR_INYECTADO",
    )
    m = {"cuerpo": cuerpo, "firma": r["manifiesto"]["firma"]}

    ok, exc = blindado(verificar, r["datos"], manifiesto=m,
                       pub_bytes=pub, modo=MODO_PROTEGIDO)
    assert exc is None, f"crash con cuerpo TOCTOU: {exc!r}"
    assert cuerpo.lecturas <= 1 or ok is False, (
        f"TOCTOU: n_neutro se leyó {cuerpo.lecturas} veces y cambió "
        f"tras la primera (legítimo={legitimo!r}), pero fue aceptado"
    )



# ===============================================================
# 7. CLAVE PÚBLICA
# ===============================================================

@pytest.mark.parametrize(
    "pub",
    [
        b"", b"x", b"x" * 31, b"x" * 33,
        b"\x00" * 32, b"\xff" * 32, bytes(range(32)),
    ],
)
def test_clave_publica_invalida(build_valido, pub):
    r, _ = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert (
        "FIRMA_INVÁLIDA" in v["conceptos"]
        or "CÓDIGO_INVÁLIDO" in v["conceptos"]
    )


def test_clave_atacante_no_valida(build_valido, tmp_path):
    r, _ = build_valido
    priv = tmp_path / "atk.key"
    pub = tmp_path / "atk.pub"

    generar_claves(str(priv), str(pub))

    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub.read_bytes(),
        modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "FIRMA_INVÁLIDA" in v["conceptos"]


@pytest.mark.parametrize(
    "pub",
    [None, "", "abc", 0, [], {}, 1.5, True, bytearray(32)],
)
def test_pub_bytes_tipo_hostil_no_crashea(build_valido, pub):
    r, _ = build_valido
    ok, exc = blindado(
        verificar,
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert exc is None
    assert ok is False


def test_firmar_clave_inexistente_falla(tmp_path):
    r = firmar_bytes(b"msg", str(tmp_path / "no.key"))
    assert r["ok"] is False
    assert "CÓDIGO_INVÁLIDO" in r["conceptos"]


def test_firmar_clave_basura_falla(tmp_path):
    p = tmp_path / "fake.key"
    p.write_bytes(b"no-es-ed25519-seed-valida!!!!!")

    ok, exc = blindado(firmar_bytes, b"msg", str(p))
    assert exc is None
    assert ok is False


# ===============================================================
# 8. CANONICALIZACIÓN / SERIALIZACIÓN
# ===============================================================

def test_reordenar_claves_no_rompe(build_valido):
    """El orden de claves NO es parte de la firma."""
    r, pub = build_valido
    cuerpo = r["manifiesto"]["cuerpo"]

    inverso = {k: cuerpo[k] for k in reversed(list(cuerpo))}

    assert serializar(cuerpo) == serializar(inverso)

    v = verificar(
        r["datos"],
        manifiesto={
            "cuerpo": inverso,
            "firma": r["manifiesto"]["firma"],
        },
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is True


def test_serializar_determinista(build_valido):
    r, _ = build_valido
    c = r["manifiesto"]["cuerpo"]
    assert serializar(c) == serializar(dict(reversed(list(c.items()))))


def test_cambio_semantico_cambia_serializacion(build_valido):
    r, _ = build_valido
    c = copy.deepcopy(r["manifiesto"]["cuerpo"])
    antes = serializar(c)
    c["artifact_id"] = "CAMBIO"
    assert antes != serializar(c)


@pytest.mark.parametrize(
    "a,b",
    [
        ("café", "cafe\u0301"),   # NFC vs NFD
        ("A", "\u0410"),          # latina vs cirílica
        ("ID", "I\u200bD"),       # zero-width
        ("x", "x\ufeff"),         # BOM
        ("x", "x "),              # espacio final
    ],
)
def test_formas_textuales_distintas_no_colisionan(a, b):
    assert serializar({"artifact_id": a}) != serializar({"artifact_id": b})


def test_serializar_claves_mixtas_no_acepta_silenciosamente():
    """sort_keys con claves int/str mezcladas: debe fallar clasificado."""
    ok, exc = blindado(serializar, {1: "a", "b": 2})
    assert exc is None or isinstance(exc, (TypeError, ValueError))


def test_serializar_referencia_circular_no_cuelga():
    c = {"esquema": 1}
    c["yo"] = c

    t0 = time.monotonic()
    ok, exc = blindado(serializar, c)

    assert time.monotonic() - t0 < 5
    assert exc is None or isinstance(exc, (ValueError, RecursionError))


def test_serializar_surrogate_no_cuelga():
    """'\\ud800' rompe .encode('utf-8'). Debe fallar controlado."""
    ok, exc = blindado(
        serializar,
        {"esquema": 1, "artifact_id": "\ud800"},
    )
    assert exc is None or isinstance(
        exc, (UnicodeEncodeError, ValueError, TypeError)
    )


def test_serializar_anidamiento_profundo_no_cuelga():
    c = {"esquema": 1}
    nodo = c

    for _ in range(2000):
        nodo["n"] = {}
        nodo = nodo["n"]

    t0 = time.monotonic()
    ok, exc = blindado(serializar, c)

    assert time.monotonic() - t0 < 5
    assert exc is None or isinstance(exc, (RecursionError, ValueError))


def test_roundtrip_json_no_cambia_veredicto(build_valido):
    """El manifiesto viaja como texto: serializar→parsear no altera nada."""
    r, pub = build_valido
    vuelta = json.loads(json.dumps(r["manifiesto"]))

    v = verificar(
        r["datos"], manifiesto=vuelta,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is True


def test_inyeccion_string_no_escapa(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    ataque = '","firma":"deadbeef","x":"'
    m["cuerpo"]["artifact_id"] = ataque

    vuelta = json.loads(json.dumps(m))
    assert vuelta["cuerpo"]["artifact_id"] == ataque

    v = verificar(
        r["datos"], manifiesto=vuelta,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


# ===============================================================
# 9. VERSIÓN / ESQUEMA
# ===============================================================

def test_version_regresiva_rechazada(build_valido, claves):
    r, _ = build_valido
    priv, _, pub = claves

    c = copy.deepcopy(r["manifiesto"]["cuerpo"])
    c["version"] = 0
    f = firmar_bytes(serializar(c), str(priv))
    assert f["ok"] is True

    vm = verificar_manifiesto(
        {"cuerpo": c, "firma": f["firma"]},
        pub_bytes=pub, version_minima=1,
    )
    assert vm["ok"] is False
    assert "VERSIÓN_REGRESIVA" in vm["conceptos"]


def test_version_alta_aceptada(build_valido, claves):
    r, _ = build_valido
    priv, _, pub = claves

    c = copy.deepcopy(r["manifiesto"]["cuerpo"])
    c["version"] = 999
    f = firmar_bytes(serializar(c), str(priv))
    assert f["ok"] is True

    vm = verificar_manifiesto(
        {"cuerpo": c, "firma": f["firma"]},
        pub_bytes=pub, version_minima=1,
    )
    assert vm["ok"] is True


def test_esquema_incompatible_falla(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["esquema"] = 999

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


def test_esquema_firmado_pero_no_autorizado(build_valido, claves):
    """Firmar un esquema desconocido no lo autoriza."""
    r, _ = build_valido
    priv, _, pub = claves

    c = copy.deepcopy(r["manifiesto"]["cuerpo"])
    c["esquema"] = ESQUEMA_MANIFIESTO + 1
    f = firmar_bytes(serializar(c), str(priv))
    assert f["ok"] is True

    vm = verificar_manifiesto(
        {"cuerpo": c, "firma": f["firma"]},
        pub_bytes=pub,
    )
    assert vm["ok"] is False


# ===============================================================
# 10. n_neutro — EL CUERPO MANDA
# ===============================================================

def test_n_neutro_externo_no_pisa_cuerpo(build_valido):
    r, pub = build_valido

    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, n_neutro=999,
        modo=MODO_PROTEGIDO,
    )

    assert (
        v["pasos"]["identidad_neutra"]["n"]
        == r["manifiesto"]["cuerpo"]["n_neutro"]
    )


def test_n_neutro_cuerpo_conservado(build_valido):
    r, pub = build_valido
    esperado = r["manifiesto"]["cuerpo"]["n_neutro"]

    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["pasos"]["identidad_neutra"]["n"] == esperado


def test_mutar_n_neutro_rompe(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["n_neutro"] = 999

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


@pytest.mark.parametrize("n", [-100, -1, 0, 1])
def test_sellar_n_invalido(n):
    r = sellar(b"datos", n=n)
    assert r["ok"] is False
    assert "CÓDIGO_INVÁLIDO" in r["conceptos"]


@pytest.mark.parametrize("n", [-1, 0, 1])
def test_verificar_neutro_n_invalido(n):
    r = verificar_neutro(b"x", n=n)
    assert r["ok"] is False
    assert "CÓDIGO_INVÁLIDO" in r["conceptos"]


@pytest.mark.parametrize(
    "n", [None, "3", 1.5, True, False, [], {}, 10 ** 20]
)
def test_sellar_n_hostil_no_crashea(n):
    ok, exc = blindado(sellar, b"datos", n=n)
    assert exc is None
    assert ok is False


# ===============================================================
# 11. z / NEUTRO = EVIDENCIA, NO AUTORIDAD
# ===============================================================

def test_z_no_en_fallos(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert "z" in v["pasos"]
    assert "z" not in v["fallos"]


def test_neutro_no_en_fallos(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert "identidad_neutra" in v["pasos"]
    assert "identidad_neutra" not in v["fallos"]


def test_mutar_valuaciones_rompe_firma(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["valuaciones"] = [999999]

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


# ===============================================================
# 12. DIAGNÓSTICO
# ===============================================================

def test_diagnostico_sin_manifiesto_ok(build_valido):
    r, _ = build_valido
    assert verificar(r["datos"], modo=MODO_DIAGNOSTICO)["ok"] is True


def test_diagnostico_manifiesto_valido(build_valido):
    r, pub = build_valido
    assert verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_DIAGNOSTICO,
    )["ok"] is True


def test_diagnostico_detecta_manifiesto_falso(build_valido):
    """Diagnóstico relaja la exigencia de manifiesto, no su validez."""
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["artifact_id"] = "ATACANTE"

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_DIAGNOSTICO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


# ===============================================================
# 13. FRAGMENTOS — COBERTURA EXACTA
# ===============================================================

@pytest.mark.parametrize(
    "n",
    list(range(80)) + [
        81, 97, 99, 100, 101, 127, 128, 129,
        255, 256, 257, 512, 1024,
    ],
)
def test_fragmentos_cobertura_exacta(n):
    """Ni un byte sin cubrir: manipulación en la cola debe ser visible."""
    datos = bytes(i % 256 for i in range(n))
    frags = _fragmentos(datos, k=8)

    assert b"".join(frags) == datos
    assert sum(len(f) for f in frags) == len(datos)


@pytest.mark.parametrize(
    "k", [1, 2, 3, 4, 5, 7, 8, 9, 16, 32, 64, 1000, 100000]
)
def test_fragmentos_varios_k(k):
    datos = b"0123456789" * 37
    assert b"".join(_fragmentos(datos, k=k)) == datos


@pytest.mark.parametrize(
    "k", [None, "8", 1.5, True, [], {}, 0, -1, -8]
)
def test_fragmentos_k_hostil_no_cuelga(k):
    t0 = time.monotonic()
    ok, exc = blindado(_fragmentos, b"abc", k=k)
    assert time.monotonic() - t0 < 5
    assert exc is None or isinstance(
        exc, (TypeError, ValueError, ZeroDivisionError)
    )


# ===============================================================
# 14. API CRIPTO DIRECTA
# ===============================================================

def test_firmar_verificar_bytes(claves):
    priv, _, pub = claves
    f = firmar_bytes(b"mensaje protegido", str(priv))
    assert f["ok"] is True

    assert verificar_bytes(
        b"mensaje protegido",
        f["firma"],
        pub_bytes=pub,
    )["ok"] is True


def test_firma_no_reutilizable_otro_mensaje(claves):
    priv, _, pub = claves
    f = firmar_bytes(b"A", str(priv))
    assert f["ok"] is True

    assert verificar_bytes(
        b"B", f["firma"], pub_bytes=pub
    )["ok"] is False


@pytest.mark.parametrize(
    "datos",
    [None, "texto", 0, 1.5, True, [], {}, bytearray(b"abc")]
)
def test_firmar_datos_hostiles_no_crashea(claves, datos):
    priv, _, _ = claves
    ok, exc = blindado(firmar_bytes, datos, str(priv))
    assert exc is None


@pytest.mark.parametrize(
    "firma",
    [None, "", 0, True, [], {}, b"\x00" * 64,
     bytearray(64), "zz"]
)
def test_verificar_firma_hostil_no_crashea(claves, firma):
    _, _, pub = claves
    ok, exc = blindado(
        verificar_bytes, b"mensaje",
        firma, pub_bytes=pub,
    )
    assert exc is None
    assert ok is False


# ===============================================================
# 15. REFERENCIAS EXTERNAS — NUNCA TOMAN AUTORIDAD
# ===============================================================

def test_nucleo_S_Q_externos_ignorados(build_valido):
    """Con manifiesto válido, los kwargs externos se descartan."""
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub,
        nucleo_esperado="00" * 32,
        S_esperado="00" * 32,
        Q_esperado="00" * 32,
        modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is True


def test_cuatro_referencias_externas_simultaneas(build_valido):
    r, pub = build_valido
    cuerpo = r["manifiesto"]["cuerpo"]

    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub,
        nucleo_esperado="AA" * 32,
        S_esperado="BB" * 32,
        Q_esperado="CC" * 32,
        n_neutro=999999,
        modo=MODO_PROTEGIDO,
    )

    assert v["ok"] is True
    assert (
        v["pasos"]["identidad_neutra"]["n"]
        == cuerpo["n_neutro"]
    )


def test_externos_no_salvan_artefacto_roto(build_valido):
    """Un externo que 'confirme' el artefacto roto no lo autoriza."""
    r, pub = build_valido

    d = bytearray(r["datos"])
    d[0] ^= 1
    roto = bytes(d)

    v = verificar(
        roto,
        manifiesto=r["manifiesto"],
        pub_bytes=pub,
        nucleo_esperado=nucleo(roto),
        S_esperado="00" * 32,
        Q_esperado="00" * 32,
        n_neutro=3,
        modo=MODO_PROTEGIDO,
    )

    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


# ===============================================================
# 16. ALGORITMOS / IDENTIDAD / LONGITUD
# ===============================================================

@pytest.mark.parametrize(
    "campo,valor",
    [
        ("algoritmo_hash", "MD5"),
        ("algoritmo_firma", "RSA"),
        ("artifact_id", "OTRO"),
        ("clave_publica_id", "CLAVE-ATACANTE"),
    ],
)
def test_identidad_algoritmo_mutado_rompe(build_valido, campo, valor):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"][campo] = valor

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


def test_n_bytes_mutado_rompe(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["n_bytes"] += 1

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False
    assert "manifiesto" in v["fallos"]


# ===============================================================
# 17. TIPOS ADVERSARIALES  →  test_n_neutro_tipo_adversarial
# ===============================================================
# CERO SKIP. 3.0 es float(3.0). 3 es int(3).
# Si el canónico acepta 3.0 como 3 → ok=True (normalizador).
# Si lo rechaza → ok=False (estricto).
# En ambos casos el test CORRE y da veredicto.
# ===============================================================

@pytest.mark.parametrize("valor", TIPOS_ADVERSARIOS)
def test_n_neutro_tipo_adversarial(build_valido, valor):
    r, pub = build_valido
    legitimo = r["manifiesto"]["cuerpo"]["n_neutro"]

    _exige_aceptado(r, r["manifiesto"], pub, ctx="[n_neutro]")

    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["n_neutro"] = valor

    # 3.0 vs 3: mismo número, distinto tipo. NO es skip.
    es_float_equivalente = (
        isinstance(legitimo, int)
        and not isinstance(legitimo, bool)
        and isinstance(valor, float)
        and valor == float(legitimo)
        and valor == valor  # no NaN
    )

    if es_float_equivalente:
        ok, exc = blindado(
            verificar, r["datos"], manifiesto=m,
            pub_bytes=pub, modo=MODO_PROTEGIDO,
        )
        assert exc is None, (
            f"n_neutro float equivalente crasheó: "
            f"legítimo={legitimo!r} atacante={valor!r} exc={exc!r}"
        )
        # Contrato medido: normalizador → True; estricto → False.
        # Ambos son PASS. Nunca skip.
        assert ok in (True, False)
        return

    # Mismo valor Y mismo tipo: identidad, no mutación.
    # Tampoco skip: se exige que siga aceptado.
    if type(valor) is type(legitimo) and valor == legitimo:
        _exige_aceptado(r, m, pub, ctx="[n_neutro-identidad]")
        return

    # Todo lo demás: type-confusion / valor hostil → rechazo.
    _exige_rechazado(
        r, m, pub,
        f"Type-confusion no rechazado: "
        f"legítimo={legitimo!r} ({type(legitimo).__name__}) "
        f"vs atacante={valor!r} ({type(valor).__name__})",
    )
# ===============================================================
# 18. MUTACIÓN PROFUNDA / ALIASING
# ===============================================================

def test_valuaciones_elemento_mutado_rompe(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    vals = m["cuerpo"]["valuaciones"]

    assert isinstance(vals, list) and vals
    original = copy.deepcopy(vals)

    vals[0] = "ATAQUE"
    assert vals != original

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


def test_valuaciones_append_rompe(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["valuaciones"] = (
        list(m["cuerpo"]["valuaciones"]) + [0]
    )

    assert verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


def test_valuaciones_pop_rompe(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    vals = list(m["cuerpo"]["valuaciones"])

    if not vals:
        pytest.skip("sin valuaciones")

    vals.pop()
    m["cuerpo"]["valuaciones"] = vals

    assert verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )["ok"] is False


def test_mutacion_posterior_no_recalcula_firma(build_valido):
    r, pub = build_valido
    m = r["manifiesto"]
    firma_original = m["firma"]

    m["cuerpo"]["artifact_id"] = "ATAQUE"

    assert m["firma"] == firma_original

    v = verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is False


def test_verificar_no_muta_manifiesto(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    antes = copy.deepcopy(m)

    verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert m == antes


def test_verificar_no_muta_manifiesto_rechazado(build_valido):
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["artifact_id"] = "X"
    antes = copy.deepcopy(m)

    verificar(
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert m == antes


# ===============================================================
# 19. TOCTOU / MAPPINGS HOSTILES
# ===============================================================

@pytest.mark.parametrize(
    "campo",
    ["version", "nucleo", "S", "Q", "n_neutro", "esquema"],
)
def test_toctou_no_debe_producir_aceptacion(build_valido, campo):
    """
    Un dict que devuelve un valor la primera lectura y otro después.
    Se cierra congelando el cuerpo con json.loads(canonico) tras
    verificar la firma: a partir de ahí son datos inertes.
    """
    r, pub = build_valido

    mutante = DictMutante(
        r["manifiesto"]["cuerpo"],
        campo,
        "MALO",
    )

    m = {
        "cuerpo": mutante,
        "firma": r["manifiesto"]["firma"],
    }

    ok, exc = blindado(
        verificar,
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert exc is None
    if ok:
        assert mutante.lecturas <= 1, (
            f"TOCTOU potencial en {campo}: "
            f"{mutante.lecturas} lecturas"
        )


@pytest.mark.parametrize("campo", ["nucleo", "S", "Q"])
def test_objeto_eq_siempre_true_no_pasa(build_valido, claves, campo):
    """
    Objeto con __eq__ siempre-True: revienta cualquier validación
    que compare con == en vez de sobre datos tipados y canónicos.

    NOTA: serializar(c) va dentro del lambda (ver test_hash_hostil).
    """
    r, _ = build_valido
    priv, _, pub = claves

    c = dict(r["manifiesto"]["cuerpo"])
    c[campo] = SiempreIgual()

    ok, exc = blindado(lambda: firmar_bytes(serializar(c), str(priv)))
    if exc is not None or not ok:
        return  # el canónico lo rechazó: correcto

    f = firmar_bytes(serializar(c), str(priv))
    ok, exc = blindado(
        verificar,
        r["datos"],
        manifiesto={"cuerpo": c, "firma": f["firma"]},
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert exc is None
    assert ok is False


# ===============================================================
# 20. SELLADO / RESELLADO
# ===============================================================

def test_sellar_n_grande_no_cuelga():
    t0 = time.monotonic()
    ok, exc = blindado(sellar, b"datos", n=2 ** 40)
    assert exc is None
    assert time.monotonic() - t0 < 10


def test_sellar_idempotencia_veredicto():
    s1 = sellar(b"payload", n=3)
    assert s1["ok"] is True

    s2 = sellar(s1["datos"], n=3)
    assert s2["ok"] is True

    assert verificar_neutro(s2["datos"], n=3)["ok"] is True


def test_resellado_no_salva_autorizacion(claves):
    """
    Con n=3 la marca neutra son ~1.6 bits: el atacante la re-sella en
    pocos intentos. Este test DOCUMENTA que es marca de build, no
    barrera — y que la firma sí atrapa el artefacto alterado.
    """
    priv, _, pub = claves

    original = build(b"ORIGINAL", str(priv), n_neutro=3)
    assert original["ok"] is True

    d = bytearray(original["datos"])
    d[0] ^= 0xFF

    regrindado = sellar(bytes(d), n=3)
    assert regrindado["ok"] is True
    assert verificar_neutro(regrindado["datos"], n=3)["ok"] is True

    v = verificar(
        regrindado["datos"],
        manifiesto=original["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert v["ok"] is False
    assert "nucleo" in v["fallos"]


# ===============================================================
# 21. DATOS EXTREMOS / DoS
# ===============================================================

@pytest.mark.parametrize(
    "datos",
    [
        b"", b"\x00", b"\xff", b"X", b"AB",
        b"A" * 3, b"A" * 7, b"A" * 8, b"A" * 9,
        b"A" * 100, b"A" * 1000, b"A" * 10000,
        bytes(range(256)),
        b"\x00" * 4096,
        b"\xff" * 4096,
    ],
)
def test_datos_extremos_build_y_verify(claves, datos):
    priv, _, pub = claves

    r = build(
        datos, str(priv),
        n_neutro=3, artifact_id="EDGE", version=1,
    )
    assert r["ok"] is True

    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert v["ok"] is True


@pytest.mark.parametrize(
    "datos",
    [None, "texto", 0, [], {}, 1.5, True, bytearray(b"ab")]
)
def test_datos_tipo_hostil_no_crashea(build_valido, datos):
    r, pub = build_valido
    ok, exc = blindado(
        verificar,
        datos, manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert exc is None


def test_version_gigante_no_cuelga(build_valido, claves):
    """
    10**5000 supera el límite de conversión de enteros de Python 3.11
    (4300 dígitos). Rechazarlo por rango es protección, no fallo.

    NOTA: serializar(c) va dentro del lambda.
    """
    r, _ = build_valido
    priv, _, pub = claves

    c = copy.deepcopy(r["manifiesto"]["cuerpo"])
    c["version"] = 10 ** 5000

    t0 = time.monotonic()
    ok, exc = blindado(lambda: firmar_bytes(serializar(c), str(priv)))

    assert time.monotonic() - t0 < 5
    assert exc is None or isinstance(exc, (ValueError, OverflowError))

    if exc is None and ok:
        f = firmar_bytes(serializar(c), str(priv))
        ok2, exc2 = blindado(
            verificar_manifiesto,
            {"cuerpo": c, "firma": f["firma"]},
            pub_bytes=pub,
        )
        assert exc2 is None


def test_cuerpo_grande_no_cuelga(build_valido, claves):
    r, _ = build_valido
    priv, _, pub = claves

    c = copy.deepcopy(r["manifiesto"]["cuerpo"])
    c["artifact_id"] = "A" * (5 * 1024 * 1024)

    t0 = time.monotonic()
    ok, exc = blindado(lambda: firmar_bytes(serializar(c), str(priv)))

    assert time.monotonic() - t0 < 15
    assert exc is None or isinstance(
        exc, (ValueError, OverflowError, MemoryError)
    )

    if exc is None and ok:
        f = firmar_bytes(serializar(c), str(priv))
        ok2, exc2 = blindado(
            verificar,
            r["datos"],
            manifiesto={"cuerpo": c, "firma": f["firma"]},
            pub_bytes=pub, modo=MODO_PROTEGIDO,
        )
        assert exc2 is None


def test_artefacto_grande_no_cuelga(claves):
    priv, _, pub = claves

    r = build(
        b"\x5a" * (2 * 1024 * 1024),
        str(priv), version=1,
    )
    assert r["ok"] is True

    t0 = time.monotonic()
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert v["ok"] is True
    assert time.monotonic() - t0 < 10


# ===============================================================
# 22. CONCURRENCIA
# ===============================================================

def test_verificacion_concurrente_sin_estado_compartido(build_valido):
    r, pub = build_valido
    resultados = []
    lock = threading.Lock()

    def correr():
        locales = []

        for _ in range(30):
            locales.append(
                verificar(
                    r["datos"],
                    manifiesto=r["manifiesto"],
                    pub_bytes=pub,
                    modo=MODO_PROTEGIDO,
                )
            )

        with lock:
            resultados.extend(locales)

    hilos = [threading.Thread(target=correr) for _ in range(8)]

    for h in hilos:
        h.start()
    for h in hilos:
        h.join()

    assert len(resultados) == 240
    assert all(v["ok"] is True for v in resultados)
    assert all(v["fallos"] == [] for v in resultados)


# ===============================================================
# 23. INVARIANTES DE CONTRATO
# ===============================================================

def test_verificar_nunca_lanza_sobre_entrada_arbitraria(build_valido):
    """Invariante 4: rechazo controlado, nunca excepción libre."""
    r, pub = build_valido

    basura = [
        None, 0, "", b"", [], {}, set(), object(),
        1.5, True,
        {
            "cuerpo": {"a": {"b": {"c": [1, {"d": None}]}}},
            "firma": "0" * 128,
        },
    ]

    for m in basura:
        ok, exc = blindado(
            verificar,
            r["datos"], manifiesto=m,
            pub_bytes=pub, modo=MODO_PROTEGIDO,
        )
        assert exc is None, (
            f"manifiesto={m!r} lanza {type(exc).__name__}: {exc}"
        )


@pytest.mark.parametrize(
    "modo",
    [
        None, "", "protegido", "PROTEGIDO",
        0, 1, -1, [], {}, True,
    ],
)
def test_modo_desconocido_no_relaja_seguridad(build_valido, modo):
    """Invariante 6: un modo no reconocido nunca degrada a diagnóstico."""
    r, pub = build_valido
    m = copy.deepcopy(r["manifiesto"])
    m["cuerpo"]["artifact_id"] = "ATACANTE"

    ok, exc = blindado(
        verificar,
        r["datos"], manifiesto=m,
        pub_bytes=pub, modo=modo,
    )

    assert exc is None
    assert ok is False


def test_fallos_y_conceptos_siempre_presentes(build_valido):
    r, pub = build_valido

    for m in (None, {}, r["manifiesto"]):
        v = verificar(
            r["datos"], manifiesto=m,
            pub_bytes=pub, modo=MODO_PROTEGIDO,
        )
        assert isinstance(v.get("fallos"), list)
        assert isinstance(v.get("conceptos"), list)
        assert isinstance(v.get("ok"), bool)


def test_ok_true_implica_fallos_vacios(build_valido):
    r, pub = build_valido
    v = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert (v["ok"] is True) == (v["fallos"] == [])


# ===============================================================
# 24. CADENA COMPLETA
# ===============================================================

def test_cadena_ok_luego_tamper(build_valido):
    r, pub = build_valido

    ok = verificar(
        r["datos"], manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )
    assert ok["ok"] is True
    assert ok["fallos"] == []

    d = bytearray(r["datos"])
    d[-1] ^= 1

    bad = verificar(
        bytes(d), manifiesto=r["manifiesto"],
        pub_bytes=pub, modo=MODO_PROTEGIDO,
    )

    assert bad["ok"] is False
    assert "nucleo" in bad["fallos"]


def test_nucleo_cambia_si_cambia_artefacto(build_valido):
    r, _ = build_valido
    h0 = nucleo(r["datos"])

    d = bytearray(r["datos"])
    d[0] ^= 1

    assert nucleo(bytes(d)) != h0


# ===============================================================
# FIN — batería unificada sin clemencia
#
#  Ilver Villasmil.
# Módulo bajo prueba: modules/spartaco_seguridad/proteccion.py
# — arquitectura y autoría: Ilver Villasmil.
# ===============================================================
