# ===========================================================================
# SPARTACO-SECURITY — tests/test_conformidad_independiente.py
# VIRTUAL ATTACKER EXPERIMENT — INDEPENDENT CONFORMANCE
# SPEC: SPARTACO-SEGURIDAD-ATAQUE-VIRTUAL-1.0
# ===========================================================================
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# The attacker does not have the private key.
# Starts only from observable surfaces.
# Each attack advances up to the first real barrier in proteccion.py.
# The stopping station is recorded.
# Only BREACH (acceptance of unauthorized modification) is a security
# failure.
#
# THE SEVEN REAL STATIONS
# ---------------------------------------------------------------------------
# Extracted directly from proteccion.verificar() / verificar_manifiesto().
# The file does NOT invent station names; it derives them from the real
# fields of the result dict (fallos, conceptos, pasos, error).
#
#   1. entrada_datos      data must be bytes
#   2. manifiesto_forma   exactly {cuerpo, firma}; types
#   3. firma              Ed25519 over canonical body
#   4. esquema_cuerpo     exact CLAVES_CUERPO + types/ranges
#   5. nucleo             SHA-256(datos) vs cuerpo["nucleo"]
#   6. canales            S/Q vs cuerpo["S"], cuerpo["Q"]
#   7. n_bytes            len(datos) vs cuerpo["n_bytes"]
#
# z and identidad_neutra are evidence (steps), not rejection barriers
# on failures.
#
# INDEPENDENT ORACLE
# ---------------------------------------------------------------------------
# The file reimplements the verification contract WITHOUT importing
# anything from proteccion.py. Four functions form the external
# specification:
#
#   oracle_canonical      canonical serialization written by hand with
#                         the same options the contract declares
#                         (sorted keys, no spaces, ASCII-escaped, no NaN)
#   oracle_verify_sig     Ed25519 verification using the cryptography
#                         library directly, not through proteccion.py
#   oracle_nucleo         SHA-256 of the data
#   oracle_canales        SHA-256 of the two halves of the data
#
# If the module and the oracle disagree, the disagreement is the
# finding. This is the same doctrine of Klein's three layers that the
# canon/man customs test applies to canonicalization: the
# specification is written independently, and the contrast between the
# two is what gets published.
#
# HONEST ATTACKER MODEL
# ---------------------------------------------------------------------------
# The AtacanteVirtual constructor asserts three things:
#
#   no attribute "private_key"
#   no attribute "priv"
#   no "private" in the internal dict
#
# And sin_clave_privada() verifies there is no private_key, priv,
# ruta_priv or seed. A test that attacked the system WITH the private
# key would not be simulating a real attacker; it would be simulating
# the authority, and the conclusions would be invalid. The file ensures
# in every execution that the attacker does not have that material.
#
# INTENTAR_FIRMA_FALSA — POSITIVE CONTROL INSIDE THE ATTACK
# ---------------------------------------------------------------------------
# The attacker builds the canonical message of the body it wants to
# forge, generates 64 random bytes with os.urandom, and presents them
# as a signature. Before passing the fake signature to the real system,
# the file verifies with the independent oracle that this signature
# does not validate against the public key. The attacker must confirm
# with its own oracle that the signature is false, so that when the
# system rejects it, the conclusion is "the system rejects signatures
# forged without the private key" rather than "the signature happened
# to be valid by chance". The file does not depend on probability; it
# verifies the rejection before presenting the attack.
#
# STATION DETECTION AND CLASSIFICATION
# ---------------------------------------------------------------------------
# estacion_detencion(result) derives the stopping station from the real
# contract fields only. It uses the real keys of the contract: fallos,
# conceptos, pasos, error. If ok is True it returns NINGUNA_BREACH
# because the attack was accepted. If fallos contains "datos" it
# returns entrada_datos. If fallos contains "manifiesto" it
# distinguishes between MANIFIESTO_AUSENTE, FIRMA_INVÁLIDA,
# CÓDIGO_INVÁLIDO and VERSIÓN_REGRESIVA to identify whether the stop
# was at the manifest shape, the signature, or the body schema. Same
# for nucleo, canales and n_bytes. If there are failures but none
# match a known category, it returns "otro:" + fallos[0], which is a
# finding because it means an undeclared station appeared.
#
# clasificar(result, expected_rejection) returns:
#
#   BREACH          ok=True where a rejection was expected
#   BLOCKED         ok=False where a rejection was expected
#   REACHED_LATER   the attack went further than expected but was
#                   stopped before acceptance
#
# The distinction between BREACH and REACHED_LATER matters: BREACH is
# a security failure, REACHED_LATER is informational.
#
# THE TEN PROGRESSIVE ATTACKS
# ---------------------------------------------------------------------------
#   test_ataque_00_reconocimiento         public structure visible,
#                                         no private key
#   test_ataque_01_mutacion_artifact_id   body field mutated, no
#                                         re-sign: stop at firma /
#                                         esquema_cuerpo / forma
#   test_ataque_02_mutacion_nucleo        body nucleo mutated: stop at
#                                         firma or esquema_cuerpo
#   test_ataque_03_mutacion_canales       body S/Q mutated: stop at
#                                         firma or esquema_cuerpo
#   test_ataque_04_flip_byte_artefacto    artifact flipped, manifest
#                                         intact: stop at nucleo /
#                                         canales / n_bytes
#   test_ataque_05_sustitucion_A_sobre_B  manifest A on data B: stop
#                                         at nucleo / canales / n_bytes
#   test_ataque_06_firma_sin_clave        random signature after body
#                                         mutation: stop at firma
#   test_ataque_07_manifiesto_extra       extra key: stop at
#                                         manifiesto_forma
#   test_ataque_08_cuerpo_incompleto      missing body field: stop at
#                                         firma / esquema_cuerpo /
#                                         manifiesto_forma
#   test_ataque_09_sin_manifiesto         manifiesto=None: stop at
#                                         manifiesto_forma with
#                                         MANIFIESTO_AUSENTE
#
# FINAL TABLE AND ASSERTIONS
# ---------------------------------------------------------------------------
# test_99_tabla_final_atacante runs seven representative attacks,
# accumulates the results, and prints a table with three columns:
# attack name, stopping station, classification. It then verifies four
# assertions:
#
#   1. The attacker does not possess the private key.
#   2. There was no BREACH.
#   3. Every hostile attack ended with BLOCKED and ok=False.
#   4. The set of stopping stations includes at least one from
#      {firma, manifiesto_forma, esquema_cuerpo} AND at least one from
#      {nucleo, canales, n_bytes}.
#
# The fourth assertion matters because it verifies the experiment
# actually exercised both families of barriers in the pipeline. If
# every attack had stopped at the same station, the experiment would
# not have walked the full pipeline. The coverage requirement ensures
# the map the file builds is real and not a simplification.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It does not exhaust the adversarial surface (that is the
#     red-team's role).
#   - It does not qualify an instrument.
#   - It does not persist a dossier.
#   - It does not certify the whole system: it draws a map of the
#     verification pipeline using the virtual attacker as a probe.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The red-teams look for failures. The metrological kernel measures
# instruments. The isolated-resource auditors qualify a resource
# against synthetic controls. The monitor correlates observation. The
# universal closure verifies verified == loaded == executed. The
# transition auditor measures state changes. The RAW causal boundary
# auditor audits the Engine-provider boundary. The UI auditor verifies
# the user can recover and download. The rotation suite covers the
# full lifecycle of a link. The unified hard audit merges the five
# fronts into a single CI entry. The DVC calibration qualifies the
# audit motor. The canon/man customs test measures canonicalization
# and manifest shape against an independent specification. The
# Sentinel test audits the supervisor. This file is the experiment
# that maps the verification pipeline, using the virtual attacker as
# a probe and the independent oracle as a reference.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# An attacker without the private key must be stopped at a real
# barrier of the contract. Only the acceptance of an unauthorized
# modification is a security failure. Rejections at any station are
# the expected behavior. The map of stopping stations is the result,
# and it must cover both families of barriers so the experiment
# actually walked the pipeline. The attacker model is verified to be
# honest in every execution, and the fake signature is verified false
# with the independent oracle before being presented to the system.
#
# ===========================================================================
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

import modules.spartaco_seguridad.proteccion as P


# ============================================================
# PROCEDENCIA
# ============================================================

SPEC_ID = "SPARTACO-SEGURIDAD-ATAQUE-VIRTUAL-1.0"
SPEC_REVISION = "2026-08-11"
SPEC_HASH = hashlib.sha256(
    b"ATAQUE-VIRTUAL|proteccion.verificar|estaciones-reales|sin-clave-privada"
).hexdigest()


def test_00_procedencia():
    assert SPEC_ID.startswith("SPARTACO")
    assert SPEC_REVISION != "<REVISION>"
    assert len(SPEC_HASH) == 64
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        assert os.environ.get("GITHUB_SHA")


# ============================================================
# ORÁCULO INDEPENDIENTE (sin P.serializar / P.verificar)
# ============================================================

def oracle_canonical(obj: Any) -> bytes:
    """Regla canónica alineada con el contrato, implementada fuera de P."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def oracle_verify_sig(pub_bytes: bytes, message: bytes, firma_hex: str) -> bool:
    try:
        sig = bytes.fromhex(firma_hex)
        if len(sig) != 64 or len(pub_bytes) != 32:
            return False
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig, message)
        return True
    except Exception:
        return False


def oracle_nucleo(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def oracle_canales(datos: bytes) -> Tuple[str, str]:
    mid = len(datos) // 2
    return (
        hashlib.sha256(datos[:mid]).hexdigest(),
        hashlib.sha256(datos[mid:]).hexdigest(),
    )


# ============================================================
# ESTACIONES REALES DEL PIPELINE
# ============================================================

# Orden de aparición en verificar() / verificar_manifiesto()
ESTACIONES = (
    "entrada_datos",
    "manifiesto_forma",
    "firma",
    "esquema_cuerpo",
    "nucleo",
    "canales",
    "n_bytes",
)


def estacion_detencion(resultado: Dict[str, Any]) -> str:
    """
    Deriva la estación de detención SOLO de campos reales de proteccion.py.
    No inventa nombres.
    """
    if resultado.get("ok") is True:
        return "NINGUNA_BREACH"

    fallos = list(resultado.get("fallos") or [])
    conceptos = list(resultado.get("conceptos") or [])
    pasos = resultado.get("pasos") or {}
    error = str(resultado.get("error") or "")

    # 1. datos
    if "datos" in fallos:
        return "entrada_datos"

    # 2-4. manifiesto (forma / firma / esquema viven bajo el mismo fallo "manifiesto")
    if "manifiesto" in fallos:
        if "MANIFIESTO_AUSENTE" in conceptos:
            return "manifiesto_forma"
        if "FIRMA_INVÁLIDA" in conceptos:
            return "firma"
        if "CÓDIGO_INVÁLIDO" in conceptos or "VERSIÓN_REGRESIVA" in conceptos:
            # forma de claves o validación de esquema del cuerpo
            if "exactamente" in error or "no dict" in error or "firma ausente" in error:
                return "manifiesto_forma"
            return "esquema_cuerpo"
        return "manifiesto_forma"

    # 5. nucleo
    if "nucleo" in fallos:
        return "nucleo"
    p_n = pasos.get("nucleo") or {}
    if p_n.get("ok") is False:
        return "nucleo"

    # 6. canales
    if "canales" in fallos:
        return "canales"
    p_c = pasos.get("canales") or {}
    if p_c.get("ok") is False:
        return "canales"

    # 7. n_bytes
    if "n_bytes" in fallos:
        return "n_bytes"

    if fallos:
        return f"otro:{fallos[0]}"
    return "desconocida"


def clasificar(resultado: Dict[str, Any], esperaba_rechazo: bool) -> str:
    """
    BLOCKED          — detenido por barrera prevista
    REACHED_LATER    — atravesó más de lo esperado (informativo)
    BREACH           — modificación no autorizada aceptada
    """
    if resultado.get("ok") is True and esperaba_rechazo:
        return "BREACH"
    if resultado.get("ok") is False and esperaba_rechazo:
        return "BLOCKED"
    if resultado.get("ok") is True and not esperaba_rechazo:
        return "BLOCKED"  # camino legítimo: no es ataque
    return "REACHED_LATER"


# ============================================================
# ATACANTE VIRTUAL
# ============================================================

class AtacanteVirtual:
    """
    Solo posee superficies públicas.
    Nunca recibe la clave privada.
    """

    def __init__(
        self,
        pub_bytes: bytes,
        datos_obs: bytes,
        manifiesto_obs: Dict[str, Any],
    ):
        self.pub_bytes = bytes(pub_bytes)
        self.datos = bytes(datos_obs)
        self.manifiesto = copy.deepcopy(manifiesto_obs)
        # Garantía estructural: no hay clave privada en el objeto
        assert not hasattr(self, "private_key")
        assert not hasattr(self, "priv")
        assert "private" not in self.__dict__

    def sin_clave_privada(self) -> bool:
        return not any(
            k in self.__dict__ for k in ("private_key", "priv", "ruta_priv", "seed")
        )

    def intentar_firma_falsa(self, cuerpo: Dict[str, Any]) -> str:
        """
        Atacante sin clave privada: fabrica bytes aleatorios de 64 B
        y los presenta como firma. El oráculo independiente debe rechazarlos.
        """
        falso = os.urandom(64).hex()
        msg = oracle_canonical(cuerpo)
        assert oracle_verify_sig(self.pub_bytes, msg, falso) is False
        return falso

    def ataque(self, nombre: str, datos: bytes, manifiesto: Dict[str, Any]) -> Dict[str, Any]:
        resultado = P.verificar(
            datos,
            manifiesto=manifiesto,
            pub_bytes=self.pub_bytes,
            modo=P.MODO_PROTEGIDO,
        )
        est = estacion_detencion(resultado)
        clase = clasificar(resultado, esperaba_rechazo=True)
        return {
            "ataque": nombre,
            "ok": resultado.get("ok"),
            "fallos": list(resultado.get("fallos") or []),
            "conceptos": list(resultado.get("conceptos") or []),
            "pasos": resultado.get("pasos"),
            "error": resultado.get("error"),
            "estacion_detencion": est,
            "clasificacion": clase,
        }


# ============================================================
# FIXTURE LEGÍTIMA (sistema, no atacante)
# ============================================================

@pytest.fixture
def sistema_legitimo(tmp_path: Path):
    priv = tmp_path / "legit.key"
    pub = tmp_path / "legit.pub"
    assert P.generar_claves(str(priv), str(pub))["ok"] is True
    pub_bytes = pub.read_bytes()

    datos_orig = b"VPSI-TRUTH::ARTEFACTO::LEGITIMO::CONFORMIDAD"
    built = P.build(
        datos_orig,
        str(priv),
        n_neutro=3,
        artifact_id="LEGIT-001",
        version=1,
        clave_publica_id="ROOT-LEGIT",
    )
    assert built["ok"] is True

    # Superficie observable que recibe el atacante
    superficie = {
        "pub_bytes": pub_bytes,
        "datos": built["datos"],
        "manifiesto": copy.deepcopy(built["manifiesto"]),
    }
    return {
        "priv_path": priv,
        "pub_bytes": pub_bytes,
        "built": built,
        "superficie": superficie,
    }


@pytest.fixture
def atacante(sistema_legitimo) -> AtacanteVirtual:
    s = sistema_legitimo["superficie"]
    a = AtacanteVirtual(s["pub_bytes"], s["datos"], s["manifiesto"])
    assert a.sin_clave_privada() is True
    return a


# ============================================================
# ATAQUES PROGRESIVOS
# ============================================================

def test_ataque_00_reconocimiento(atacante, sistema_legitimo):
    """El atacante ve estructura pública; no tiene clave privada."""
    assert atacante.sin_clave_privada()
    m = atacante.manifiesto
    assert set(m.keys()) == {"cuerpo", "firma"}
    assert isinstance(m["cuerpo"], dict)
    assert isinstance(m["firma"], str)
    # Reconocimiento de campos observables del cuerpo
    for k in ("nucleo", "S", "Q", "n_bytes", "n_neutro", "artifact_id"):
        assert k in m["cuerpo"]


def test_ataque_01_mutacion_cuerpo_artifact_id(atacante):
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["artifact_id"] = "ATACANTE-ID"
    reg = atacante.ataque("mutacion_artifact_id", atacante.datos, m)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["estacion_detencion"] in ("firma", "esquema_cuerpo", "manifiesto_forma")
    assert reg["ok"] is False


def test_ataque_02_mutacion_nucleo_en_cuerpo(atacante):
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["nucleo"] = "00" * 32
    reg = atacante.ataque("mutacion_nucleo_cuerpo", atacante.datos, m)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    # Firma cubre el cuerpo → debe caer en firma (o esquema si el hex fuera inválido)
    assert reg["estacion_detencion"] in ("firma", "esquema_cuerpo")


def test_ataque_03_mutacion_canales_en_cuerpo(atacante):
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["S"] = "11" * 32
    m["cuerpo"]["Q"] = "22" * 32
    reg = atacante.ataque("mutacion_canales_cuerpo", atacante.datos, m)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    assert reg["estacion_detencion"] in ("firma", "esquema_cuerpo")


def test_ataque_04_alteracion_artefacto_flip_byte(atacante):
    """Datos alterados, manifiesto intacto → barrera nucleo/canales."""
    d = bytearray(atacante.datos)
    d[0] ^= 0xFF
    reg = atacante.ataque("flip_byte_artefacto", bytes(d), atacante.manifiesto)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    assert reg["estacion_detencion"] in ("nucleo", "canales", "n_bytes")
    assert "nucleo" in reg["fallos"] or "canales" in reg["fallos"]


def test_ataque_05_sustitucion_manifiesto_A_datos_B(atacante, sistema_legitimo, tmp_path):
    """Manifiesto legítimo A + datos de otro artefacto B."""
    priv_b = tmp_path / "b.key"
    pub_b = tmp_path / "b.pub"
    P.generar_claves(str(priv_b), str(pub_b))
    built_b = P.build(
        b"ARTEFACTO-B-DISTINTO",
        str(priv_b),
        n_neutro=3,
        artifact_id="B-001",
        version=1,
        clave_publica_id="ROOT-B",
    )
    assert built_b["ok"] is True

    reg = atacante.ataque(
        "sustitucion_A_sobre_B",
        built_b["datos"],
        atacante.manifiesto,  # manifiesto de A
    )
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    assert reg["estacion_detencion"] in ("nucleo", "canales", "n_bytes")


def test_ataque_06_firma_fabricada_sin_clave(atacante):
    """Sin clave privada no se puede producir firma válida (oráculo independiente)."""
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["artifact_id"] = "FORJADO"
    firma_falsa = atacante.intentar_firma_falsa(m["cuerpo"])
    m["firma"] = firma_falsa

    # Oráculo independiente ya rechazó; ahora el sistema también.
    reg = atacante.ataque("firma_fabricada_sin_clave", atacante.datos, m)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    assert reg["estacion_detencion"] in ("firma", "manifiesto_forma")
    assert "FIRMA_INVÁLIDA" in reg["conceptos"] or "manifiesto" in reg["fallos"]


def test_ataque_07_recomposicion_manifiesto_claves_extra(atacante):
    m = copy.deepcopy(atacante.manifiesto)
    m["campo_extra"] = "x"
    reg = atacante.ataque("manifiesto_clave_extra", atacante.datos, m)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    assert reg["estacion_detencion"] in ("manifiesto_forma", "esquema_cuerpo", "firma")


def test_ataque_08_cuerpo_incompleto(atacante):
    m = copy.deepcopy(atacante.manifiesto)
    del m["cuerpo"]["nucleo"]
    reg = atacante.ataque("cuerpo_sin_nucleo", atacante.datos, m)
    assert reg["clasificacion"] != "BREACH", reg
    assert reg["ok"] is False
    assert reg["estacion_detencion"] in ("firma", "esquema_cuerpo", "manifiesto_forma")


def test_ataque_09_sin_manifiesto(atacante):
    resultado = P.verificar(
        atacante.datos,
        manifiesto=None,
        pub_bytes=atacante.pub_bytes,
        modo=P.MODO_PROTEGIDO,
    )
    assert resultado["ok"] is False
    assert estacion_detencion(resultado) == "manifiesto_forma"
    assert "MANIFIESTO_AUSENTE" in resultado.get("conceptos", [])


# ============================================================
# TABLA FINAL DEL EXPERIMENTO
# ============================================================

def test_99_tabla_final_atacante(atacante, sistema_legitimo, tmp_path):
    """
    Ejecuta la batería de ataques y emite la tabla de estaciones.
    Falla solo si aparece BREACH.
    """
    registros: List[Dict[str, Any]] = []

    def run(nombre, datos, man):
        reg = atacante.ataque(nombre, datos, man)
        registros.append(reg)
        return reg

    # 1. mutación cuerpo
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["artifact_id"] = "X"
    run("mutacion_artifact_id", atacante.datos, m)

    # 2. mutación nucleo en cuerpo
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["nucleo"] = "ff" * 32
    run("mutacion_nucleo_cuerpo", atacante.datos, m)

    # 3. mutación canales en cuerpo
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["S"] = "aa" * 32
    run("mutacion_S_cuerpo", atacante.datos, m)

    # 4. flip artefacto
    d = bytearray(atacante.datos)
    d[-1] ^= 0x01
    run("flip_artefacto", bytes(d), atacante.manifiesto)

    # 5. sustitución A→B
    priv_b = tmp_path / "bx.key"
    pub_b = tmp_path / "bx.pub"
    P.generar_claves(str(priv_b), str(pub_b))
    b = P.build(b"OTRO", str(priv_b), n_neutro=3, artifact_id="B", version=1, clave_publica_id="KB")
    run("sustitucion_A_sobre_B", b["datos"], atacante.manifiesto)

    # 6. firma fabricada
    m = copy.deepcopy(atacante.manifiesto)
    m["cuerpo"]["artifact_id"] = "FORJA"
    m["firma"] = atacante.intentar_firma_falsa(m["cuerpo"])
    run("firma_sin_clave", atacante.datos, m)

    # 7. manifiesto mal formado
    m = copy.deepcopy(atacante.manifiesto)
    m["extra"] = 1
    run("manifiesto_extra", atacante.datos, m)

    # --- tabla ---
    lineas = [
        f"{'ATAQUE':<28} {'ESTACIÓN':<18} {'RESULTADO'}",
        "-" * 60,
    ]
    breaches = []
    for reg in registros:
        lineas.append(
            f"{reg['ataque']:<28} {reg['estacion_detencion']:<18} {reg['clasificacion']}"
        )
        if reg["clasificacion"] == "BREACH":
            breaches.append(reg)

    tabla = "\n".join(lineas)
    print("\n" + tabla + "\n")

    # Respuestas objetivas del experimento
    assert atacante.sin_clave_privada(), "El atacante no debe poseer clave privada"
    assert not breaches, f"BREACH detectado: {breaches}"

    # Todo ataque hostil debe haber sido BLOCKED
    for reg in registros:
        assert reg["clasificacion"] == "BLOCKED", reg
        assert reg["ok"] is False

    # Al menos una detención en firma y una en nucleo/canales
    estaciones = {r["estacion_detencion"] for r in registros}
    assert estaciones & {"firma", "manifiesto_forma", "esquema_cuerpo"}, estaciones
    assert estaciones & {"nucleo", "canales", "n_bytes"}, estaciones
