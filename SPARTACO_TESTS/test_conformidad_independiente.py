# tests/test_conformidad_independiente.py
"""
EXPERIMENTO DE ATACANTE VIRTUAL — conformidad independiente

Principio:
  El atacante no tiene la clave privada.
  Parte solo de superficies observables.
  Cada ataque avanza hasta la primera barrera real de proteccion.py.
  Se registra la estación de detención.
  Solo BREACH (aceptación de modificación no autorizada) es fallo de seguridad.

Estaciones reales extraídas de proteccion.verificar() / verificar_manifiesto():
  1. entrada_datos      — datos deben ser bytes
  2. manifiesto_forma   — exactamente {cuerpo, firma}; tipos
  3. firma              — Ed25519 sobre canónico del cuerpo
  4. esquema_cuerpo     — CLAVES_CUERPO exactas + tipos/rangos
  5. nucleo             — SHA-256(datos) vs cuerpo["nucleo"]
  6. canales            — S/Q vs cuerpo["S"], cuerpo["Q"]
  7. n_bytes            — len(datos) vs cuerpo["n_bytes"]

z e identidad_neutra son evidencia (pasos), no barreras de rechazo en fallos.
"""

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
