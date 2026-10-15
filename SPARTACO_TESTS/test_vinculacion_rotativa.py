# ===========================================================================
# VPSI-TRUTH — tests/test_vinculacion_rotativa.py
# ===========================================================================
#
# ADVERSARIAL AND INTEGRAL SUITE FOR
#     modules.spartaco_seguridad.vinculacion
#
# ARCHITECTURAL PRINCIPLE
# ---------------------------------------------------------------------------
#     GENERATE
#         -> REGISTER
#         -> BUILD
#         -> VERIFY
#         -> ASSERT
#
# The chain imposes an order. Nothing is verified before it is built.
# Nothing is built before it is registered when verification is against
# a store. Nothing is asserted that has not passed through the four
# previous stages. This discipline avoids the classic failure mode of
# security tests: verifying an invented ID against a state that never
# existed.
#
# DOCTRINE (TEN RULES)
# ---------------------------------------------------------------------------
#   1. Legitimate entities are deterministic. No secrets, no uuid, no
#      os.urandom, no random in the generation of identities, devices,
#      credentials, materials or authorities.
#   2. The module under test does not generate entropy. If the auditor
#      sees entropy, it must come from the attack, not the system.
#   3. Attacks may be stochastic. A dedicated RNG with fixed seed
#      produces values that look random but are reproducible byte by
#      byte on every run.
#   4. An attack starts from an existing entity or context. Never
#      invent an ID to verify against a nonexistent state.
#   5. The verificar() helper is passthrough: it consumes exclusively
#      the tuple that exists in the context, generates nothing, and
#      does not mutate the context.
#   6. The base context is never mutated.
#   7. No internal detail of the module is inspected to decide what it
#      should return. The observable contract is verified, not the
#      implementation.
#   8. The suite must detect false positives. A test that passes by
#      accident or by lax checking must be made visible.
#   9. Deterministic time: a fixed epoch constant feeds every test so
#      expiration, future timestamps and clock tolerance are precise
#      and reproducible.
#  10. Separation between deterministic legitimate generation and
#      stochastic adversarial pressure is explicit and preserved.
#
# GENERATION MODEL
# ---------------------------------------------------------------------------
#   _determinista(prefix, index) builds a byte material from
#   f"VPSI-TRUTH:{prefix}:{index}", computes SHA-256, and returns
#   f"{prefix}_{digest}". Every legitimate entity is built by this
#   function. Two calls with the same index produce the same entity.
#   This is what allows the suite to prove that legitimate generation
#   is reproducible.
#
#   AHORA_BASE = 1800000000.0 and timestamp_iso(epoch) produce
#   reproducible ISO timestamps compatible with the module's parser.
#   A test that depended on time.time() would not be reproducible.
#
# ATTACK MODEL
# ---------------------------------------------------------------------------
#   ataque_estocastico(rng, prefix) produces a 256-bit value with
#   rng.getrandbits(256) formatted as f"{prefix}_{value:064x}". It is
#   unpredictable without the seed but reproducible with it. Every
#   attack test uses the same dedicated RNG with seed 0x56505349,
#   fixed at the fixture level. The stochastic character of the attack
#   is explicitly separated from the determinism of the legitimate
#   entity.
#
# FIFTY-FIVE DISTINCT SCENARIOS
# ---------------------------------------------------------------------------
#   LEGITIMATE FLOW AND ITS DERIVATIVES
#       correct credential links; duplicate registration rejects;
#       absent state rejects; missing fields reject; wrong material,
#       device, or credential rejects.
#
#   INPUT VALIDATION
#       false unlock; wrong-typed unlock; invalid timestamp; boolean
#       timestamp; future timestamp; timestamp before issuance;
#       manipulated digest; malformed digest; extra key; missing key;
#       non-dict proof.
#
#   LIFECYCLE
#       rotation increments generation by exactly one; old credential
#       rejected after rotation; new credential links after rotation;
#       revocation rejects subsequent linkage; revocation preserves
#       evidence; rotation preserves authority, device and identity;
#       second rotation increments again; rotation without state
#       rejects; revocation without state rejects; repeated revocation
#       does not create new state; a single linkage is current per
#       identity.
#
#   STATE INTEGRITY AND NON-LEAK
#       estado_de does not expose material; proof does not expose
#       material; attacker material is not persisted; material does
#       not appear in the store; construction does not mutate the
#       context; verification does not mutate the context;
#       construction does not declare linked; linked is not
#       authorized.
#
#   STOCHASTIC ATTACK AND REPRODUCIBILITY
#       sixteen consecutive stochastic attacks link none; legitimate
#       material is reproducible; legitimate identifiers are
#       reproducible; thirty-two attacks leave the state identical;
#       attacker material is not persisted.
#
#   OBSERVABLE CONTRACT (DOCTRINAL)
#       test_053  construction is independent of the state
#       test_054  construction does not declare linkage
#       test_055  LINKED does not mean AUTHORIZED
#
# WHAT THIS SUITE IS NOT
# ---------------------------------------------------------------------------
#   - It is not an audit of credencial.py, proteccion.py, perimeter.py
#     or the launcher.
#   - It does not qualify any instrument.
#   - It does not run a Monte Carlo.
#   - It does not measure coverage or performance.
#   - It does not certify the whole system: it certifies the
#     observable contract of vinculacion's lifecycle under
#     deterministic legitimate flow and stochastic adversarial
#     pressure.
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
# the complete metrological doctrine over the system surface. The
# transition auditor asks what observable state changes between
# transitions. The RAW causal boundary auditor audits the boundary
# between Engine and provider. The UI auditor verifies the USER can
# recover and download the content. This file audits the full
# lifecycle of a rotating link: register, build proof, verify, rotate,
# revoke, under deterministic legitimate flow and stochastic
# adversarial pressure.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# Determinism belongs to the legitimate path. Stochasticity belongs to
# the attacker. The passthrough helper verifies what exists, not what
# the auditor wishes existed. The chain GENERATE, REGISTER, BUILD,
# VERIFY, ASSERT orders the operations and prevents verifying the
# nothing. The material never appears in the state. The link is not
# the authorization. Every property has its own test, and every test
# is reproducible byte by byte.
#
# ===========================================================================

from __future__ import annotations

import copy
import hashlib
import random
from typing import Any, Dict

import pytest

from modules.spartaco_seguridad import vinculacion as V


# ===============================================================
# GENERACIÓN DETERMINISTA DE ENTIDADES LEGÍTIMAS
# ===============================================================

def _determinista(prefijo: str, indice: int) -> str:
    """
    Genera una identidad textual determinista.

    No utiliza random, secrets, uuid ni os.urandom.
    """
    material = f"VPSI-TRUTH:{prefijo}:{indice}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()
    return f"{prefijo}_{digest}"


def crear_identidad(indice: int = 1) -> str:
    return _determinista("identidad", indice)


def crear_dispositivo(indice: int = 1) -> str:
    return _determinista("dispositivo", indice)


def crear_credencial(indice: int = 1) -> str:
    return _determinista("credencial", indice)


def crear_material(indice: int = 1) -> str:
    return _determinista("material", indice)


def crear_autoridad(indice: int = 1) -> str:
    return _determinista("autoridad", indice)


# ===============================================================
# TIEMPO DETERMINISTA
# ===============================================================

AHORA_BASE = 1_800_000_000.0


def timestamp_iso(epoch: float) -> str:
    """
    Conversión determinista compatible con el parser del módulo.
    """
    from datetime import datetime, timezone

    return datetime.fromtimestamp(
        epoch,
        timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


# ===============================================================
# ATAQUE ESTOCÁSTICO
# ===============================================================

def ataque_estocastico(rng: random.Random, prefijo: str) -> str:
    """
    El ataque sí puede ser estocástico.

    Esto no forma parte de la generación legítima del sistema.
    """
    valor = rng.getrandbits(256)
    return f"{prefijo}_{valor:064x}"


# ===============================================================
# CONTEXTO
# ===============================================================

def construir_contexto_valido(
    *,
    indice: int = 1,
    ahora: float = AHORA_BASE,
    ttl_segundos: int = 300,
) -> Dict[str, Any]:
    """
    Construye una tupla legítima completa.

    Todos sus identificadores y material son deterministas.
    """

    identidad = crear_identidad(indice)
    dispositivo_id = crear_dispositivo(indice)
    credencial_id = crear_credencial(indice)
    material = crear_material(indice)
    autoridad_id = crear_autoridad(indice)

    ctx = {
        "identidad": identidad,
        "dispositivo_id": dispositivo_id,
        "credencial_id": credencial_id,
        "material": material,
        "autoridad_id": autoridad_id,
        "ahora": ahora,
        "ttl_segundos": ttl_segundos,
    }

    preparar_prueba(ctx)

    return ctx


def preparar_prueba(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Construye prueba desde el contexto existente.

    No inventa entidades.
    No registra estado.
    No verifica.
    """

    resultado = V.construir_prueba(
        identidad=ctx["identidad"],
        dispositivo_id=ctx["dispositivo_id"],
        credencial_id=ctx["credencial_id"],
        material=ctx["material"],
        desbloqueo_local=ctx.get(
            "desbloqueo_local",
            True,
        ),
        timestamp=ctx.get(
            "timestamp",
            timestamp_iso(ctx["ahora"]),
        ),
    )

    ctx["prueba_input"] = {
        "identidad": ctx["identidad"],
        "dispositivo_id": ctx["dispositivo_id"],
        "credencial_id": ctx["credencial_id"],
        "material": ctx["material"],
        "desbloqueo_local": ctx.get(
            "desbloqueo_local",
            True,
        ),
        "timestamp": ctx.get(
            "timestamp",
            timestamp_iso(ctx["ahora"]),
        ),
    }

    ctx["prueba_construida"] = resultado

    return ctx


# ===============================================================
# REGISTRO
# ===============================================================

def registrar_contexto(
    ctx: Dict[str, Any],
    almacen: Any,
) -> Dict[str, Any]:
    """
    Registra exactamente la entidad existente en el contexto.
    """

    return V.registrar_estado(
        identidad=ctx["identidad"],
        dispositivo_id=ctx["dispositivo_id"],
        credencial_id=ctx["credencial_id"],
        material=ctx["material"],
        autoridad_id=ctx["autoridad_id"],
        ttl_segundos=ctx["ttl_segundos"],
        almacen=almacen,
        ahora=ctx["ahora"],
    )


# ===============================================================
# HELPER DE VERIFICACIÓN
# ===============================================================

def verificar(
    ctx: Dict[str, Any],
    almacen: Any,
) -> Dict[str, Any]:
    """
    Pasante puro.

    Consume exclusivamente la tupla existente en ctx.

    No genera:
        identidad
        dispositivo
        credencial
        material

    No muta ctx.
    """

    datos = copy.deepcopy(
        ctx["prueba_input"]
    )

    built = V.construir_prueba(
        **datos
    )

    if (
        isinstance(built, dict)
        and built.get("ok") is False
    ):
        return built

    if isinstance(built, dict):
        prueba_obj = built.get(
            "prueba",
            built,
        )
    else:
        prueba_obj = built

    return V.verificar_vinculacion(
        prueba_obj,
        material=datos["material"],
        almacen=almacen,
        ahora=ctx["ahora"],
    )


# ===============================================================
# FIXTURES
# ===============================================================

@pytest.fixture
def almacen():
    return V._AlmacenVinculacionMemoria()


@pytest.fixture
def contexto():
    return construir_contexto_valido()


@pytest.fixture
def ataque_rng():
    """
    RNG dedicado exclusivamente a generar ataques.

    La arquitectura legítima permanece determinista.
    """
    return random.Random(
        0x56505349
    )


# ===============================================================
# 001 — FLUJO LEGÍTIMO
# ===============================================================

def test_001_credencial_correcta_vincula(
    almacen,
    contexto,
):
    registro = registrar_contexto(
        contexto,
        almacen,
    )

    assert registro["ok"] is True
    assert registro["estado"] == V.VINCULADO

    resultado = verificar(
        contexto,
        almacen,
    )

    assert resultado["ok"] is True
    assert resultado["estado"] == V.VINCULADO


# ===============================================================
# 002 — REGISTRO DUPLICADO
# ===============================================================

def test_002_registro_duplicado_rechazado(
    almacen,
    contexto,
):
    primero = registrar_contexto(
        contexto,
        almacen,
    )

    assert primero["ok"] is True

    segundo = registrar_contexto(
        contexto,
        almacen,
    )

    assert segundo["ok"] is False
    assert segundo["estado"] == V.RECHAZADO
    assert "ESTADO_YA_EXISTENTE" in segundo["conceptos"]


# ===============================================================
# 003 — ESTADO AUSENTE
# ===============================================================

def test_003_estado_ausente(
    almacen,
):
    ctx = construir_contexto_valido(
        indice=3
    )

    resultado = verificar(
        ctx,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO
    assert "ESTADO_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 004 — IDENTIDAD AUSENTE EN REGISTRO
# ===============================================================

def test_004_identidad_ausente(
    almacen,
):
    resultado = V.registrar_estado(
        identidad="",
        dispositivo_id=crear_dispositivo(4),
        credencial_id=crear_credencial(4),
        material=crear_material(4),
        autoridad_id=crear_autoridad(4),
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False
    assert "IDENTIDAD_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 005 — DISPOSITIVO AUSENTE
# ===============================================================

def test_005_dispositivo_ausente(
    almacen,
):
    resultado = V.registrar_estado(
        identidad=crear_identidad(5),
        dispositivo_id="",
        credencial_id=crear_credencial(5),
        material=crear_material(5),
        autoridad_id=crear_autoridad(5),
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False
    assert "DISPOSITIVO_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 006 — CREDENCIAL AUSENTE
# ===============================================================

def test_006_credencial_ausente(
    almacen,
):
    resultado = V.registrar_estado(
        identidad=crear_identidad(6),
        dispositivo_id=crear_dispositivo(6),
        credencial_id="",
        material=crear_material(6),
        autoridad_id=crear_autoridad(6),
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False
    assert "CREDENCIAL_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 007 — MATERIAL AUSENTE
# ===============================================================

def test_007_material_ausente(
    almacen,
):
    resultado = V.registrar_estado(
        identidad=crear_identidad(7),
        dispositivo_id=crear_dispositivo(7),
        credencial_id=crear_credencial(7),
        material="",
        autoridad_id=crear_autoridad(7),
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False
    assert "CREDENCIAL_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 008 — MATERIAL INCORRECTO
# ===============================================================

def test_008_material_incorrecto_rechaza(
    almacen,
    contexto,
    ataque_rng,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "material"
    ] = ataque_estocastico(
        ataque_rng,
        "material_atacante",
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 009 — DISPOSITIVO INCORRECTO
# ===============================================================

def test_009_dispositivo_no_vinculado(
    almacen,
    contexto,
    ataque_rng,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "dispositivo_id"
    ] = ataque_estocastico(
        ataque_rng,
        "dispositivo_atacante",
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert "DISPOSITIVO_NO_VINCULADO" in resultado["conceptos"]


# ===============================================================
# 010 — CREDENCIAL INCORRECTA
# ===============================================================

def test_010_credencial_no_vigente(
    almacen,
    contexto,
    ataque_rng,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "credencial_id"
    ] = ataque_estocastico(
        ataque_rng,
        "credencial_atacante",
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert "CREDENCIAL_NO_VIGENTE" in resultado["conceptos"]


# ===============================================================
# 011 — DESBLOQUEO FALSO
# ===============================================================

def test_011_desbloqueo_local_false_rechaza(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "desbloqueo_local"
    ] = False

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert "DESBLOQUEO_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 012 — DESBLOQUEO NO BOOL
# ===============================================================

@pytest.mark.parametrize(
    "valor",
    [0, 1, None, "", "true", []],
)
def test_012_desbloqueo_tipo_invalido(
    almacen,
    contexto,
    valor,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "desbloqueo_local"
    ] = valor

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False


# ===============================================================
# 013 — TIMESTAMP INVÁLIDO
# ===============================================================

@pytest.mark.parametrize(
    "timestamp",
    [
        "",
        "invalid",
        "2026",
        "2026-01-01",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00+00:00",
    ],
)
def test_013_timestamp_invalido(
    almacen,
    contexto,
    timestamp,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "timestamp"
    ] = timestamp

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False


# ===============================================================
# 014 — TIMESTAMP BOOL
# ===============================================================

@pytest.mark.parametrize(
    "valor",
    [True, False],
)
def test_014_bool_no_es_timestamp(
    almacen,
    contexto,
    valor,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["ahora"] = valor

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 015 — TIMESTAMP FUTURO
# ===============================================================

def test_015_timestamp_futuro_rechazado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "timestamp"
    ] = timestamp_iso(
        contexto["ahora"] + 1000
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 016 — TIMESTAMP ANTERIOR A EMISIÓN
# ===============================================================

def test_016_timestamp_anterior_rechazado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "timestamp"
    ] = timestamp_iso(
        contexto["ahora"] - 1000
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 017 — DIGEST MANIPULADO
# ===============================================================

def test_017_digest_manipulado_rechazado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    assert built["ok"] is True

    ataque = copy.deepcopy(
        built["prueba"]
    )

    ataque["prueba_digest"] = (
        "0" * 64
    )

    resultado = V.verificar_vinculacion(
        ataque,
        material=contexto["material"],
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 018 — DIGEST MAL FORMADO
# ===============================================================

@pytest.mark.parametrize(
    "digest",
    [
        "",
        "0",
        "f" * 63,
        "f" * 65,
        "g" * 64,
        None,
        123,
    ],
)
def test_018_digest_malformado(
    almacen,
    contexto,
    digest,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    prueba = copy.deepcopy(
        built["prueba"]
    )

    prueba["prueba_digest"] = digest

    resultado = V.verificar_vinculacion(
        prueba,
        material=contexto["material"],
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False


# ===============================================================
# 019 — CLAVES EXTRA
# ===============================================================

def test_019_clave_extra_rechazada(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    prueba = copy.deepcopy(
        built["prueba"]
    )

    prueba["extra"] = "ataque"

    resultado = V.verificar_vinculacion(
        prueba,
        material=contexto["material"],
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False
    assert "PRUEBA_INVALIDA" in resultado["conceptos"]


# ===============================================================
# 020 — CLAVE FALTANTE
# ===============================================================

def test_020_clave_faltante_rechazada(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    prueba = copy.deepcopy(
        built["prueba"]
    )

    del prueba["prueba_digest"]

    resultado = V.verificar_vinculacion(
        prueba,
        material=contexto["material"],
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False
    assert "PRUEBA_INVALIDA" in resultado["conceptos"]


# ===============================================================
# 021 — PRUEBA NO DICT
# ===============================================================

@pytest.mark.parametrize(
    "prueba",
    [
        None,
        "",
        [],
        (),
        0,
        False,
    ],
)
def test_021_prueba_no_dict(
    almacen,
    contexto,
    prueba,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    resultado = V.verificar_vinculacion(
        prueba,
        material=contexto["material"],
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False
    assert "PRUEBA_INVALIDA" in resultado["conceptos"]


# ===============================================================
# 022 — ROTACIÓN
# ===============================================================

def test_022_rotacion_incrementa_generacion(
    almacen,
    contexto,
):
    registro = registrar_contexto(
        contexto,
        almacen,
    )

    assert registro["generacion"] == 1

    nuevo_material = crear_material(
        22_2
    )

    nueva_credencial = crear_credencial(
        22_2
    )

    rotacion = V.rotar(
        identidad=contexto["identidad"],
        credencial_id=nueva_credencial,
        material=nuevo_material,
        almacen=almacen,
        ahora=contexto["ahora"] + 10,
    )

    assert rotacion["ok"] is True
    assert rotacion["generacion"] == 2


# ===============================================================
# 023 — CREDENCIAL ANTIGUA DESPUÉS DE ROTACIÓN
# ===============================================================

def test_023_credencial_antigua_rechazada_despues_de_rotacion(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    antigua = copy.deepcopy(
        contexto
    )

    nueva_credencial = crear_credencial(
        23_2
    )

    nuevo_material = crear_material(
        23_2
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=nueva_credencial,
        material=nuevo_material,
        almacen=almacen,
        ahora=contexto["ahora"] + 10,
    )

    resultado = verificar(
        antigua,
        almacen,
    )

    assert resultado["ok"] is False
    assert "CREDENCIAL_NO_VIGENTE" in resultado["conceptos"]


# ===============================================================
# 024 — NUEVA CREDENCIAL DESPUÉS DE ROTACIÓN
# ===============================================================

def test_024_nueva_credencial_vincula_despues_de_rotar(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    nueva = copy.deepcopy(
        contexto
    )

    nueva["credencial_id"] = crear_credencial(
        24_2
    )

    nueva["material"] = crear_material(
        24_2
    )

    ahora_nuevo = (
        contexto["ahora"] + 10
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=nueva["credencial_id"],
        material=nueva["material"],
        almacen=almacen,
        ahora=ahora_nuevo,
    )

    nueva["ahora"] = ahora_nuevo

    nueva["timestamp"] = timestamp_iso(
        ahora_nuevo
    )

    preparar_prueba(nueva)

    resultado = verificar(
        nueva,
        almacen,
    )

    assert resultado["ok"] is True
    assert resultado["estado"] == V.VINCULADO


# ===============================================================
# 025 — REVOCACIÓN
# ===============================================================

def test_025_revocacion_rechaza_vinculacion(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    revocacion = V.revocar(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert revocacion["ok"] is True
    assert revocacion["estado"] == V.RECHAZADO

    resultado = verificar(
        contexto,
        almacen,
    )

    assert resultado["ok"] is False
    assert "CREDENCIAL_REVOCADA" in resultado["conceptos"]


# ===============================================================
# 026 — REVOCACIÓN CONSERVA EVIDENCIA
# ===============================================================

def test_026_revocacion_no_elimina_estado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    antes = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    V.revocar(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    despues = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert antes["ok"] is True
    assert despues["ok"] is True

    assert (
        despues["generacion"]
        == antes["generacion"]
    )

    assert despues["revocado"] is True


# ===============================================================
# 027 — ESTADO_DE NO EXPONE MATERIAL
# ===============================================================

def test_027_estado_no_expone_material(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["ok"] is True

    assert contexto["material"] not in (
        repr(estado)
    )


# ===============================================================
# 028 — PRUEBA NO EXPONE MATERIAL
# ===============================================================

def test_028_prueba_no_expone_material(
    contexto,
):
    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    assert built["ok"] is True

    assert contexto["material"] not in (
        repr(built["prueba"])
    )


# ===============================================================
# 029 — CONSTRUCCIÓN NO MUTÓ CONTEXTO
# ===============================================================

def test_029_construccion_no_muta_contexto():
    contexto = construir_contexto_valido(
        indice=29
    )

    original = copy.deepcopy(
        contexto
    )

    V.construir_prueba(
        **contexto["prueba_input"]
    )

    assert contexto == original


# ===============================================================
# 030 — VERIFICACIÓN NO MUTÓ CONTEXTO
# ===============================================================

def test_030_verificacion_no_muta_contexto(
    almacen,
):
    contexto = construir_contexto_valido(
        indice=30
    )

    registrar_contexto(
        contexto,
        almacen,
    )

    original = copy.deepcopy(
        contexto
    )

    verificar(
        contexto,
        almacen,
    )

    assert contexto == original


# ===============================================================
# 031 — MATERIAL ANTIGUO DESPUÉS DE ROTACIÓN
# ===============================================================

def test_031_material_antiguo_rechazado_despues_de_rotacion(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    antigua = copy.deepcopy(
        contexto
    )

    nueva_credencial = crear_credencial(
        31_2
    )

    nuevo_material = crear_material(
        31_2
    )

    nuevo_ahora = (
        contexto["ahora"] + 10
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=nueva_credencial,
        material=nuevo_material,
        almacen=almacen,
        ahora=nuevo_ahora,
    )

    resultado = verificar(
        antigua,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 032 — MATERIAL NUEVO CON CREDENCIAL ANTIGUA
# ===============================================================

def test_032_material_nuevo_con_credencial_antigua_rechaza(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    nueva_credencial = crear_credencial(
        32_2
    )

    nuevo_material = crear_material(
        32_2
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=nueva_credencial,
        material=nuevo_material,
        almacen=almacen,
        ahora=contexto["ahora"] + 10,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "material"
    ] = nuevo_material

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 033 — CREDENCIAL NUEVA CON MATERIAL ANTIGUO
# ===============================================================

def test_033_credencial_nueva_con_material_antiguo_rechaza(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    nueva_credencial = crear_credencial(
        33_2
    )

    nuevo_material = crear_material(
        33_2
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=nueva_credencial,
        material=nuevo_material,
        almacen=almacen,
        ahora=contexto["ahora"] + 10,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "credencial_id"
    ] = nueva_credencial

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 034 — IDENTIDAD DE OTRO CONTEXTO
# ===============================================================

def test_034_identidad_cruzada_rechazada(
    almacen,
):
    contexto_a = construir_contexto_valido(
        indice=34_1
    )

    contexto_b = construir_contexto_valido(
        indice=34_2
    )

    registrar_contexto(
        contexto_a,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto_b
    )

    ataque["identidad"] = contexto_a[
        "identidad"
    ]

    preparar_prueba(ataque)

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False


# ===============================================================
# 035 — DISPOSITIVOS CRUZADOS
# ===============================================================

def test_035_dispositivo_cruzado_rechazado(
    almacen,
):
    contexto_a = construir_contexto_valido(
        indice=35_1
    )

    contexto_b = construir_contexto_valido(
        indice=35_2
    )

    registrar_contexto(
        contexto_a,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto_a
    )

    ataque["prueba_input"][
        "dispositivo_id"
    ] = contexto_b[
        "dispositivo_id"
    ]

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert "DISPOSITIVO_NO_VINCULADO" in resultado["conceptos"]


# ===============================================================
# 036 — MATERIAL ESTOCÁSTICO DE ATAQUE
# ===============================================================

def test_036_material_estocastico_no_vincula(
    almacen,
    contexto,
    ataque_rng,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    for _ in range(16):
        ataque = copy.deepcopy(
            contexto
        )

        ataque["prueba_input"][
            "material"
        ] = ataque_estocastico(
            ataque_rng,
            "ataque",
        )

        resultado = verificar(
            ataque,
            almacen,
        )

        assert resultado["ok"] is False
        assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 037 — MATERIAL LEGÍTIMO DETERMINISTA
# ===============================================================

def test_037_material_legitimo_reproducible():
    primero = crear_material(
        37
    )

    segundo = crear_material(
        37
    )

    assert primero == segundo


# ===============================================================
# 038 — IDS LEGÍTIMOS REPRODUCIBLES
# ===============================================================

def test_038_ids_legitimos_reproducibles():
    assert crear_identidad(38) == crear_identidad(38)
    assert crear_dispositivo(38) == crear_dispositivo(38)
    assert crear_credencial(38) == crear_credencial(38)
    assert crear_autoridad(38) == crear_autoridad(38)


# ===============================================================
# 039 — MATERIAL DE ATAQUE NO SE PERSISTE
# ===============================================================

def test_039_material_atacante_no_persistido(
    almacen,
    contexto,
    ataque_rng,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    atacante = ataque_estocastico(
        ataque_rng,
        "material",
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "material"
    ] = atacante

    verificar(
        ataque,
        almacen,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert atacante not in repr(
        estado
    )


# ===============================================================
# 040 — TTL INVÁLIDO
# ===============================================================

@pytest.mark.parametrize(
    "ttl",
    [
        0,
        -1,
        True,
        False,
        1.5,
        "300",
        None,
    ],
)
def test_040_ttl_invalido(
    almacen,
    ttl,
):
    resultado = V.registrar_estado(
        identidad=crear_identidad(
            40
        ),
        dispositivo_id=crear_dispositivo(
            40
        ),
        credencial_id=crear_credencial(
            40
        ),
        material=crear_material(
            40
        ),
        autoridad_id=crear_autoridad(
            40
        ),
        ttl_segundos=ttl,
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False


# ===============================================================
# 041 — AHORA BOOL EN REGISTRO
# ===============================================================

@pytest.mark.parametrize(
    "valor",
    [True, False],
)
def test_041_ahora_bool_rechazado_en_registro(
    almacen,
    valor,
):
    resultado = V.registrar_estado(
        identidad=crear_identidad(
            41
        ),
        dispositivo_id=crear_dispositivo(
            41
        ),
        credencial_id=crear_credencial(
            41
        ),
        material=crear_material(
            41
        ),
        autoridad_id=crear_autoridad(
            41
        ),
        almacen=almacen,
        ahora=valor,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 042 — AHORA BOOL EN ROTACIÓN
# ===============================================================

@pytest.mark.parametrize(
    "valor",
    [True, False],
)
def test_042_ahora_bool_rechazado_en_rotacion(
    almacen,
    contexto,
    valor,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    resultado = V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            42
        ),
        material=crear_material(
            42
        ),
        almacen=almacen,
        ahora=valor,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO


# ===============================================================
# 043 — EXPIRACIÓN
# ===============================================================

def test_043_credencial_expirada_rechazada(
    almacen,
):
    contexto = construir_contexto_valido(
        indice=43,
        ahora=AHORA_BASE,
        ttl_segundos=10,
    )

    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["ahora"] = (
        AHORA_BASE + 100
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert (
        "CREDENCIAL_EXPIRADA"
        in resultado["conceptos"]
    )


# ===============================================================
# 044 — LÍMITE TEMPORAL
# ===============================================================

def test_044_timestamp_dentro_de_tolerancia(
    almacen,
):
    contexto = construir_contexto_valido(
        indice=44,
        ahora=AHORA_BASE,
        ttl_segundos=300,
    )

    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "timestamp"
    ] = timestamp_iso(
        AHORA_BASE
        + V.TOLERANCIA_RELOJ_SEGUNDOS
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is True
    assert resultado["estado"] == V.VINCULADO


# ===============================================================
# 045 — MATERIAL NO APARECE EN ALMACÉN
# ===============================================================

def test_045_material_no_aparece_en_almacen(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    estado = almacen.obtener(
        contexto["identidad"]
    )

    assert estado is not None
    assert contexto["material"] not in repr(
        estado
    )


# ===============================================================
# 046 — AUTORIDAD SE CONSERVA EN ROTACIÓN
# ===============================================================

def test_046_autoridad_se_conserva_en_rotacion(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            46_2
        ),
        material=crear_material(
            46_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["ok"] is True
    assert (
        estado["autoridad_id"]
        == contexto["autoridad_id"]
    )


# ===============================================================
# 047 — DISPOSITIVO SE CONSERVA EN ROTACIÓN
# ===============================================================

def test_047_dispositivo_se_conserva_en_rotacion(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            47_2
        ),
        material=crear_material(
            47_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["ok"] is True
    assert (
        estado["dispositivo_id"]
        == contexto["dispositivo_id"]
    )


# ===============================================================
# 048 — GENERACIÓN EXACTAMENTE +1
# ===============================================================

def test_048_generacion_incrementa_exactamente_uno(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    primera = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            48_2
        ),
        material=crear_material(
            48_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    segunda = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert (
        segunda["generacion"]
        == primera["generacion"] + 1
    )


# ===============================================================
# 049 — SEGUNDA ROTACIÓN +1
# ===============================================================

def test_049_segunda_rotacion_incrementa_uno(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            49_2
        ),
        material=crear_material(
            49_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    estado_1 = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            49_3
        ),
        material=crear_material(
            49_3
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 2,
    )

    estado_2 = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert (
        estado_2["generacion"]
        == estado_1["generacion"] + 1
    )


# ===============================================================
# 050 — ROTACIÓN SIN ESTADO
# ===============================================================

def test_050_rotacion_sin_estado_rechazada(
    almacen,
):
    resultado = V.rotar(
        identidad=crear_identidad(
            50
        ),
        credencial_id=crear_credencial(
            50
        ),
        material=crear_material(
            50
        ),
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False
    assert "ESTADO_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 051 — REVOCACIÓN SIN ESTADO
# ===============================================================

def test_051_revocacion_sin_estado_rechazada(
    almacen,
):
    resultado = V.revocar(
        identidad=crear_identidad(
            51
        ),
        almacen=almacen,
    )

    assert resultado["ok"] is False
    assert "ESTADO_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 052 — ESTADO_DE NO MUTACIÓN
# ===============================================================

def test_052_estado_de_no_muta(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    antes = almacen.obtener(
        contexto["identidad"]
    )

    V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    despues = almacen.obtener(
        contexto["identidad"]
    )

    assert antes == despues


# ===============================================================
# 053 — CONSTRUCCIÓN NO CONSULTA ALMACÉN
# ===============================================================

def test_053_construccion_independiente_del_estado():
    contexto = construir_contexto_valido(
        indice=53
    )

    construido = V.construir_prueba(
        **contexto["prueba_input"]
    )

    assert construido["ok"] is True


# ===============================================================
# 054 — CONSTRUIR PRUEBA NO DECIDE VINCULACIÓN
# ===============================================================

def test_054_construccion_no_declara_vinculado():
    contexto = construir_contexto_valido(
        indice=54
    )

    construido = V.construir_prueba(
        **contexto["prueba_input"]
    )

    assert construido["ok"] is True
    assert "estado" not in construido


# ===============================================================
# 055 — VINCULADO NO SIGNIFICA AUTORIZADO
# ===============================================================

def test_055_vinculado_no_es_autorizado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    resultado = verificar(
        contexto,
        almacen,
    )

    assert resultado["estado"] == V.VINCULADO
    assert resultado["estado"] != "AUTORIZADO"


# ===============================================================
# 056 — MATERIAL ATACANTE ESTOCÁSTICO REPETIDO
# ===============================================================

def test_056_ataques_estocasticos_no_afectan_estado(
    almacen,
    contexto,
    ataque_rng,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    estado_inicial = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    for _ in range(32):
        ataque = copy.deepcopy(
            contexto
        )

        ataque["prueba_input"][
            "material"
        ] = ataque_estocastico(
            ataque_rng,
            "ataque",
        )

        verificar(
            ataque,
            almacen,
        )

    estado_final = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado_final == estado_inicial


# ===============================================================
# 057 — ROTACIÓN NO REINICIA GENERACIÓN
# ===============================================================

def test_057_rotacion_no_reinicia_generacion(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            57_2
        ),
        material=crear_material(
            57_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["generacion"] == 2


# ===============================================================
# 058 — REVOCAR NO BORRA IDENTIDAD
# ===============================================================

def test_058_revocar_conserva_identidad(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    V.revocar(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["ok"] is True
    assert (
        estado["identidad"]
        == contexto["identidad"]
    )


# ===============================================================
# 059 — REVOCACIÓN REPETIDA NO CREA ESTADO NUEVO
# ===============================================================

def test_059_revocacion_repetida_no_crea_estado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    primera = V.revocar(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    segunda = V.revocar(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert primera["ok"] is True
    assert segunda["ok"] is True

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["revocado"] is True


# ===============================================================
# 060 — MATERIAL VACÍO EN VERIFICACIÓN
# ===============================================================

def test_060_material_vacio_rechazado(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    resultado = V.verificar_vinculacion(
        built["prueba"],
        material="",
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False
    assert "CREDENCIAL_AUSENTE" in resultado["conceptos"]


# ===============================================================
# 061 — TIPO MATERIAL INVALIDO
# ===============================================================

@pytest.mark.parametrize(
    "material",
    [
        None,
        0,
        False,
        [],
        {},
    ],
)
def test_061_material_tipo_invalido(
    almacen,
    contexto,
    material,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    built = V.construir_prueba(
        **contexto["prueba_input"]
    )

    resultado = V.verificar_vinculacion(
        built["prueba"],
        material=material,
        almacen=almacen,
        ahora=contexto["ahora"],
    )

    assert resultado["ok"] is False


# ===============================================================
# 062 — TIPO AHORA INVALIDO
# ===============================================================

@pytest.mark.parametrize(
    "ahora",
    [
        None,
        "",
        "123",
        [],
        {},
        object(),
    ],
)
def test_062_ahora_tipo_invalido(
    almacen,
    contexto,
    ahora,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    resultado = verificar(
        {
            **contexto,
            "ahora": ahora,
        },
        almacen,
    )

    assert resultado["ok"] is False


# ===============================================================
# 063 — CONSTRUCCIÓN RECHAZA TIMESTAMP MALFORMADO
# ===============================================================

def test_063_construccion_timestamp_malformado():
    contexto = construir_contexto_valido(
        indice=63
    )

    resultado = V.construir_prueba(
        identidad=contexto["identidad"],
        dispositivo_id=contexto["dispositivo_id"],
        credencial_id=contexto["credencial_id"],
        material=contexto["material"],
        desbloqueo_local=True,
        timestamp="timestamp_invalido",
    )

    assert resultado["ok"] is False
    assert "VENTANA_INVALIDA" in resultado["conceptos"]


# ===============================================================
# 064 — DESBLOQUEO ESTRICTAMENTE TRUE
# ===============================================================

def test_064_desbloqueo_1_no_equivale_true(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "desbloqueo_local"
    ] = 1

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False


# ===============================================================
# 065 — IDENTIDAD NO PUEDE SER BOOL
# ===============================================================

def test_065_identidad_bool_rechazada(
    almacen,
):
    resultado = V.registrar_estado(
        identidad=True,
        dispositivo_id=crear_dispositivo(
            65
        ),
        credencial_id=crear_credencial(
            65
        ),
        material=crear_material(
            65
        ),
        autoridad_id=crear_autoridad(
            65
        ),
        almacen=almacen,
        ahora=AHORA_BASE,
    )

    assert resultado["ok"] is False


# ===============================================================
# 066 — ROTACIÓN CONSERVA IDENTIDAD
# ===============================================================

def test_066_rotacion_conserva_identidad(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            66_2
        ),
        material=crear_material(
            66_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    estado = V.estado_de(
        identidad=contexto["identidad"],
        almacen=almacen,
    )

    assert estado["identidad"] == contexto["identidad"]


# ===============================================================
# 067 — SOLO UNA VINCULACIÓN VIGENTE
# ===============================================================

def test_067_una_sola_vinculacion_vigente(
    almacen,
):
    contexto = construir_contexto_valido(
        indice=67
    )

    registrar_contexto(
        contexto,
        almacen,
    )

    V.rotar(
        identidad=contexto["identidad"],
        credencial_id=crear_credencial(
            67_2
        ),
        material=crear_material(
            67_2
        ),
        almacen=almacen,
        ahora=contexto["ahora"] + 1,
    )

    estado = almacen.obtener(
        contexto["identidad"]
    )

    assert estado is not None
    assert estado["generacion"] == 2


# ===============================================================
# 068 — CAMBIO DE CREDENCIAL SIN MATERIAL CORRESPONDIENTE
# ===============================================================

def test_068_cambio_credencial_sin_material_vigente_rechaza(
    almacen,
    contexto,
):
    registrar_contexto(
        contexto,
        almacen,
    )

    ataque = copy.deepcopy(
        contexto
    )

    ataque["prueba_input"][
        "credencial_id"
    ] = crear_credencial(
        68_2
    )

    resultado = verificar(
        ataque,
        almacen,
    )

    assert resultado["ok"] is False
    assert resultado["estado"] == V.RECHAZADO
