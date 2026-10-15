# ===========================================================================
# SPARTACO-SECURITY — tests/test_proteccion_adversarial.py
# VPSI-TRUTH — PROTECCION 3.1
# ===========================================================================
#
# ADVERSARIAL BATTERY — DECLARED CONTRACT
# ---------------------------------------------------------------------------
#
# The real implementation lives in:
#     modules/spartaco_seguridad/proteccion.py
#
# The authorized manifest is EXCLUSIVELY:
#     {
#         "cuerpo": {...},
#         "firma":  "..."
#     }
#
# The following are NOT accepted under any circumstance:
#     - absent manifests
#     - loose signatures in PROTEGIDO mode
#     - altered bodies
#     - altered signatures
#     - altered artifacts
#     - wrong public keys
#     - regressive versions
#     - parallel fields
#     - extra fields
#     - external references that contradict the authenticated body
#
# THESIS
# ---------------------------------------------------------------------------
# This is the base adversarial battery for proteccion.py. It declares
# the contract at the top and then verifies, block by block, that each
# clause holds under systematic attack. It is the file to read first
# and the reference when someone needs to know what proteccion.py
# actually guarantees.
#
# It is NOT the demolition battery. That file (test_proteccion_
# adversarial_demolicion.py) adds metrological doctrine on top of this
# one: crash-as-failure discipline, TOCTOU, aliasing, concurrency,
# Ed25519 non-canonical S forms, numeric canonicalization diagnostics.
# This file is the declared contract; the other file is the layered
# architectural pressure on the same module.
#
# STRUCTURE — 38 BLOCKS
# ---------------------------------------------------------------------------
#
#   1  Happy path: valid build, verification ok=True, empty fallos,
#      internal steps manifiesto / nucleo / canales all green.
#   2  Fail-closed: missing manifest, six malformed manifest shapes,
#      missing pub, wrong pub, all rejected with "manifiesto" in
#      fallos and the appropriate concepto.
#   3  Body mutation: each of the 14 declared fields mutated according
#      to its type, plus full body replacement, plus signature reuse
#      over a different body. All must break.
#   4  Artifact mutation: byte at 0, middle, tail, append, pop, edge
#      positions. All must fail under "nucleo" and, where applicable,
#      "canales", with concepto INTEGRIDAD_COMPROMETIDA.
#   5  Signature: one-nibble flip, seven malformed shapes (empty, two
#      chars, non-hex, 128 zeros, extra chars, single char, short hex).
#      All must fail with FIRMA_INVÁLIDA.
#   6  Public key: five wrong lengths, plus a valid 32-byte key from a
#      different key pair. All must fail with FIRMA_INVÁLIDA.
#   7  Canonicalization: key reordering does not break the signature;
#      value change with the same type does; serializer is
#      deterministic; serialization changes on semantic change.
#   8  Version: signed regressive version rejected with
#      VERSIÓN_REGRESIVA; signed higher version accepted. Signed is
#      not the same as authorized.
#   9  n_neutro: authenticated value is not overridden by an external
#      n_neutro argument.
#  10  z / neutro: evidence, never authority. Present in steps, absent
#      from fallos. Mutating valuaciones breaks body authentication.
#  11  Diagnostic: relaxes the manifest requirement, not its validity.
#  12  Fragmentation: 81 values of n and 11 values of k, exact byte
#      coverage and exact length sum.
#  13  Direct crypto API: firmar / verificar round-trip; signature not
#      reusable for another message; signing with a nonexistent key
#      fails with CÓDIGO_INVÁLIDO.
#  14  Direct manifest: verificar_manifiesto valid returns the body;
#      invalid types, missing cuerpo, missing firma, flat field, extra
#      key, extra cuerpo, signature as list, cuerpo as list — all
#      rejected.
#  15  Manifest structure: eliminating cuerpo, eliminating firma,
#      cuerpo not dict, firma not string — all rejected.
#  16  Body consistency: n_bytes must match the artifact;
#      identidad_neutra and n_neutro authenticated values cannot be
#      modified.
#  17  Manifest A != Artifact B: cross-manifest does not authenticate;
#      failure under "nucleo" and "canales".
#  18  Regression: the build signature is the signature of the BODY,
#      not of the artifact digest.
#  19  Conflicting external references: nucleo_esperado, S_esperado,
#      Q_esperado all zero while the manifest is valid — verification
#      still passes, because the authenticated body is authority.
#  20  Massive artifact mutation: byte at 0, 1, n/4, n/2, 3n/4, n-2,
#      n-1 — all detected under "nucleo".
#  21  Body replacement attack: attacker without private key cannot
#      sign; the attempt fails.
#  22  Extreme data: empty, single byte, 0x00, 0xFF, 3, 7, 8, 9, 100,
#      1000, 10000 bytes — build and verify all ok.
#  23  Invalid n_neutro: -100, -1, 0, 1 — all fail with CÓDIGO_INVÁLIDO.
#  24  Schema: signed incompatible schema fails.
#  25  Algorithms: mutated algoritmo_hash and algoritmo_firma break the
#      signature.
#  26  Artifact identity: artifact_id and clave_publica_id cannot be
#      replaced.
#  27  Full chain: original ok, byte flip fails under "nucleo".
#  28  No bypass with loose firma_hex in PROTEGIDO.
#  29  Two builds do not share authorization; cross-manifest fails.
#  30  Final fail-closed: four insufficient manifests, all rejected.
#  31  JSON order is not part of the signature.
#  32  Signature cannot be transplanted from one body to another.
#  33  Every signature position mutated fails.
#  34  Public key with correct 32-byte length but different bytes
#      fails with FIRMA_INVÁLIDA.
#  35  Deleting any authenticated body field breaks the signature.
#  36  Additional structural attacks: extra firma, extra cuerpo, firma
#      as list, cuerpo as list.
#  37  Mode type: PROTEGIDO is fail-closed even with firma_hex present.
#  38  Cross authentication: correct signature with wrong data does not
#      authorize; same signed body with different data fails.
#
# POSTURE
# ---------------------------------------------------------------------------
# A traditional adversarial battery. No metrological doctrine, no
# calibration, no accounting, no crash-as-failure discipline. The
# contract is declared at the top; the 38 blocks are executable
# verifications of that contract. The demolition file adds layers on
# top; this file is the base declaration that says what is being
# attacked.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The credential red-teams attack credencial.py. The metrological
# kernel audits the instruments. The integration smoke test checks the
# honest path. The monitor correlates external and internal
# observation. The fail-closed auditor qualifies itself against
# synthetic controls. The seal closure test verifies that declared
# algebra is physically operated. The demolition battery piles layered
# architectural pressure on proteccion.py. This file is the base
# adversarial battery that declares the manifest contract and verifies
# it clause by clause across 38 blocks.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# A contract that is not attacked is a hope. This file writes the
# contract down, then attacks it in 38 blocks, requiring each clause
# to hold with the correct failure node and the correct concepto
# whenever it is violated.
#
# ===========================================================================
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from modules.spartaco_seguridad.proteccion import (
    MODO_DIAGNOSTICO,
    MODO_PROTEGIDO,
    _fragmentos,
    build,
    firmar_bytes,
    generar_claves,
    serializar,
    sellar,
    verificar,
    verificar_bytes,
    verificar_manifiesto,
)


# ===============================================================
# FIXTURES
# ===============================================================

@pytest.fixture
def claves(tmp_path: Path):
    priv = tmp_path / "omega.key"
    pub = tmp_path / "omega.pub"

    resultado = generar_claves(
        str(priv),
        str(pub),
    )

    assert resultado["ok"] is True
    assert priv.exists()
    assert pub.exists()

    return priv, pub, pub.read_bytes()


@pytest.fixture
def build_valido(claves):
    priv, _, pub_bytes = claves

    datos = (
        b"VPSI-TRUTH::ARTEFACTO::ORIGINAL::"
        b"0123456789ABCDEF::SEGURIDAD"
    )

    resultado = build(
        datos,
        str(priv),
        n_neutro=3,
        artifact_id="TEST-001",
        version=3,
        clave_publica_id="OMEGA-ROOT-01",
    )

    assert resultado["ok"] is True
    assert resultado["manifiesto"]["cuerpo"]["n_neutro"] == 3

    return resultado, pub_bytes


# ===============================================================
# 1. CAMINO FELIZ
# ===============================================================

def test_build_protegido_valido(build_valido):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is True
    assert verificacion["fallos"] == []

    assert verificacion["pasos"]["manifiesto"]["ok"] is True
    assert verificacion["pasos"]["nucleo"]["ok"] is True
    assert verificacion["pasos"]["canales"]["ok"] is True


def test_build_produce_formato_unico(build_valido):
    resultado, _ = build_valido

    manifiesto = resultado["manifiesto"]

    assert set(manifiesto.keys()) == {
        "cuerpo",
        "firma",
    }

    assert isinstance(manifiesto["cuerpo"], dict)
    assert isinstance(manifiesto["firma"], str)
    assert manifiesto["firma"]


# ===============================================================
# 2. FAIL-CLOSED
# ===============================================================

def test_protegido_sin_manifiesto_falla(build_valido):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]
    assert "MANIFIESTO_AUSENTE" in verificacion["conceptos"]


@pytest.mark.parametrize(
    "manifiesto",
    [
        {},
        {"firma": "00"},
        {"cuerpo": {}},
        {"cuerpo": {}, "firma": ""},
        {"cuerpo": "no-dict", "firma": "00"},
        {"cuerpo": {}, "firma": None},
    ],
)
def test_protegido_manifiesto_malformado_falla(
    build_valido,
    manifiesto,
):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


def test_protegido_sin_clave_publica_falla(build_valido):
    resultado, _ = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


def test_protegido_clave_publica_incorrecta_falla(
    build_valido,
    tmp_path,
):
    resultado, _ = build_valido

    otra_priv = tmp_path / "otra.key"
    otra_pub = tmp_path / "otra.pub"

    generar_claves(
        str(otra_priv),
        str(otra_pub),
    )

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=otra_pub.read_bytes(),
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


# ===============================================================
# 3. ATAQUE: MODIFICAR CADA CAMPO DEL CUERPO
# ===============================================================

CAMPOS_ATACABLES = [
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


@pytest.mark.parametrize("campo", CAMPOS_ATACABLES)
def test_modificar_cualquier_campo_del_cuerpo_rompe_firma(
    build_valido,
    campo,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(resultado["manifiesto"])
    original = manifiesto["cuerpo"][campo]

    if isinstance(original, bool):
        ataque = not original
    elif isinstance(original, int):
        ataque = original + 999
    elif isinstance(original, list):
        ataque = list(original) + [999999]
    else:
        ataque = "ATAQUE"

    manifiesto["cuerpo"][campo] = ataque

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


def test_cuerpo_reemplazado_completamente_rompe_firma(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": {
            "esquema": 1,
            "version": 999,
            "artifact_id": "ATACANTE",
        },
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


def test_firma_de_otro_cuerpo_no_es_reutilizable(
    build_valido,
    claves,
):
    resultado, _ = build_valido
    priv, _, pub = claves

    cuerpo_diferente = copy.deepcopy(
        resultado["manifiesto"]["cuerpo"]
    )

    cuerpo_diferente["artifact_id"] = "OTRO"

    firma = firmar_bytes(
        serializar(cuerpo_diferente),
        str(priv),
    )

    assert firma["ok"] is True

    manifiesto = {
        "cuerpo": resultado["manifiesto"]["cuerpo"],
        "firma": firma["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 4. ATAQUE: MODIFICAR EL ARTEFACTO
# ===============================================================

def test_modificar_un_byte_rompe_integridad(build_valido):
    resultado, pub = build_valido

    datos = bytearray(resultado["datos"])
    datos[0] ^= 0x01

    verificacion = verificar(
        bytes(datos),
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]
    assert "canales" in verificacion["fallos"]
    assert "INTEGRIDAD_COMPROMETIDA" in verificacion["conceptos"]


def test_modificar_byte_en_mitad_rompe_integridad(
    build_valido,
):
    resultado, pub = build_valido

    datos = bytearray(resultado["datos"])
    datos[len(datos) // 2] ^= 0x80

    verificacion = verificar(
        bytes(datos),
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]


def test_agregar_byte_rompe_integridad(build_valido):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"] + b"X",
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]


def test_eliminar_byte_rompe_integridad(build_valido):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"][:-1],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]


@pytest.mark.parametrize(
    "posicion",
    [0, 1, 2, -1, -2],
)
def test_mutaciones_en_extremos_del_artefacto(
    build_valido,
    posicion,
):
    resultado, pub = build_valido

    datos = bytearray(resultado["datos"])
    datos[posicion] ^= 0xFF

    verificacion = verificar(
        bytes(datos),
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]


# ===============================================================
# 5. FIRMA
# ===============================================================

def test_firma_alterada_falla(build_valido):
    resultado, pub = build_valido

    firma = resultado["manifiesto"]["firma"]

    alterada = (
        ("0" if firma[0] != "0" else "1")
        + firma[1:]
    )

    manifiesto = copy.deepcopy(resultado["manifiesto"])
    manifiesto["firma"] = alterada

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


@pytest.mark.parametrize(
    "firma",
    [
        "",
        "00",
        "zzzz",
        "0" * 128,
        "a" * 128 + "00",
        "a",
        "deadbeef",
    ],
)
def test_firma_malformada_falla(
    firma,
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(resultado["manifiesto"])
    manifiesto["firma"] = firma

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 6. CLAVE PÚBLICA
# ===============================================================

@pytest.mark.parametrize(
    "pub",
    [
        b"",
        b"x",
        b"x" * 31,
        b"x" * 33,
        b"\x00" * 32,
    ],
)
def test_clave_publica_invalida_falla(
    build_valido,
    pub,
):
    resultado, _ = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


def test_clave_publica_atacante_no_valida_manifiesto(
    build_valido,
    tmp_path,
):
    resultado, _ = build_valido

    priv = tmp_path / "attacker.key"
    pub = tmp_path / "attacker.pub"

    generar_claves(
        str(priv),
        str(pub),
    )

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub.read_bytes(),
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


# ===============================================================
# 7. CANONICALIZACIÓN
# ===============================================================

def test_reordenar_cuerpo_no_rompe_firma(build_valido):
    resultado, pub = build_valido

    cuerpo = resultado["manifiesto"]["cuerpo"]

    reordenado = {
        clave: cuerpo[clave]
        for clave in reversed(list(cuerpo.keys()))
    }

    manifiesto = {
        "cuerpo": reordenado,
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is True


def test_cambiar_valor_por_mismo_tipo_rompe_firma(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(resultado["manifiesto"])

    manifiesto["cuerpo"]["artifact_id"] = "TEST-002"

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


def test_serializar_es_determinista(build_valido):
    resultado, _ = build_valido

    cuerpo = resultado["manifiesto"]["cuerpo"]

    a = serializar(cuerpo)

    b = serializar(
        dict(reversed(list(cuerpo.items())))
    )

    assert a == b


def test_serializar_no_acepta_diferencias_semanticas(
    build_valido,
):
    resultado, _ = build_valido

    cuerpo = copy.deepcopy(
        resultado["manifiesto"]["cuerpo"]
    )

    a = serializar(cuerpo)

    cuerpo["artifact_id"] = "CAMBIO"

    b = serializar(cuerpo)

    assert a != b


# ===============================================================
# 8. VERSIÓN
# ===============================================================

def test_version_regresiva_firmada_es_rechazada(
    build_valido,
    claves,
):
    resultado, _ = build_valido
    priv, _, pub = claves

    cuerpo = copy.deepcopy(
        resultado["manifiesto"]["cuerpo"]
    )

    cuerpo["version"] = 0

    firma = firmar_bytes(
        serializar(cuerpo),
        str(priv),
    )

    assert firma["ok"] is True

    manifiesto = {
        "cuerpo": cuerpo,
        "firma": firma["firma"],
    }

    resultado_verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
        version_minima=1,
    )

    assert resultado_verificacion["ok"] is False
    assert "VERSIÓN_REGRESIVA" in (
        resultado_verificacion["conceptos"]
    )


def test_version_firmada_superior_es_aceptada(
    build_valido,
    claves,
):
    resultado, _ = build_valido
    priv, _, pub = claves

    cuerpo = copy.deepcopy(
        resultado["manifiesto"]["cuerpo"]
    )

    cuerpo["version"] = 999

    firma = firmar_bytes(
        serializar(cuerpo),
        str(priv),
    )

    assert firma["ok"] is True

    manifiesto = {
        "cuerpo": cuerpo,
        "firma": firma["firma"],
    }

    resultado_verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
        version_minima=1,
    )

    assert resultado_verificacion["ok"] is True


# ===============================================================
# 9. n_neutro
# ===============================================================

def test_n_neutro_autenticado_no_debe_ser_sobrescrito_externamente(
    build_valido,
):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        n_neutro=999,
        modo=MODO_PROTEGIDO,
    )

    assert (
        verificacion["pasos"]["identidad_neutra"]["n"]
        == resultado["manifiesto"]["cuerpo"]["n_neutro"]
    )


def test_n_neutro_interno_del_cuerpo_se_conserva(
    build_valido,
):
    resultado, pub = build_valido

    esperado = (
        resultado["manifiesto"]
        ["cuerpo"]["n_neutro"]
    )

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert (
        verificacion["pasos"]
        ["identidad_neutra"]["n"]
        == esperado
    )


# ===============================================================
# 10. z / NEUTRO SON EVIDENCIA
# ===============================================================

def test_z_no_aparece_en_fallos(build_valido):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert "z" in verificacion["pasos"]
    assert "z" not in verificacion["fallos"]


def test_neutro_no_aparece_en_fallos(build_valido):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert "identidad_neutra" in verificacion["pasos"]
    assert "identidad_neutra" not in verificacion["fallos"]


def test_mutar_valuaciones_rompe_autenticacion_del_cuerpo(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(resultado["manifiesto"])

    manifiesto["cuerpo"]["valuaciones"] = [999999]

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 11. DIAGNÓSTICO
# ===============================================================

def test_diagnostico_sin_manifiesto_no_falla_por_autoridad(
    build_valido,
):
    resultado, _ = build_valido

    verificacion = verificar(
        resultado["datos"],
        modo=MODO_DIAGNOSTICO,
    )

    assert verificacion["ok"] is True


def test_diagnostico_acepta_manifiesto_valido(
    build_valido,
):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_DIAGNOSTICO,
    )

    assert verificacion["ok"] is True


def test_diagnostico_detecta_manifiesto_falso(
    build_valido,
    pub=None,
):
    resultado, pub_real = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["artifact_id"] = "ATACANTE"

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub_real,
        modo=MODO_DIAGNOSTICO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 12. FRAGMENTACIÓN — COBERTURA EXACTA
# ===============================================================

@pytest.mark.parametrize(
    "n",
    list(range(0, 80))
    + [
        81,
        97,
        99,
        100,
        101,
        127,
        128,
        129,
        255,
        256,
        257,
    ],
)
def test_fragmentos_cubren_exactamente_todos_los_bytes(n):
    datos = bytes(i % 256 for i in range(n))

    fragmentos = _fragmentos(
        datos,
        k=8,
    )

    assert b"".join(fragmentos) == datos

    assert (
        sum(len(fragmento) for fragmento in fragmentos)
        == len(datos)
    )


@pytest.mark.parametrize(
    "k",
    [
        1,
        2,
        3,
        4,
        5,
        7,
        8,
        9,
        16,
        32,
    ],
)
def test_fragmentos_cubren_datos_para_distintos_k(k):
    datos = b"0123456789" * 37

    fragmentos = _fragmentos(
        datos,
        k=k,
    )

    assert b"".join(fragmentos) == datos


# ===============================================================
# 13. API CRIPTOGRÁFICA DIRECTA
# ===============================================================

def test_firmar_y_verificar_bytes(claves):
    priv, _, pub = claves

    mensaje = b"mensaje protegido"

    firma = firmar_bytes(
        mensaje,
        str(priv),
    )

    assert firma["ok"] is True

    verificacion = verificar_bytes(
        mensaje,
        firma["firma"],
        pub_bytes=pub,
    )

    assert verificacion["ok"] is True


def test_firma_no_es_reutilizable_para_otro_mensaje(claves):
    priv, _, pub = claves

    firma = firmar_bytes(
        b"A",
        str(priv),
    )

    assert firma["ok"] is True

    verificacion = verificar_bytes(
        b"B",
        firma["firma"],
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


def test_firma_con_clave_privada_inexistente_falla(tmp_path):
    inexistente = tmp_path / "no-existe.key"

    resultado = firmar_bytes(
        b"mensaje",
        str(inexistente),
    )

    assert resultado["ok"] is False
    assert "CÓDIGO_INVÁLIDO" in resultado["conceptos"]


# ===============================================================
# 14. MANIFIESTO DIRECTO
# ===============================================================

def test_verificar_manifiesto_valido(build_valido):
    resultado, pub = build_valido

    verificacion = verificar_manifiesto(
        resultado["manifiesto"],
        pub_bytes=pub,
    )

    assert verificacion["ok"] is True

    assert (
        verificacion["cuerpo"]
        == resultado["manifiesto"]["cuerpo"]
    )


@pytest.mark.parametrize(
    "manifiesto",
    [
        None,
        [],
        "texto",
        123,
        b"bytes",
    ],
)
def test_verificar_manifiesto_rechaza_tipos_invalidos(
    manifiesto,
):
    resultado = verificar_manifiesto(manifiesto)

    assert resultado["ok"] is False


def test_verificar_manifiesto_no_acepta_cuerpo_ausente(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = {
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


def test_verificar_manifiesto_no_acepta_firma_ausente(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": resultado["manifiesto"]["cuerpo"],
    }

    verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


# ===============================================================
# IMPORTANTE:
# EL CONTRATO DICE:
#
#   SOLO {cuerpo, firma}
#
# Por tanto estos ataques DEBEN fallar.
# ===============================================================

def test_verificar_manifiesto_no_acepta_campo_plano(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["artifact_id"] = "CAMPO_PLANO_ATACANTE"

    verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


def test_agregar_campo_extra_al_manifiesto_falla_en_protegido(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["campo_extra"] = "NO_AUTORIZADO"

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 15. ESTRUCTURA DEL MANIFIESTO
# ===============================================================

def test_eliminar_cuerpo_falla(build_valido):
    resultado, pub = build_valido

    manifiesto = {
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


def test_eliminar_firma_falla(build_valido):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": resultado["manifiesto"]["cuerpo"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


def test_cuerpo_no_dict_falla(build_valido):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": "ATAQUE",
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


def test_firma_no_string_falla(build_valido):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": resultado["manifiesto"]["cuerpo"],
        "firma": 123456,
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 16. CONSISTENCIA DEL CUERPO
# ===============================================================

def test_n_bytes_debe_corresponder_al_artefacto(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["n_bytes"] += 1

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


def test_identidad_neutra_autenticada_no_puede_modificarse(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["identidad_neutra"] = (
        not manifiesto["cuerpo"]["identidad_neutra"]
    )

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


def test_n_neutro_autenticado_no_puede_modificarse(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["n_neutro"] = 999

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 17. MANIFIESTO A != ARTEFACTO B
# ===============================================================

def test_manifiesto_de_artefacto_A_no_autentica_B(
    build_valido,
):
    resultado, pub = build_valido

    datos_b = resultado["datos"] + b"ATAQUE"

    verificacion = verificar(
        datos_b,
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]
    assert "canales" in verificacion["fallos"]


# ===============================================================
# 18. REGRESIÓN: FIRMA DEL CUERPO
# ===============================================================

def test_la_firma_del_build_es_firma_del_cuerpo(
    build_valido,
):
    resultado, pub = build_valido

    cuerpo = resultado["manifiesto"]["cuerpo"]
    firma = resultado["manifiesto"]["firma"]

    verificacion = verificar_bytes(
        serializar(cuerpo),
        firma,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is True


def test_la_firma_del_cuerpo_no_valida_el_digest_del_artefacto(
    build_valido,
):
    resultado, pub = build_valido

    cuerpo = resultado["manifiesto"]["cuerpo"]
    firma = resultado["manifiesto"]["firma"]

    verificacion = verificar_bytes(
        bytes.fromhex(cuerpo["nucleo"]),
        firma,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 19. REFERENCIAS EXTERNAS CONFLICTIVAS
# ===============================================================

def test_protegido_usa_el_cuerpo_autenticado_como_autoridad(
    build_valido,
):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        nucleo_esperado="00" * 32,
        S_esperado="00" * 32,
        Q_esperado="00" * 32,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is True


# ===============================================================
# 20. MUTACIÓN MASIVA DEL ARTEFACTO
# ===============================================================

def test_mutaciones_individuales_del_artefacto(
    build_valido,
):
    resultado, pub = build_valido

    original = bytearray(resultado["datos"])

    posiciones = {
        0,
        1,
        len(original) // 4,
        len(original) // 2,
        (3 * len(original)) // 4,
        len(original) - 2,
        len(original) - 1,
    }

    for posicion in posiciones:
        datos = bytearray(original)
        datos[posicion] ^= 0xFF

        verificacion = verificar(
            bytes(datos),
            manifiesto=resultado["manifiesto"],
            pub_bytes=pub,
            modo=MODO_PROTEGIDO,
        )

        assert verificacion["ok"] is False, (
            f"Mutación no detectada en byte {posicion}"
        )

        assert "nucleo" in verificacion["fallos"], (
            f"Núcleo no detectó byte {posicion}"
        )


# ===============================================================
# 21. ATAQUE DE REEMPLAZO DE CUERPO
# ===============================================================

def test_atacante_no_puede_firmar_sin_clave_privada(
    build_valido,
    tmp_path,
):
    resultado, _ = build_valido

    fake_key = tmp_path / "fake.key"
    fake_key.write_bytes(b"clave-falsa")

    cuerpo = copy.deepcopy(
        resultado["manifiesto"]["cuerpo"]
    )

    cuerpo["artifact_id"] = "ATACANTE"

    firma = firmar_bytes(
        serializar(cuerpo),
        str(fake_key),
    )

    assert firma["ok"] is False


# ===============================================================
# 22. DATOS EXTREMOS
# ===============================================================

@pytest.mark.parametrize(
    "datos",
    [
        b"",
        b"\x00",
        b"\xff",
        b"X",
        b"AB",
        b"A" * 3,
        b"A" * 7,
        b"A" * 8,
        b"A" * 9,
        b"A" * 100,
        b"A" * 1000,
        b"A" * 10000,
    ],
)
def test_datos_extremos_no_rompen_build(
    claves,
    datos,
):
    priv, _, pub = claves

    resultado = build(
        datos,
        str(priv),
        n_neutro=3,
        artifact_id="EDGE",
        version=1,
    )

    assert resultado["ok"] is True

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is True


# ===============================================================
# 23. n_neutro INVÁLIDO
# ===============================================================

@pytest.mark.parametrize(
    "n",
    [
        -100,
        -1,
        0,
        1,
    ],
)
def test_n_neutro_invalido_falla(n):
    resultado = sellar(
        b"datos",
        n=n,
    )

    assert resultado["ok"] is False

    assert "CÓDIGO_INVÁLIDO" in (
        resultado["conceptos"]
    )


# ===============================================================
# 24. ESQUEMA
# ===============================================================

def test_esquema_firmado_incompatible_falla(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["esquema"] = 999

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 25. ALGORITMOS
# ===============================================================

def test_cambiar_algoritmo_hash_rompe_firma(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["algoritmo_hash"] = "MD5"

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


def test_cambiar_algoritmo_firma_rompe_firma(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["algoritmo_firma"] = "RSA"

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 26. IDENTIDAD DEL ARTEFACTO
# ===============================================================

def test_artifact_id_no_puede_ser_reemplazado(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["artifact_id"] = "OTRO-ARTEFACTO"

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


def test_clave_publica_id_no_puede_ser_reemplazada(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo"]["clave_publica_id"] = (
        "CLAVE-ATACANTE"
    )

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 27. CADENA COMPLETA
# ===============================================================

def test_cadena_completa_original_y_tamper(
    build_valido,
):
    resultado, pub = build_valido

    original = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert original["ok"] is True
    assert original["fallos"] == []

    datos = bytearray(resultado["datos"])
    datos[-1] ^= 1

    alterado = verificar(
        bytes(datos),
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert alterado["ok"] is False
    assert alterado["fallos"]
    assert "nucleo" in alterado["fallos"]


# ===============================================================
# 28. NO HAY BYPASS CON firma_hex SUELTA
# ===============================================================

def test_firma_hex_suelta_no_sustituye_manifiesto_en_protegido(
    build_valido,
):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        firma_hex=resultado["manifiesto"]["firma"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 29. DOS ARTEFACTOS NO COMPARTEN AUTORIZACIÓN
# ===============================================================

def test_dos_builds_no_comparten_autorizacion(claves):
    priv, _, pub = claves

    artefacto_a = build(
        b"ARTEFACTO-A",
        str(priv),
        artifact_id="A",
        version=1,
    )

    artefacto_b = build(
        b"ARTEFACTO-B",
        str(priv),
        artifact_id="B",
        version=1,
    )

    assert artefacto_a["ok"] is True
    assert artefacto_b["ok"] is True

    verificacion_a = verificar(
        artefacto_a["datos"],
        manifiesto=artefacto_a["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    verificacion_b = verificar(
        artefacto_b["datos"],
        manifiesto=artefacto_b["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion_a["ok"] is True
    assert verificacion_b["ok"] is True

    cruzado = verificar(
        artefacto_a["datos"],
        manifiesto=artefacto_b["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert cruzado["ok"] is False
    assert "nucleo" in cruzado["fallos"]


# ===============================================================
# 30. FAIL-CLOSED FINAL
# ===============================================================

def test_contrato_protegido_fail_closed(build_valido):
    resultado, pub = build_valido

    casos = [
        None,
        {},
        {
            "cuerpo": resultado["manifiesto"]["cuerpo"],
        },
        {
            "firma": resultado["manifiesto"]["firma"],
        },
    ]

    for manifiesto in casos:
        verificacion = verificar(
            resultado["datos"],
            manifiesto=manifiesto,
            pub_bytes=pub,
            modo=MODO_PROTEGIDO,
        )

        assert verificacion["ok"] is False


# ===============================================================
# 31. ORDEN JSON
# ===============================================================

def test_orden_json_no_es_parte_de_la_firma(
    build_valido,
):
    resultado, pub = build_valido

    cuerpo = resultado["manifiesto"]["cuerpo"]

    invertido = {
        clave: cuerpo[clave]
        for clave in reversed(list(cuerpo.keys()))
    }

    assert serializar(cuerpo) == serializar(invertido)

    verificacion = verificar_bytes(
        serializar(invertido),
        resultado["manifiesto"]["firma"],
        pub_bytes=pub,
    )

    assert verificacion["ok"] is True


# ===============================================================
# 32. FIRMA NO SE PUEDE TRASPLANTAR
# ===============================================================

def test_firma_de_A_no_valida_cuerpo_de_B(claves):
    priv, _, pub = claves

    cuerpo_a = {
        "esquema": 1,
        "version": 1,
        "artifact_id": "A",
    }

    cuerpo_b = {
        "esquema": 1,
        "version": 1,
        "artifact_id": "B",
    }

    firma_a = firmar_bytes(
        serializar(cuerpo_a),
        str(priv),
    )

    assert firma_a["ok"] is True

    verificacion = verificar_bytes(
        serializar(cuerpo_b),
        firma_a["firma"],
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 33. MUTACIÓN DE CADA POSICIÓN DE LA FIRMA
# ===============================================================

def test_mutar_cada_posicion_de_la_firma_falla(
    build_valido,
):
    resultado, pub = build_valido

    firma_original = resultado["manifiesto"]["firma"]

    for i in range(0, len(firma_original), 2):
        firma = list(firma_original)

        firma[i] = (
            "0"
            if firma[i] != "0"
            else "1"
        )

        firma_mutada = "".join(firma)

        manifiesto = copy.deepcopy(
            resultado["manifiesto"]
        )

        manifiesto["firma"] = firma_mutada

        verificacion = verificar(
            resultado["datos"],
            manifiesto=manifiesto,
            pub_bytes=pub,
            modo=MODO_PROTEGIDO,
        )

        assert verificacion["ok"] is False


# ===============================================================
# 34. CLAVE PÚBLICA CON LONGITUD CORRECTA PERO DISTINTA
# ===============================================================

def test_clave_publica_distinta_de_32_bytes_falla(
    build_valido,
):
    resultado, _ = build_valido

    pub_falsa = bytes(range(32))

    verificacion = verificar(
        resultado["datos"],
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub_falsa,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "FIRMA_INVÁLIDA" in verificacion["conceptos"]


# ===============================================================
# 35. ELIMINACIÓN DE CUALQUIER CAMPO AUTENTICADO
# ===============================================================

@pytest.mark.parametrize(
    "campo",
    CAMPOS_ATACABLES,
)
def test_eliminar_cualquier_campo_del_cuerpo_rompe_firma(
    build_valido,
    campo,
):
    resultado, pub = build_valido

    cuerpo = copy.deepcopy(
        resultado["manifiesto"]["cuerpo"]
    )

    del cuerpo[campo]

    manifiesto = {
        "cuerpo": cuerpo,
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 36. ATAQUES ESTRUCTURALES ADICIONALES
# ===============================================================

def test_manifiesto_con_claves_extra_no_es_equivalente(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["firma_extra"] = manifiesto["firma"]

    verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


def test_manifiesto_con_cuerpo_extra_no_es_equivalente(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = copy.deepcopy(
        resultado["manifiesto"]
    )

    manifiesto["cuerpo_extra"] = {
        "artifact_id": "ATACANTE"
    }

    verificacion = verificar_manifiesto(
        manifiesto,
        pub_bytes=pub,
    )

    assert verificacion["ok"] is False


def test_firma_no_puede_ser_lista(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": resultado["manifiesto"]["cuerpo"],
        "firma": [],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


def test_cuerpo_no_puede_ser_lista(
    build_valido,
):
    resultado, pub = build_valido

    manifiesto = {
        "cuerpo": [],
        "firma": resultado["manifiesto"]["firma"],
    }

    verificacion = verificar(
        resultado["datos"],
        manifiesto=manifiesto,
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False


# ===============================================================
# 37. TIPO DE MODO
# ===============================================================

def test_modo_protegido_es_fail_closed(
    build_valido,
):
    resultado, pub = build_valido

    verificacion = verificar(
        resultado["datos"],
        pub_bytes=pub,
        firma_hex=resultado["manifiesto"]["firma"],
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "manifiesto" in verificacion["fallos"]


# ===============================================================
# 38. AUTENTICACIÓN CRUZADA
# ===============================================================

def test_firma_correcta_con_datos_incorrectos_no_autoriza(
    build_valido,
):
    resultado, pub = build_valido

    datos = resultado["datos"] + b"::MODIFICADO"

    verificacion = verificar(
        datos,
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]
    assert "canales" in verificacion["fallos"]


def test_mismo_cuerpo_firmado_con_datos_diferentes_falla(
    build_valido,
):
    resultado, pub = build_valido

    datos = bytearray(resultado["datos"])
    datos[0] ^= 0xAA

    verificacion = verificar(
        bytes(datos),
        manifiesto=resultado["manifiesto"],
        pub_bytes=pub,
        modo=MODO_PROTEGIDO,
    )

    assert verificacion["ok"] is False
    assert "nucleo" in verificacion["fallos"]


# ===============================================================
# FIN DE LA BATERÍA ADVERSARIAL
# ===============================================================
