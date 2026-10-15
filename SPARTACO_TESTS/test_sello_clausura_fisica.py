# ===========================================================================
# SPARTACO-SECURITY — tests/test_sello_clausura_fisica.py
# ===========================================================================
#
# CRAFT, NOT VOCABULARY
# ---------------------------------------------------------------------------
# This file does not search for the string "ALPHA" in the source code.
# It does not patch attributes in RAM to force a result.
# The CI measures bytes, modules and halves — nothing else.
#
# THESIS
# ---------------------------------------------------------------------------
# Declaring an algebraic architecture is not the same as operating it.
# The cube declares a partition (3 divisions per axis, 27 cells, 26
# exterior, 1 center, ALPHA = 26/27, BETA = 1/27). That algebra is
# coherent in the constants module. It is NOT guaranteed to be the
# algebra that the sealing function actually uses when it produces
# bytes. This file closes that gap by measuring the REAL bytes the
# sealing produces and verifying that they satisfy the modular
# property of the axis. It is the difference between declaring an
# architecture and operating it.
#
# WHAT THIS FILE IS
# ---------------------------------------------------------------------------
# A closure test. It verifies correspondence between two levels of the
# architecture and requires that they match:
#
#   * algebraic constants of the cube  <->  bytes produced by the seal
#   * API defaults (measured via inspect.signature)  <->  declared
#     constant of the axis
#   * signed body fields  <->  channels derived from the sealed payload
#   * legitimate material  <->  document opens
#   * alien material  <->  document does not open
#   * one-byte mutation  <->  document does not open
#   * partial secret injection  <->  document does not open
#
# It does NOT search by symbol name. It measures effective values: the
# actual default stored on the function object, the actual hash of the
# actual bytes, the actual modular residue. Renaming the constant does
# not change the test; changing its value does.
#
# TESTS
# ---------------------------------------------------------------------------
#   test_050  cube partition: divisions per axis, total, exterior,
#             center, ALPHA and BETA as Fraction, ALPHA + BETA == 1
#             exactly (not as floating-point approximation).
#
#   test_051  the seal uses the axis of the cube. Reads the actual
#             defaults of P.sellar(n) and C.proteger(n_neutro) via
#             inspect.signature and requires both to equal
#             DIVISIONS_PER_AXIS. Coupled to the effective value, not
#             to the symbol name.
#
#   test_052  the seal closes the modulo of the axis. For nine distinct
#             payloads across three cycles, seals each one, hashes the
#             resulting bytes, requires the integer hash to be exactly
#             divisible by the number of divisions per axis, and
#             requires verificar_neutro to accept the same blob. The
#             physical closure of the algebraic property over the
#             actual bytes.
#
#   test_053  the signed body signs the axis. Builds a body from a
#             sealed payload, requires cuerpo["n_neutro"] to equal
#             DIVISIONS_PER_AXIS, and requires the S and Q channels
#             declared in the body to equal the ones returned by the
#             channels function on the same sealed payload.
#
#   test_054  end-to-end legitimate path: with secrets derived from a
#             known label, the document opens and the plaintext
#             matches.
#
#   test_055  alien material does not open: the same blob with wrong
#             authentication material is rejected without exposing a
#             plaintext.
#
#   test_056  a single-byte flip does not open.
#
#   test_057  a single injection does not open: passing only the
#             authentication secret, or only the session secret, is
#             rejected in both cases. Both secrets are mandatory.
#
# DESIGN NOTES
# ---------------------------------------------------------------------------
#   * inspect.signature is used to read the effective default value,
#     not to read source text.
#   * The modular property is checked on real bytes, not on
#     intermediate symbolic values.
#   * Nine payloads (three cycles of three) cover all equivalence
#     classes modulo three, so the modular property cannot pass by
#     accident on a single case.
#   * Fractions are used, not floats, so the sum of ALPHA and BETA is
#     checked for exact equality.
#   * The tests are few because the property is structural, not
#     statistical. No parameterisation is needed to make the point.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It is not adversarial: it does not try to break the module.
#   - It is not metrological: it does not qualify its own instrument.
#   - It is not an audit of an isolated resource.
#   - It does not certify the whole system: it certifies that a
#     declared algebraic architecture is physically operated by the
#     bytes the system produces.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The adversarial battery attacks the layered architecture of
# proteccion.py. The credential red-teams attack credencial.py. The
# metrological kernel audits the instruments. The integration smoke
# test checks the honest end-to-end path. The monitor correlates
# external and internal observation. The fail-closed auditor qualifies
# itself against synthetic controls. This file closes the loop between
# declared algebra and produced bytes: it verifies that what the
# architecture says about the cube is what the system does, in bytes,
# without searching for names and without forcing memory.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# An architecture that declares algebra and does not operate it is
# decorative. A test that searches for a symbol name confirms
# vocabulary, not behaviour. A test that patches memory confirms
# nothing. This file measures the effective default, the produced
# bytes, the modular residue, the derived channels and the mandatory
# secrets, and requires each of them to match what the architecture
# declares. Craft, not vocabulary.
#
# ===========================================================================

from __future__ import annotations

import hashlib
import inspect
from fractions import Fraction

import modules.spartaco_seguridad.credencial as C
import modules.spartaco_seguridad.proteccion as P
from modules.constante.constante import (
    ALPHA,
    BETA,
    CUBE_CENTER,
    CUBE_EXTERIOR,
    CUBE_TOTAL,
    DIVISIONS_PER_AXIS,
)


def _mat(etiqueta: bytes) -> bytes:
    return hashlib.sha256(b"UIS-CI|" + etiqueta).digest()


def _par(tmp_path):
    priv = tmp_path / "cierre.priv"
    pub = tmp_path / "cierre.pub"
    r = P.generar_claves(str(priv), str(pub))
    assert r.get("ok") is True, r
    return priv, pub


def _proteger(tmp_path, claro: bytes, etiqueta: bytes):
    priv, pub = _par(tmp_path)
    r = C.proteger(
        claro,
        str(priv),
        artifact_id="art-" + etiqueta.hex()[:16],
        authority_id="aut-" + etiqueta.hex()[16:32],
        secreto_autenticacion=_mat(b"A|" + etiqueta),
        secreto_defensa=_mat(b"D|" + etiqueta),
        secreto_sesion=_mat(b"S|" + etiqueta),
    )
    assert r.get("ok") is True, r
    return r, pub.read_bytes()


def test_050_particion_del_cubo():
    assert DIVISIONS_PER_AXIS == 3
    assert CUBE_TOTAL == 27
    assert CUBE_EXTERIOR == 26
    assert CUBE_CENTER == 1
    assert ALPHA == Fraction(CUBE_EXTERIOR, CUBE_TOTAL)
    assert BETA == Fraction(CUBE_CENTER, CUBE_TOTAL)
    assert ALPHA + BETA == Fraction(1)


def test_051_sello_usa_el_eje_del_cubo():
    n_sello = inspect.signature(P.sellar).parameters["n"].default
    n_proteger = inspect.signature(C.proteger).parameters["n_neutro"].default
    assert n_sello == DIVISIONS_PER_AXIS
    assert n_proteger == DIVISIONS_PER_AXIS


def test_052_sello_cierra_modulo_del_eje():
    n = DIVISIONS_PER_AXIS
    for i in range(n * 3):
        payload = bytes([i & 255]) * 48 + i.to_bytes(4, "big")
        sello = P.sellar(payload, n=n)
        assert sello.get("ok") is True, sello
        blob = sello["datos"]
        h = int(hashlib.sha256(blob).hexdigest(), 16)
        assert h % n == 0
        neutro = P.verificar_neutro(blob, n=n)
        assert neutro.get("ok") is True, neutro


def test_053_cuerpo_firma_el_eje():
    datos = bytes(range(64))
    sello = P.sellar(datos, n=DIVISIONS_PER_AXIS)
    assert sello.get("ok") is True
    cuerpo = P.construir_cuerpo(
        sello["datos"],
        n_neutro=DIVISIONS_PER_AXIS,
        artifact_id="eje",
        clave_publica_id="aut",
    )
    assert cuerpo.get("ok") is True, cuerpo
    assert cuerpo["cuerpo"]["n_neutro"] == DIVISIONS_PER_AXIS
    s_ch, q_ch = P.canales(sello["datos"])
    assert cuerpo["cuerpo"]["S"] == s_ch
    assert cuerpo["cuerpo"]["Q"] == q_ch


def test_054_sobre_y_material_del_dominio_abren(tmp_path):
    claro = bytes(range(256)) + b"|CIERRE|"
    etq = b"054"
    prot, pub = _proteger(tmp_path, claro, etq)
    ab = C.abrir_documento(
        prot["blob"],
        manifiesto=prot["manifiesto"],
        pub_bytes=pub,
        secreto_autenticacion=_mat(b"A|" + etq),
        secreto_sesion=_mat(b"S|" + etq),
    )
    assert ab.get("ok") is True, ab
    assert ab.get("plaintext") == claro


def test_055_material_ajeno_no_abre(tmp_path):
    claro = bytes(range(256)) + b"|CIERRE|"
    etq = b"055"
    prot, pub = _proteger(tmp_path, claro, etq)
    ab = C.abrir_documento(
        prot["blob"],
        manifiesto=prot["manifiesto"],
        pub_bytes=pub,
        secreto_autenticacion=_mat(b"A-AJENO|" + etq),
        secreto_sesion=_mat(b"S|" + etq),
    )
    assert ab.get("ok") is False, ab
    assert "plaintext" not in ab or ab.get("plaintext") is None


def test_056_un_byte_no_abre(tmp_path):
    claro = bytes(range(256)) + b"|CIERRE|"
    etq = b"056"
    prot, pub = _proteger(tmp_path, claro, etq)
    mut = bytearray(prot["blob"])
    mut[0] ^= 0x01
    ab = C.abrir_documento(
        bytes(mut),
        manifiesto=prot["manifiesto"],
        pub_bytes=pub,
        secreto_autenticacion=_mat(b"A|" + etq),
        secreto_sesion=_mat(b"S|" + etq),
    )
    assert ab.get("ok") is False, ab
    assert "plaintext" not in ab or ab.get("plaintext") is None


def test_057_una_sola_inyeccion_no_abre(tmp_path):
    claro = bytes(range(256)) + b"|CIERRE|"
    etq = b"057"
    prot, pub = _proteger(tmp_path, claro, etq)
    solo_auth = C.abrir_documento(
        prot["blob"],
        manifiesto=prot["manifiesto"],
        pub_bytes=pub,
        secreto_autenticacion=_mat(b"A|" + etq),
    )
    solo_ses = C.abrir_documento(
        prot["blob"],
        manifiesto=prot["manifiesto"],
        pub_bytes=pub,
        secreto_sesion=_mat(b"S|" + etq),
    )
    assert solo_auth.get("ok") is False, solo_auth
    assert solo_ses.get("ok") is False, solo_ses
