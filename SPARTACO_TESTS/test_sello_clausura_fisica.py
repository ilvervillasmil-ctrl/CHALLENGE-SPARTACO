#==============================================================
# tests/test_sello_clausura_fisica.py
#
# Oficio, no vocabulario.
# No busca la cadena "ALPHA".
# No parchea atributos en RAM.
# El CI mide bytes, módulos y mitades.
# ==============================================================

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
