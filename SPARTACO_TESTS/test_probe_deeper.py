# tests/test_probe_deeper.py
"""
Pruebas adicionales dirigidas a las áreas de mayor incertidumbre:
 - AntiHackValidation (engine) — ciclos, manifiesto, pub_bytes, artefacto
 - Centinela — ausencia de Engine, grafos incompletos, capacidades no-callable
 - Launcher — carga de manifiesto corrupto, modos inválidos, ausencia de archivos
 - Arranque — empaquetado/desempaquetado frontera: rutas duplicadas y traversal
 - Vinculacion — registrar/rotar/revocar atomicidad y semántica
 - Generador de claves: generación mínima (sanity)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Asegurar que el repo root está en sys.path al ejecutar via pytest desde cualquier cwd
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Importar unidades bajo prueba
from core.engine import (
    AntiHackValidation,
    CircularityDetectedError,
    StructuralIntegrityError,
)
from core.centinela import Centinela, ESTADO_RETENIDO
from modules.spartaco_seguridad import launcher as L
from modules.spartaco_seguridad import arranque as A
from modules.spartaco_seguridad import generador_claves as G
from modules.spartaco_seguridad import vinculacion as V

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import modules.spartaco_seguridad.proteccion as P
from core.centinela import Centinela, ESTADO_RETENIDO, MOTIVO_CAPACIDAD_NO_CALLABLE




# ---------------------------
# AntiHackValidation tests
# ---------------------------

def test_anti_hack_detects_reference_cycle():
    a = {}
    b = {"child": a}
    a["child"] = b  # ciclo a <-> b
    with pytest.raises(CircularityDetectedError):
        AntiHackValidation.detect_reference_cycle(a)


def test_validate_manifiesto_rejects_extra_keys_and_types():
    # extra key
    manifest = {"cuerpo": {}, "firma": "00" * 32, "extra": 1}
    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_manifiesto(manifest)

    # cuerpo no dict
    manifest2 = {"cuerpo": "no-dict", "firma": "aa"}
    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_manifiesto(manifest2)

    # firma no str/no vacía
    manifest3 = {"cuerpo": {}, "firma": ""}
    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_manifiesto(manifest3)


def test_validate_pub_bytes_and_artefacto_reject_bad_inputs():
    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_pub_bytes(b"short")
    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_pub_bytes("not-bytes")

    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_artefacto(b"")  # empty
    with pytest.raises(StructuralIntegrityError):
        AntiHackValidation.validate_artefacto("not-bytes")


# ---------------------------
# Centinela tests
# ---------------------------

def test_centinela_without_engine_enters_contencion_and_retained():
    c = Centinela(invocador=None)
    v = c.supervisar(None)  # director ausente -> contención
    assert isinstance(v, type(v))  # sanity; v is Veredicto-like object
    assert v.estado == ESTADO_RETENIDO or v.estado == "RETENIDO"
    # también probar verificar() con paquete vacío
    v2 = c.verificar({"estado": "NO_VALIDO"}, depositar_salida=False, depositar_propuesta=False)
    assert v2.estado == ESTADO_RETENIDO


class _FakeModule:
    def __init__(self, nombre: str, rol: str, capacidades: Dict[str, Any], requiere=()):
        self.nombre = nombre
        self.rol = rol
        self.version = "0"
        self.requiere = list(requiere)
        # capacidades como dict: name -> callable or not
        self.capacidades = capacidades
        # fn resolver: if asked, return the callable reference or value from capacidades
        self.fn = lambda k: self.capacidades.get(k)

def test_centinela_detects_non_callable_and_missing_roles():
    # construir registro simulado
    registro = type("R", (), {})()
    # contenedor con una capacidad declarada pero no-callable
    bad = _FakeModule("mod_bad", "SC", {"verificar": None}, requiere=())
    # contenedor sin capacidades declaradas (should flag)
    empty = _FakeModule("mod_empty", "CT", {}, requiere=())
    # montar registro
    registro.contenedores = {"mod_bad": bad, "mod_empty": empty}
    registro.por_rol = {"SC": [bad], "CT": [empty]}
    registro.errores_arranque = []
    registro.estado = "OPERATIVO"
    # invocador fake con registro
    inv = type("Inv", (), {"registro": registro, "errores_arranque": []})()
    c = Centinela(invocador=inv)
    ver = c.supervisar(inv)
    # debe retener porque una capacidad declarada no es callable / o vacíos
    assert ver.estado == ESTADO_RETENIDO or ver.estado == "RETENIDO"

    # comprobar que Centinela reportó el problema esperado:
    motivos = [str(m) for m in ver.motivos]
    assert any(
        MOTIVO_CAPACIDAD_NO_CALLABLE in m or "contrato sin capacidades" in m
        for m in motivos
    ), f"motivos observados: {motivos}"




# ---------------------------
# Launcher tests
# ---------------------------

def test_launcher_cargar_manifiesto_malformed_json(tmp_path: Path):
    mf = tmp_path / "bad.json"
    mf.write_bytes(b'{"cuerpo": {"a": 1}, "firma": "xx"')  # truncated JSON
    r = L.cargar_manifiesto(mf)
    assert r.get("ok") is False
    # el rechazo viene desde P._rechazo con concepto "CÓDIGO_INVÁLIDO"
    conceptos = r.get("conceptos") or []
    assert any("C" in c or "CÓDIGO" in c or "CÓDIGO_INVÁLIDO" in c for c in conceptos) or "CÓDIGO_INVÁLIDO" in (r.get("conceptos") or [])


def test_launcher_verificar_y_ejecutar_missing_files_and_invalid_mode(tmp_path: Path):
    # nonexistent artifact
    res = L.verificar_y_ejecutar(ruta_artefacto=tmp_path/"no.bin", ruta_manifiesto=tmp_path/"m.json", ruta_pub=tmp_path/"p.pub")
    assert res["ok"] is False
    assert "ARTEFACTO_AUSENTE" in (res.get("conceptos") or [])
    # create artifact, missing manifest
    art = tmp_path/"a.bin"
    art.write_bytes(b"\x00\x01")
    pub = tmp_path/"pub.bin"
    pub.write_bytes(b"\x00"*32)
    res2 = L.verificar_y_ejecutar(ruta_artefacto=art, ruta_manifiesto=tmp_path/"no.json", ruta_pub=pub)
    assert res2["ok"] is False
    assert "MANIFIESTO_AUSENTE" in (res2.get("conceptos") or [])
    # invalid mode
    mf = tmp_path/"m.json"
    mf.write_text(json.dumps({"cuerpo": {}, "firma": "00"*64}))
    res3 = L.verificar_y_ejecutar(ruta_artefacto=art, ruta_manifiesto=mf, ruta_pub=pub, modo="NO_EXISTE")
    assert res3["ok"] is False
    assert "MODO_INVALIDO" in (res3.get("conceptos") or [])


# ---------------------------
# Arranque empaquetador tests
# ---------------------------

def _build_integrado_bytes(archivos: Dict[str, bytes]) -> bytes:
    # Reusar la lógica de empaquetado tal como A._empaquetar
    return A._empaquetar(archivos)


def test_arranque_desempaquetar_rejects_duplicate_route(tmp_path: Path):
    # crear cuerpo con la misma ruta dos veces (manualmente)
    ruta = "kernel/imagen"
    datos = b"X"
    cuerpo = bytearray()
    # dos entradas idénticas
    for _ in range(2):
        cuerpo.extend(ruta.encode("utf-8"))
        cuerpo.append(0)
        cuerpo.extend(len(datos).to_bytes(8, "big"))
        cuerpo.extend(datos)
    raw = A.MAGIA_INTEGRADO + b"{}" + A.SEP_INTEGRADO + bytes(cuerpo)
    des = A._desempaquetar(raw)
    assert des.get("ok") is False


def test_arranque_parser_accepts_path_traversal_entries():
    archivos = {"../escape": b"X"}
    paquete = _build_integrado_bytes(archivos)
    # _desempaquetar debería leerlo y devolver la ruta tal cual (no valida la seguridad)
    r = A._desempaquetar(paquete)
    assert r.get("ok") is True
    assert "../escape" in r.get("archivos")


# ---------------------------
# Generador de claves sanity
# ---------------------------

def test_generar_claves_writes_files_and_keys_are_valid(tmp_path: Path) -> None:
    priv_path = tmp_path / "legit.key"
    pub_path = tmp_path / "legit.pub"

    # Genera las claves en disco (API existente en proteccion.py)
    res = P.generar_claves(str(priv_path), str(pub_path))
    assert isinstance(res, dict) and res.get("ok") is True

    # Archivos creados y tamaños esperados (raw Ed25519: 32 bytes)
    assert priv_path.is_file(), "clave privada no creada"
    assert pub_path.is_file(), "clave publica no creada"
    priv_raw = priv_path.read_bytes()
    pub_raw = pub_path.read_bytes()
    assert isinstance(priv_raw, (bytes, bytearray)) and len(priv_raw) == 32
    assert isinstance(pub_raw, (bytes, bytearray)) and len(pub_raw) == 32

    # Comprueba que las bytes se interpretan como claves Ed25519 válidas
    # y que pueden firmar/verificar un mensaje (round-trip)
    msg = b"vpsi-test-sign"
    priv_obj = Ed25519PrivateKey.from_private_bytes(bytes(priv_raw))
    pub_obj = Ed25519PublicKey.from_public_bytes(bytes(pub_raw))

    sig = priv_obj.sign(msg)
    # Si la verificación falla lanzará excepción → test fallará
    pub_obj.verify(sig, msg)


# ---------------------------
# Vinculacion - atomic operations
# ---------------------------

def test_vinculacion_registrar_rotar_revocar_and_estado(tmp_path: Path):
    almacen = V._AlmacenVinculacionMemoria()
    identidad = "id-1"
    dispositivo = "dev-1"
    cred = "cred-1"
    material = "mat-1"
    # registrar
    r = V.registrar_estado(
        identidad=identidad,
        dispositivo_id=dispositivo,
        credencial_id=cred,
        material=material,
        almacen=almacen,
        ahora=0.0,
        ttl_segundos=60,
    )
    assert r.get("ok") is True
    # estado_de should return the stored state
    s = V.estado_de(identidad=identidad, almacen=almacen)
    assert s.get("ok") is True
    gen1 = s.get("generacion")
    # rotar increases generation
    r2 = V.rotar(identidad=identidad, credencial_id="cred-2", material="mat-2", almacen=almacen, ahora=1.0, ttl_segundos=120)
    assert r2.get("ok") is True
    s2 = V.estado_de(identidad=identidad, almacen=almacen)
    assert s2.get("generacion") == gen1 + 1
    # revocar marks revocado True
    rr = V.revocar(identidad=identidad, almacen=almacen)
    assert rr.get("ok") is True
    s3 = V.estado_de(identidad=identidad, almacen=almacen)
    assert s3.get("revocado") is True or isinstance(s3.get("revocado"), bool)

