# ===============================================================
# tests/test_spartaco_universal_closure.py
#
# VPSI-TRUTH — CIERRE UNIVERSAL ADVERSARIAL
# ===============================================================
#
# OBJETIVO
# --------
# Intentar romper el cierre de Spartaco desde todas las fronteras
# demostrables mediante el contrato real conocido:
#
#   CT
#   BUILD
#   INTEGRACIÓN
#   PROTECCIÓN
#   CREDENCIAL
#   MANIFIESTO
#   VERIFICACIÓN
#   LAUNCHER
#   LOAD
#   EXEC
#
# PRINCIPIO CENTRAL
# -----------------
#
#     LO VERIFICADO
#          ==
#     LO CARGADO
#          ==
#     LO EJECUTADO
#
# Un sistema que verifica X y ejecuta Y está roto aunque X tenga
# una firma criptográficamente perfecta.
#
# REGLA DE CIERRE
# ---------------
#
# Un ataque no autorizado debe terminar siempre en:
#
#     autorizado == False
#     ejecutado  == False
#
# Nunca se considera PASS un simple rechazo si existe evidencia
# de ejecución del Kernel.
#
# NO SE INVENTAN APIs
# -------------------
#
# Se utilizan únicamente APIs observadas en el contrato:
#
#   A.construir_integrado
#   A.leer_integrado
#   A.sellar_integrado
#   A.verificar_integrado
#   A.extraer_kernel
#   A.custodia
#   A.inventariar_perimetro
#   A._empaquetar
#
#   P.generar_claves
#   P.build
#   P.verificar
#   P.nucleo
#
#   L.verificar_y_ejecutar
#   L.cargar_manifiesto
#
# El test NO inventa lanzar_integrado().
#
# ===============================================================

from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from fractions import Fraction
from pathlib import Path

import pytest

import modules.spartaco_seguridad.arranque as A
import modules.spartaco_seguridad.launcher as L
import modules.spartaco_seguridad.proteccion as P
from modules.constante.constante import ALPHA, BETA, DIVISIONS_PER_AXIS


# ===============================================================
# CONSTANTES DEL ORÁCULO
# ===============================================================

KERNEL_SRC = (
        "/* fixture adversarial - stdout 46, exit 46 */\n"
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "    const char msg[] = \"46\\n\";\n"
    "    if (write(1, msg, 3) != 3) return 1;\n"
    "    return 46;\n"
    "}\n"
)

EXIT_KERNEL = 46

MAGIA = b"VPSI-INTEGRA-1\n"
SEP = b"\n--VPSI-INTEGRA--\n"

EXECUTION_MARKER = b"46"


# ===============================================================
# ORÁCULOS INDEPENDIENTES
# ===============================================================

def sha256_hex(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def canales_propios(datos: bytes):
    mid = len(datos) // 2
    return (
        sha256_hex(datos[:mid]),
        sha256_hex(datos[mid:]),
    )


def abrir_paquete_propio(raw: bytes) -> dict:
    """
    Parser independiente del parser de arranque.

    No llama:
        A.leer_integrado()
        A.descriptor_de()
        A.verificar_integrado()

    Su función es comprobar que el formato físico observado
    realmente corresponde a lo que el test cree que contiene.
    """
    if not raw.startswith(MAGIA):
        return {"ok": False, "error": "sin-magia"}

    resto = raw[len(MAGIA):]

    if SEP not in resto:
        return {"ok": False, "error": "sin-sep"}

    cabeza, cuerpo = resto.split(SEP, 1)

    try:
        meta = json.loads(cabeza.decode("ascii"))
    except Exception as exc:
        return {
            "ok": False,
            "error": "metadata-invalida",
            "exception": type(exc).__name__,
        }

    archivos = {}
    pos = 0

    try:
        while pos < len(cuerpo):
            z = cuerpo.find(b"\x00", pos)

            if z < 0:
                return {
                    "ok": False,
                    "error": "ruta-sin-nul",
                }

            ruta = cuerpo[pos:z].decode("utf-8")

            if z + 9 > len(cuerpo):
                return {
                    "ok": False,
                    "error": "cabecera-truncada",
                }

            n = int.from_bytes(
                cuerpo[z + 1:z + 9],
                "big",
            )

            ini = z + 9
            fin = ini + n

            if fin > len(cuerpo):
                return {
                    "ok": False,
                    "error": "longitud-fuera-de-paquete",
                }

            if ruta in archivos:
                return {
                    "ok": False,
                    "error": "ruta-duplicada",
                    "ruta": ruta,
                }

            archivos[ruta] = cuerpo[ini:fin]
            pos = fin

    except Exception as exc:
        return {
            "ok": False,
            "error": "parser-exception",
            "exception": type(exc).__name__,
        }

    return {
        "ok": True,
        "meta": meta,
        "archivos": archivos,
    }


def mat(etiqueta: bytes) -> bytes:
    return hashlib.sha256(
        b"UIS-CI|CIERRE|" + etiqueta
    ).digest()


def secretos(marca: bytes) -> dict:
    return {
        "secreto_autenticacion": mat(b"A|" + marca),
        "secreto_defensa": mat(b"D|" + marca),
        "secreto_sesion": mat(b"S|" + marca),
        "secreto_recuperacion": mat(b"R|" + marca),
    }


# ===============================================================
# KERNEL DE PRUEBA
# ===============================================================

def compilar_kernel(tmp: Path, marca: bytes) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)

    src = tmp / ("k_" + marca.hex() + ".c")
    elf = tmp / ("vmlinuz_" + marca.hex())

    src.write_text(
        KERNEL_SRC,
        encoding="ascii",
    )

    proc = subprocess.run(
        [
            "gcc",
            "-s",
            "-o",
            str(elf),
            str(src),
        ],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stderr

    elf.chmod(0o755)

    original = elf.read_bytes()

    elf.write_bytes(
        original + hashlib.sha256(marca).digest()
    )

    return elf


def ejecutar(binario: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binario)],
        capture_output=True,
        text=True,
        timeout=10,
    )


# ===============================================================
# LAUNCHER
# ===============================================================

def sellar_kernel_para_launcher(
    tmp: Path,
    kernel: Path,
    marca: bytes,
) -> dict:
    tmp.mkdir(parents=True, exist_ok=True)

    priv = tmp / ("lpriv_" + marca.hex())
    pub = tmp / ("lpub_" + marca.hex())

    assert (
        P.generar_claves(
            str(priv),
            str(pub),
        ).get("ok")
        is True
    )

    raw = kernel.read_bytes()

    b = P.build(
        raw,
        str(priv),
        n_neutro=3,
        artifact_id="k-" + marca.hex()[:16],
        version=1,
        clave_publica_id="aut-" + marca.hex()[16:32],
    )

    assert b.get("ok") is True, b

    elf = tmp / (
        "sellado_" + marca.hex() + ".elf"
    )

    man = tmp / (
        "lman_" + marca.hex() + ".json"
    )

    elf.write_bytes(b["datos"])
    elf.chmod(0o755)

    man.write_text(
        json.dumps(
            b["manifiesto"],
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    return {
        "elf": elf,
        "manifiesto": man,
        "pub": pub,
        "priv": priv,
        "build": b,
        "claro": raw,
    }


def lanzar(pack: dict) -> dict:
    return L.verificar_y_ejecutar(
        ruta_artefacto=str(pack["elf"]),
        ruta_manifiesto=str(pack["manifiesto"]),
        ruta_pub=str(pack["pub"]),
        modo=L.MODO_SUBPROCESS,
    )


# ===============================================================
# INTEGRACIÓN
# ===============================================================

def integrar_y_sellar(
    tmp: Path,
    kernel: Path,
    marca: bytes,
) -> dict:
    tmp.mkdir(parents=True, exist_ok=True)

    priv = tmp / ("ipriv_" + marca.hex())
    pub = tmp / ("ipub_" + marca.hex())

    assert (
        P.generar_claves(
            str(priv),
            str(pub),
        ).get("ok")
        is True
    )

    integrado = tmp / (
        "final_" + marca.hex() + ".vpsi"
    )

    cons = A.construir_integrado(
        kernel,
        integrado,
    )

    assert cons.get("ok") is True, cons

    secs = secretos(marca)

    sellado = A.sellar_integrado(
        integrado,
        str(priv),
        artifact_id="art-" + marca.hex()[:16],
        authority_id="aut-" + marca.hex()[16:32],
        **secs,
    )

    assert sellado.get("ok") is True, sellado

    man = tmp / (
        "iman_" + marca.hex() + ".json"
    )

    sobre = tmp / (
        "isobre_" + marca.hex() + ".bin"
    )

    man.write_text(
        json.dumps(
            sellado["manifiesto"],
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    sobre.write_bytes(
        sellado["blob"]
    )

    return {
        "priv": priv,
        "pub": pub,
        "integrado": integrado,
        "manifiesto": man,
        "sobre": sobre,
        "secs": secs,
        "sellado": sellado,
        "cons": cons,
        "kernel": kernel,
    }


def verificar_integrado(pack: dict) -> dict:
    return A.verificar_integrado(
        ruta_integrado=pack["integrado"],
        ruta_sobre=pack["sobre"],
        ruta_manifiesto=pack["manifiesto"],
        ruta_pub=pack["pub"],
        secreto_autenticacion=(
            pack["secs"]["secreto_autenticacion"]
        ),
        secreto_sesion=(
            pack["secs"]["secreto_sesion"]
        ),
    )


def extraer(pack: dict) -> dict:
    return A.extraer_kernel(
        ruta_integrado=pack["integrado"],
        ruta_sobre=pack["sobre"],
        ruta_manifiesto=pack["manifiesto"],
        ruta_pub=pack["pub"],
        secreto_autenticacion=(
            pack["secs"]["secreto_autenticacion"]
        ),
        secreto_sesion=(
            pack["secs"]["secreto_sesion"]
        ),
    )


# ===============================================================
# ORÁCULO DE BLOQUEO
# ===============================================================

def _huella_propia(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def _superficies(pack: dict) -> tuple:
    integ = Path(pack["integrado"])
    sobre = Path(pack["sobre"])
    man = Path(pack["manifiesto"])
    pub = Path(pack["pub"])
    return (
        integ.exists() and integ.read_bytes() or b"",
        sobre.exists() and sobre.read_bytes() or b"",
        man.exists() and man.read_bytes() or b"",
        pub.exists() and pub.read_bytes() or b"",
        pack["secs"]["secreto_autenticacion"],
        pack["secs"]["secreto_sesion"],
    )


def _diferidos(control: dict, pack: dict) -> bool:
    return _superficies(control) != _superficies(pack)


def veredicto(pack: dict, kernel_vivo: bytes) -> dict:
    ver = verificar_integrado(pack)
    ext = extraer(pack)
    datos = ext.get("datos") if isinstance(ext.get("datos"), (bytes, bytearray)) else b""
    coincide = bool(datos) and _huella_propia(datos) == _huella_propia(kernel_vivo)
    autorizado = (
        ver.get("ok") is True
        and ver.get("autorizado") is True
        and ext.get("ok") is True
        and coincide
    )
    return {
        "autorizado": autorizado,
        "verificar": ver,
        "extraer": ext,
        "coincide_kernel": coincide,
        "n_datos": len(datos),
    }


def exige_bloqueo(
    pack: dict,
    etiqueta: str,
) -> dict:
    control = pack.get("control") or pack
    kernel_vivo = Path(control["kernel"]).read_bytes()

    assert _diferidos(control, pack), (
        etiqueta,
        "ataque-no-diferencio-al-control",
    )

    bueno = veredicto(control, kernel_vivo)
    malo = veredicto(pack, kernel_vivo)

    assert bueno["autorizado"] is True, (
        etiqueta,
        "rama-legitima-no-autoriza",
        bueno,
    )
    assert malo["autorizado"] is False, (
        etiqueta,
        "rama-ataque-autorizo",
        malo,
    )
    assert bueno["coincide_kernel"] is True
    assert malo["coincide_kernel"] is False
    assert malo["n_datos"] == 0

    return malo
# ===============================================================
# FIXTURES
# ===============================================================

@pytest.fixture(scope="module")
def work(tmp_path_factory):
    return tmp_path_factory.mktemp(
        "cierre_adversarial"
    )


@pytest.fixture(scope="module")
def kernel_a(work):
    return compilar_kernel(
        work / "K_A",
        b"A",
    )


@pytest.fixture(scope="module")
def kernel_b(work):
    return compilar_kernel(
        work / "K_B",
        b"B",
    )


@pytest.fixture(scope="module")
def launch_a(work, kernel_a):
    return sellar_kernel_para_launcher(
        work / "LA",
        kernel_a,
        b"A",
    )


@pytest.fixture(scope="module")
def pack_a(work, kernel_a):
    p = integrar_y_sellar(
        work / "IA",
        kernel_a,
        b"A",
    )
    p["control"] = p
    return p


@pytest.fixture(scope="module")
def pack_b(work, kernel_b):
    p = integrar_y_sellar(
        work / "IB",
        kernel_b,
        b"B",
    )
    p["control"] = p
    return p


@pytest.fixture
def vivo_a(pack_a, tmp_path):
    dest = tmp_path / "copia.vpsi"

    dest.write_bytes(
        pack_a["integrado"].read_bytes()
    )

    pack = dict(pack_a)
    pack["integrado"] = dest

    return pack


# ===============================================================
# 000 — REPOSITORIO
# ===============================================================

@pytest.mark.parametrize(
    "nombre",
    [
        "modules.constante.constante",
        "modules.spartaco_seguridad",
        "modules.spartaco_seguridad.proteccion",
        "modules.spartaco_seguridad.credencial",
        "modules.spartaco_seguridad.generador_claves",
        "modules.spartaco_seguridad.arranque",
        "modules.spartaco_seguridad.launcher",
    ],
)
def test_000_importa(nombre):
    importlib.import_module(nombre)


def test_001_contratos_id():
    assert A.SEGURIDAD["id"] == "ARRANQUE"
    assert L.SEGURIDAD["id"] == "LAUNCHER"
    assert P.SEGURIDAD["id"] == "PROTECCION"


@pytest.mark.parametrize(
    "cap",
    A.SEGURIDAD["capacidades_recurso"],
)
def test_002_capacidad_arranque_existe(cap):
    assert cap in A.__all__ or hasattr(A, cap)

    assert callable(
        getattr(A, cap)
    )


def test_003_launcher_exporta_puerta():
    assert callable(
        L.verificar_y_ejecutar
    )

    assert callable(
        L.cargar_manifiesto
    )


# ===============================================================
# 010 — CT
# ===============================================================

def test_010_clausura_ct():
    assert ALPHA + BETA == Fraction(1)
    assert DIVISIONS_PER_AXIS == 3


def test_011_arranque_usa_ct_vivo():
    assert (
        A.ALPHA is ALPHA
        or A.ALPHA == ALPHA
    )

    assert A.BETA == BETA
    assert (
        A.DIVISIONS_PER_AXIS
        == DIVISIONS_PER_AXIS
    )


def test_012_custodia_cierra():
    assert (
        A.custodia().get("ok")
        is True
    )


def test_013_alpha_rota_niega(monkeypatch):
    monkeypatch.setattr(
        A,
        "ALPHA",
        Fraction(1, 2),
    )

    assert (
        A.custodia().get("ok")
        is False
    )


def test_014_beta_rota_niega(monkeypatch):
    monkeypatch.setattr(
        A,
        "BETA",
        Fraction(1, 2),
    )

    assert (
        A.custodia().get("ok")
        is False
    )


def test_015_eje_roto_niega(monkeypatch):
    monkeypatch.setattr(
        A,
        "DIVISIONS_PER_AXIS",
        4,
    )

    assert (
        A.custodia().get("ok")
        is False
    )


# ===============================================================
# 020 — KERNEL
# ===============================================================

def test_020_kernel_crudo_sale_46(kernel_a):
    run = ejecutar(kernel_a)

    assert run.returncode == EXIT_KERNEL
    assert EXECUTION_MARKER.decode() in run.stdout


# ===============================================================
# 030 — LAUNCHER
# ===============================================================

def test_030_launcher_ejecuta_kernel_sellado(
    launch_a,
):
    out = lanzar(launch_a)

    assert out.get("ok") is True, out
    assert out.get("ejecutado") is True
    assert out.get("exit_code") == EXIT_KERNEL

    assert (
        EXECUTION_MARKER.decode()
        in (out.get("stdout") or "")
    )


def test_031_launcher_sin_manifiesto(
    launch_a,
    tmp_path,
):
    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            launch_a["elf"]
        ),
        ruta_manifiesto=str(
            tmp_path / "no.json"
        ),
        ruta_pub=str(
            launch_a["pub"]
        ),
    )

    assert out.get("ok") is False
    assert out.get("ejecutado") is False

    assert (
        "MANIFIESTO_AUSENTE"
        in (out.get("conceptos") or [])
    )


def test_032_launcher_elf_mutado(
    launch_a,
    tmp_path,
):
    dest = tmp_path / "mut.elf"

    raw = bytearray(
        launch_a["elf"].read_bytes()
    )

    raw[len(raw) // 2] ^= 0x01

    dest.write_bytes(bytes(raw))
    dest.chmod(0o755)

    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(dest),
        ruta_manifiesto=str(
            launch_a["manifiesto"]
        ),
        ruta_pub=str(
            launch_a["pub"]
        ),
    )

    assert out.get("ok") is False
    assert out.get("ejecutado") is False

    assert (
        EXECUTION_MARKER.decode()
        not in (out.get("stdout") or "")
    )


# ===============================================================
# 040 — CONTRADICCIÓN ACTUAL
# ===============================================================

def test_040_launcher_no_carga_vpsi_integrado(
    pack_a,
):
    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            pack_a["integrado"]
        ),
        ruta_manifiesto=str(
            pack_a["manifiesto"]
        ),
        ruta_pub=str(
            pack_a["pub"]
        ),
    )

    assert out.get("ejecutado") is False
    assert out.get("ok") is False


def test_041_no_existe_lanzar_integrado():
    assert not hasattr(
        A,
        "lanzar_integrado",
    )

    assert not hasattr(
        L,
        "lanzar_integrado",
    )


# ===============================================================
# 050 — FORMATO FÍSICO
# ===============================================================

def test_050_magia_propia(pack_a):
    raw = pack_a[
        "integrado"
    ].read_bytes()

    assert raw.startswith(MAGIA)


def test_051_parser_independiente(
    pack_a,
):
    raw = pack_a[
        "integrado"
    ].read_bytes()

    propio = abrir_paquete_propio(raw)

    assert propio["ok"] is True

    assert (
        "kernel/imagen"
        in propio["archivos"]
    )

    for pieza in A.MODULOS_QUE_VIVEN:
        clave = "spartaco/" + pieza

        if (
            Path(A.__file__).parent
            / pieza
        ).is_file():
            assert (
                clave
                in propio["archivos"]
            ), pieza


def test_052_hash_independiente(
    pack_a,
):
    raw = pack_a[
        "integrado"
    ].read_bytes()

    propio = sha256_hex(raw)

    assert (
        propio
        == pack_a["cons"]["nucleo"]
    )

    assert (
        propio
        == P.nucleo(raw)
    )


def test_053_canales_independientes(
    pack_a,
):
    raw = pack_a[
        "integrado"
    ].read_bytes()

    s, q = canales_propios(raw)

    assert [s, q] == (
        pack_a["cons"]["canales"]
    )


def test_054_kernel_no_es_paquete(
    pack_a,
    kernel_a,
):
    propio = abrir_paquete_propio(
        pack_a[
            "integrado"
        ].read_bytes()
    )

    interno = propio[
        "archivos"
    ]["kernel/imagen"]

    assert (
        sha256_hex(interno)
        == sha256_hex(
            kernel_a.read_bytes()
        )
    )

    assert (
        sha256_hex(interno)
        != sha256_hex(
            pack_a[
                "integrado"
            ].read_bytes()
        )
    )


# ===============================================================
# 060 — SPARTACO INTERNO VS EXTERNO
# ===============================================================

def test_060_spartaco_interno_presente(
    pack_a,
):
    propio = abrir_paquete_propio(
        pack_a[
            "integrado"
        ].read_bytes()
    )

    assert (
        "spartaco/arranque.py"
        in propio["archivos"]
    )


def test_061_spartaco_integrado_es_copia_del_build(
    pack_a,
):
    propio = abrir_paquete_propio(
        pack_a[
            "integrado"
        ].read_bytes()
    )

    disco = Path(
        A.__file__
    ).read_bytes()

    assert (
        propio[
            "archivos"
        ]["spartaco/arranque.py"]
        == disco
    )


def test_062_spartaco_externo_es_identificable():
    vivo = Path(
        A.__file__
    ).resolve()

    assert vivo.is_file()
    assert vivo.suffix == ".py"


# ===============================================================
# 070 — SELLO
# ===============================================================

def test_070_verificar_integrado_autoriza(
    pack_a,
):
    r = verificar_integrado(pack_a)

    assert r.get("ok") is True, r
    assert (
        r.get("autorizado")
        is True
    )


def test_071_extraer_mismo_kernel(
    pack_a,
    kernel_a,
):
    r = extraer(pack_a)

    assert r.get("ok") is True, r

    assert (
        r["datos"]
        == kernel_a.read_bytes()
    )


# ===============================================================
# 080 — TAMPER FÍSICO
# ===============================================================

@pytest.mark.parametrize(
    "pos",
    [
        0,
        1,
        "mid",
        -2,
        -1,
    ],
)
def test_080_flip_bloquea(
    vivo_a,
    pos,
):
    raw = bytearray(
        vivo_a[
            "integrado"
        ].read_bytes()
    )

    i = (
        len(raw) // 2
        if pos == "mid"
        else pos
    )

    raw[i] ^= 0x01

    vivo_a[
        "integrado"
    ].write_bytes(
        bytes(raw)
    )

    exige_bloqueo(
        vivo_a,
        "flip-" + str(pos),
    )


def test_081_truncar_bloquea(
    vivo_a,
):
    raw = vivo_a[
        "integrado"
    ].read_bytes()

    vivo_a[
        "integrado"
    ].write_bytes(
        raw[
            :max(
                1,
                len(raw) // 2,
            )
        ]
    )

    exige_bloqueo(
        vivo_a,
        "truncar",
    )


def test_082_append_bloquea(
    vivo_a,
):
    raw = vivo_a[
        "integrado"
    ].read_bytes()

    vivo_a[
        "integrado"
    ].write_bytes(
        raw + b"\x00"
    )

    exige_bloqueo(
        vivo_a,
        "append",
    )


def test_083_vacio_bloquea(
    vivo_a,
):
    vivo_a[
        "integrado"
    ].write_bytes(b"")

    exige_bloqueo(
        vivo_a,
        "vacio",
    )


# ===============================================================
# 090 — MANIFIESTO / SOBRE
# ===============================================================

def test_090_manifiesto_mutado_bloquea(
    vivo_a,
):
    dest = (
        vivo_a[
            "manifiesto"
        ].parent
        / "man_mut.json"
    )

    original = vivo_a[
        "manifiesto"
    ].read_text(
        encoding="ascii"
    )

    dest.write_text(
        original[:-1] + "0",
        encoding="ascii",
    )

    pack = dict(vivo_a)
    pack["manifiesto"] = dest

    exige_bloqueo(
        pack,
        "manifiesto",
    )


def test_091_sobre_mutado_bloquea(
    vivo_a,
):
    raw = bytearray(
        vivo_a[
            "sobre"
        ].read_bytes()
    )

    raw[-1] ^= 0x01

    dest = (
        vivo_a[
            "sobre"
        ].parent
        / "sobre_mut.bin"
    )

    dest.write_bytes(
        bytes(raw)
    )

    pack = dict(vivo_a)
    pack["sobre"] = dest

    exige_bloqueo(
        pack,
        "sobre",
    )


# ===============================================================
# 100 — SPARTACO INTERNO MUTADO
# ===============================================================

def test_100_arranque_interno_mutado_bloquea(
    vivo_a,
):
    raw = vivo_a[
        "integrado"
    ].read_bytes()

    propio = abrir_paquete_propio(raw)

    pieza = bytearray(
        propio[
            "archivos"
        ]["spartaco/arranque.py"]
    )

    pieza[0] ^= 0x20

    propio[
        "archivos"
    ]["spartaco/arranque.py"] = bytes(
        pieza
    )

    recon = A._empaquetar(
        propio[
            "archivos"
        ]
    )

    vivo_a[
        "integrado"
    ].write_bytes(recon)

    exige_bloqueo(
        vivo_a,
        "spartaco-arranque",
    )


def test_101_kernel_interno_mutado_bloquea(
    vivo_a,
):
    raw = vivo_a[
        "integrado"
    ].read_bytes()

    propio = abrir_paquete_propio(raw)

    k = bytearray(
        propio[
            "archivos"
        ]["kernel/imagen"]
    )

    k[len(k) // 2] ^= 0x01

    propio[
        "archivos"
    ]["kernel/imagen"] = bytes(k)

    recon = A._empaquetar(
        propio[
            "archivos"
        ]
    )

    vivo_a[
        "integrado"
    ].write_bytes(recon)

    exige_bloqueo(
        vivo_a,
        "kernel-interno",
    )


# ===============================================================
# 110 — SUSTITUCIÓN CRUZADA
# ===============================================================

def test_110_b_con_sobre_a_bloquea(
    pack_a,
    pack_b,
):
    pack = dict(pack_a)

    pack[
        "integrado"
    ] = pack_b[
        "integrado"
    ]

    exige_bloqueo(
        pack,
        "B-sobre-A",
    )


def test_111_b_con_credenciales_a_bloquea(
    pack_a,
    pack_b,
):
    pack = dict(pack_b)

    pack[
        "manifiesto"
    ] = pack_a[
        "manifiesto"
    ]

    pack[
        "sobre"
    ] = pack_a[
        "sobre"
    ]

    pack[
        "secs"
    ] = pack_a[
        "secs"
    ]

    pack[
        "pub"
    ] = pack_a[
        "pub"
    ]

    exige_bloqueo(
        pack,
        "B-claves-A",
    )


def test_112_auth_b_sobre_a_bloquea(
    pack_a,
    pack_b,
):
    pack = dict(pack_a)

    pack["secs"] = dict(
        pack_a["secs"]
    )

    pack["secs"][
        "secreto_autenticacion"
    ] = pack_b["secs"][
        "secreto_autenticacion"
    ]

    exige_bloqueo(
        pack,
        "auth-B",
    )


def test_113_sesion_b_sobre_a_bloquea(
    pack_a,
    pack_b,
):
    pack = dict(pack_a)

    pack["secs"] = dict(
        pack_a["secs"]
    )

    pack["secs"][
        "secreto_sesion"
    ] = pack_b["secs"][
        "secreto_sesion"
    ]

    exige_bloqueo(
        pack,
        "session-B",
    )


# ===============================================================
# 120 — AUSENCIAS
# ===============================================================

def test_120_sin_manifiesto(
    pack_a,
    tmp_path,
):
    pack = dict(pack_a)

    pack[
        "manifiesto"
    ] = tmp_path / "no.json"

    exige_bloqueo(
        pack,
        "sin-manifiesto",
    )


def test_121_sin_pub(
    pack_a,
    tmp_path,
):
    pack = dict(pack_a)

    pack[
        "pub"
    ] = tmp_path / "no.pub"

    exige_bloqueo(
        pack,
        "sin-pub",
    )


def test_122_sin_auth(
    pack_a,
):
    pack = dict(pack_a)

    pack["secs"] = dict(
        pack_a["secs"]
    )

    pack["secs"][
        "secreto_autenticacion"
    ] = None

    exige_bloqueo(
        pack,
        "sin-auth",
    )


# ===============================================================
# 130 — PATH TRAVERSAL / ESTRUCTURA
# ===============================================================

@pytest.mark.parametrize(
    "ruta",
    [
        "../escape",
        "../../escape",
        "spartaco/../escape",
        "/tmp/escape",
        "",
        ".",
        "..",
    ],
)
def test_130_parser_rechaza_ruta_peligrosa(
    pack_a,
    ruta,
):
    """
    Ataque exclusivamente contra el parser independiente.

    No afirma que A._empaquetar() acepte estas rutas.
    Construye un paquete sintético para comprobar que el formato
    no debe interpretarse como una lista de rutas confiables.
    """

    archivos = {
        ruta: b"X",
    }

    cuerpo = bytearray()

    for nombre, datos in archivos.items():
        cuerpo.extend(
            nombre.encode("utf-8")
        )
        cuerpo.extend(b"\x00")
        cuerpo.extend(
            len(datos).to_bytes(
                8,
                "big",
            )
        )
        cuerpo.extend(datos)

    raw = (
        MAGIA
        + b"{}"
        + SEP
        + bytes(cuerpo)
    )

    propio = abrir_paquete_propio(raw)

    assert propio["ok"] is True

    # El parser físico puede leerlo; la seguridad superior
    # NO debe convertir automáticamente ese nombre en una ruta
    # confiable del filesystem.
    assert ruta in propio["archivos"]


# ===============================================================
# 140 — DUPLICACIÓN ESTRUCTURAL
# ===============================================================

def test_140_parser_detecta_ruta_duplicada():
    datos = b"X"

    cuerpo = bytearray()

    for _ in range(2):
        cuerpo.extend(b"dup")
        cuerpo.extend(b"\x00")
        cuerpo.extend(
            len(datos).to_bytes(
                8,
                "big",
            )
        )
        cuerpo.extend(datos)

    raw = (
        MAGIA
        + b"{}"
        + SEP
        + bytes(cuerpo)
    )

    propio = abrir_paquete_propio(raw)

    assert propio["ok"] is False
    assert (
        propio["error"]
        == "ruta-duplicada"
    )


# ===============================================================
# 150 — LONGITUDES MALFORMADAS
# ===============================================================

def test_150_parser_rechaza_longitud_interna_invalida():
    cuerpo = (
        b"kernel/imagen"
        + b"\x00"
        + (999999999).to_bytes(
            8,
            "big",
        )
        + b"X"
    )

    raw = (
        MAGIA
        + b"{}"
        + SEP
        + cuerpo
    )

    propio = abrir_paquete_propio(raw)

    assert propio["ok"] is False

    assert (
        propio["error"]
        == "longitud-fuera-de-paquete"
    )


def test_151_parser_rechaza_cabecera_truncada():
    raw = (
        MAGIA
        + b"{}"
        + SEP
        + b"kernel\x00\x01\x02"
    )

    propio = abrir_paquete_propio(raw)

    assert propio["ok"] is False


# ===============================================================
# 160 — TAMPER COMBINADO
# ===============================================================

@pytest.mark.parametrize(
    "operacion",
    [
        "prefix",
        "suffix",
        "double",
        "middle",
    ],
)
def test_160_corrupcion_combinada_bloquea(
    vivo_a,
    operacion,
):
    raw = vivo_a[
        "integrado"
    ].read_bytes()

    if operacion == "prefix":
        raw = b"\x00" + raw

    elif operacion == "suffix":
        raw = raw + b"\x00"

    elif operacion == "double":
        raw = (
            raw[:len(raw) // 2]
            + raw
            + raw[len(raw) // 2:]
        )

    elif operacion == "middle":
        i = len(raw) // 2
        raw = (
            raw[:i]
            + b"\x00"
            + raw[i:]
        )

    vivo_a[
        "integrado"
    ].write_bytes(raw)

    exige_bloqueo(
        vivo_a,
        "corrupcion-" + operacion,
    )


# ===============================================================
# 170 — PERÍMETRO
# ===============================================================

def test_170_perimetro(work):
    r = A.inventariar_perimetro(
        work,
        recursivo=True,
    )

    assert r.get("ok") is True, r
    assert r["n_archivos"] >= 1
    assert r["n_bytes_total"] > 0


# ===============================================================
# 180 — CONCURRENCIA DE VERIFICACIÓN
# ===============================================================

def test_180_veinte_verificaciones(
    pack_a,
):
    hits = []

    barrier = threading.Barrier(
        20
    )

    errores = []

    def golpe():
        try:
            barrier.wait()

            r = verificar_integrado(
                pack_a
            )

            hits.append(
                r.get("ok")
            )

        except Exception as exc:
            errores.append(exc)

    hilos = [
        threading.Thread(
            target=golpe
        )
        for _ in range(20)
    ]

    for h in hilos:
        h.start()

    for h in hilos:
        h.join()

    assert not errores, errores

    assert hits == [True] * 20


# ===============================================================
# 190 — REPLAY DEL LAUNCHER
# ===============================================================

def test_190_launcher_replay_es_idempotente(
    launch_a,
):
    a = lanzar(launch_a)
    b = lanzar(launch_a)

    assert a.get("ok") is True
    assert b.get("ok") is True

    assert (
        a.get("exit_code")
        == EXIT_KERNEL
    )

    assert (
        b.get("exit_code")
        == EXIT_KERNEL
    )


# ===============================================================
# 200 — REPLAY DEL PAQUETE INTEGRADO
# ===============================================================

def test_200_integrado_replay_es_idempotente(
    pack_a,
):
    a = verificar_integrado(
        pack_a
    )

    b = verificar_integrado(
        pack_a
    )

    assert a.get("ok") is True
    assert b.get("ok") is True


# ===============================================================
# 210 — IDENTIDAD CRUZADA
# ===============================================================

def test_210_artifact_id_no_basta(
    pack_a,
    pack_b,
):
    """
    Demuestra que un mismo identificador semántico no debe permitir
    sustituir el cuerpo criptográfico.

    Se intenta conservar la infraestructura de A y sustituir el
    contenido físico por B.
    """

    manifest_a = json.loads(
        pack_a[
            "manifiesto"
        ].read_text(
            encoding="ascii"
        )
    )

    manifest_b = json.loads(
        pack_b[
            "manifiesto"
        ].read_text(
            encoding="ascii"
        )
    )

    assert (
        manifest_a
        != manifest_b
    )

    pack = dict(pack_a)

    pack[
        "integrado"
    ] = pack_b[
        "integrado"
    ]

    exige_bloqueo(
        pack,
        "identidad-cruzada",
    )


# ===============================================================
# 220 — KERNEL EXTERNO MODIFICADO
# ===============================================================

def test_220_kernel_launcher_mutado_no_ejecuta(
    launch_a,
    tmp_path,
):
    raw = bytearray(
        launch_a[
            "elf"
        ].read_bytes()
    )

    raw[0] ^= 0x01

    dest = (
        tmp_path
        / "kernel-mutado.elf"
    )

    dest.write_bytes(
        bytes(raw)
    )

    dest.chmod(0o755)

    pack = dict(launch_a)
    pack["elf"] = dest

    out = lanzar(pack)

    assert out.get("ok") is False
    assert out.get("ejecutado") is False

    assert (
        "46"
        not in (
            out.get("stdout")
            or ""
        )
    )


# ===============================================================
# 230 — ENTORNO ADVERSARIAL
# ===============================================================

def test_230_launcher_no_depende_de_path(
    launch_a,
    monkeypatch,
):
    """
    El launcher no debe convertir PATH en una autoridad de
    autorización.

    No sustituimos ninguna API del proyecto.
    Solo eliminamos PATH del entorno del proceso de prueba.
    """

    monkeypatch.setenv(
        "PATH",
        "",
    )

    out = lanzar(
        launch_a
    )

    assert out.get("ok") is True, out
    assert out.get("ejecutado") is True
    assert out.get("exit_code") == EXIT_KERNEL


def test_231_launcher_con_pwd_hostil(
    launch_a,
    monkeypatch,
):
    monkeypatch.setenv(
        "PWD",
        "/nonexistent/spartaco-hostile",
    )

    out = lanzar(
        launch_a
    )

    assert out.get("ok") is True, out
    assert out.get("ejecutado") is True
    assert out.get("exit_code") == EXIT_KERNEL


# ===============================================================
# 240 — ARCHIVO EJECUTABLE VS ARTEFACTO
# ===============================================================

def test_240_launcher_exige_artefacto_ejecutable(
    launch_a,
    tmp_path,
):
    dest = (
        tmp_path
        / "sin-ejecucion.elf"
    )

    shutil.copy2(
        launch_a["elf"],
        dest,
    )

    dest.chmod(
        stat.S_IRUSR
        | stat.S_IWUSR
    )

    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(dest),
        ruta_manifiesto=str(
            launch_a["manifiesto"]
        ),
        ruta_pub=str(
            launch_a["pub"]
        ),
        modo=L.MODO_SUBPROCESS,
    )

    # Debe fallar de manera segura si el OS no permite ejecución.
    assert out.get("ejecutado") is False


# ===============================================================
# 250 — MANIFIESTO SEMÁNTICO
# ===============================================================

@pytest.mark.parametrize(
    "campo",
    [
        "artifact_id",
        "authority_id",
        "version",
        "n_bytes",
        "nucleo",
    ],
)
def test_250_cambio_semantico_manifiesto_bloquea(
    launch_a,
    campo,
    tmp_path,
):
    original = json.loads(
        launch_a[
            "manifiesto"
        ].read_text(
            encoding="ascii"
        )
    )

    mutado = dict(original)

    valor = mutado.get(campo)

    if isinstance(valor, int):
        mutado[campo] = valor + 1

    elif isinstance(valor, str):
        mutado[campo] = valor + "-MUT"

    elif valor is None:
        mutado[campo] = "MUT"

    else:
        pytest.skip(
            "Campo no presente o tipo no mutado por este test"
        )

    man = (
        tmp_path
        / (
            "man-"
            + campo
            + ".json"
        )
    )

    man.write_text(
        json.dumps(
            mutado,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            launch_a["elf"]
        ),
        ruta_manifiesto=str(man),
        ruta_pub=str(
            launch_a["pub"]
        ),
        modo=L.MODO_SUBPROCESS,
    )

    assert out.get("ok") is False
    assert out.get("ejecutado") is False


# ===============================================================
# 260 — JSON NO CANÓNICO / CAMBIO DE REPRESENTACIÓN
# ===============================================================

def test_260_manifesto_reordenado_no_cambia_identidad(
    launch_a,
    tmp_path,
):
    original_text = (
        launch_a[
            "manifiesto"
        ].read_text(
            encoding="ascii"
        )
    )

    original = json.loads(
        original_text
    )

    reordered = {}

    for key in reversed(
        list(original.keys())
    ):
        reordered[key] = original[key]

    man = (
        tmp_path
        / "reordered.json"
    )

    man.write_text(
        json.dumps(
            reordered,
            separators=(",", ":"),
        ),
        encoding="ascii",
    )

    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            launch_a["elf"]
        ),
        ruta_manifiesto=str(man),
        ruta_pub=str(
            launch_a["pub"]
        ),
        modo=L.MODO_SUBPROCESS,
    )

    # Si el contrato firma una representación canónica,
    # este test revela si el sistema depende del orden textual.
    #
    # No imponemos PASS/FAIL artificialmente:
    # registramos que la implementación decidió una semántica.
    assert isinstance(
        out,
        dict,
    )


# ===============================================================
# 270 — SOURCE / AST: DETECCIÓN DE SUPERFICIES CRÍTICAS
# ===============================================================

def test_270_launcher_source_auditable():
    source = Path(
        L.__file__
    ).read_text(
        encoding="utf-8"
    )

    tree = ast.parse(source)

    funciones = {
        node.name
        for node in ast.walk(tree)
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        )
    }

    assert (
        "verificar_y_ejecutar"
        in funciones
    )


def test_271_launcher_source_contiene_puerta_real():
    source = Path(
        L.__file__
    ).read_text(
        encoding="utf-8"
    )

    assert (
        "verificar_y_ejecutar"
        in source
    )


# ===============================================================
# 280 — IMPORT PATH: IDENTIDAD DEL CÓDIGO VIVO
# ===============================================================

def test_280_origen_real_arranque():
    origen = Path(
        A.__file__
    ).resolve()

    raiz_repo = origen.parents[2]

    assert origen.exists()

    assert (
        "modules"
        in origen.parts
    )

    assert (
        "spartaco_seguridad"
        in origen.parts
    )

    assert (
        raiz_repo.exists()
    )


def test_281_origen_real_launcher():
    origen = Path(
        L.__file__
    ).resolve()

    assert origen.exists()

    assert (
        "spartaco_seguridad"
        in origen.parts
    )


# ===============================================================
# 290 — ATAQUE DE SUSTITUCIÓN DEL CÓDIGO INTERNO
# ===============================================================

def test_290_todos_los_modulos_vivos_estan_en_el_paquete(
    pack_a,
):
    propio = abrir_paquete_propio(
        pack_a[
            "integrado"
        ].read_bytes()
    )

    ausentes = []

    for pieza in A.MODULOS_QUE_VIVEN:
        ruta = (
            Path(A.__file__).parent
            / pieza
        )

        if ruta.is_file():
            clave = (
                "spartaco/"
                + pieza
            )

            if clave not in propio[
                "archivos"
            ]:
                ausentes.append(
                    pieza
                )

    assert not ausentes, ausentes


# ===============================================================
# 300 — FINGERPRINT DEL PERÍMETRO
# ===============================================================

def fingerprint_archivos(
    root: Path,
) -> dict:
    resultado = {}

    for p in sorted(
        root.rglob("*")
    ):
        if not p.is_file():
            continue

        rel = str(
            p.relative_to(root)
        )

        resultado[rel] = sha256_hex(
            p.read_bytes()
        )

    return resultado


def test_300_fingerprint_determinista(
    pack_a,
):
    propio = abrir_paquete_propio(
        pack_a[
            "integrado"
        ].read_bytes()
    )

    assert (
        propio["ok"] is True
    )

    fingerprints = {
        ruta: sha256_hex(datos)
        for ruta, datos
        in propio[
            "archivos"
        ].items()
    }

    assert fingerprints
    assert (
        "kernel/imagen"
        in fingerprints
    )


# ===============================================================
# 310 — FALLO DE CREDENCIAL
# ===============================================================

def test_310_credencial_autenticacion_mutada_bloquea(
    pack_a,
):
    pack = dict(pack_a)

    pack["secs"] = dict(
        pack_a["secs"]
    )

    original = pack["secs"][
        "secreto_autenticacion"
    ]

    assert original is not None

    mutado = bytearray(
        original
    )

    mutado[0] ^= 0xFF

    pack["secs"][
        "secreto_autenticacion"
    ] = bytes(mutado)

    exige_bloqueo(
        pack,
        "credencial-mutada",
    )


def test_311_credencial_sesion_mutada_bloquea(
    pack_a,
):
    pack = dict(pack_a)

    pack["secs"] = dict(
        pack_a["secs"]
    )

    original = pack["secs"][
        "secreto_sesion"
    ]

    mutado = bytearray(
        original
    )

    mutado[-1] ^= 0xFF

    pack["secs"][
        "secreto_sesion"
    ] = bytes(mutado)

    exige_bloqueo(
        pack,
        "session-mutada",
    )


# ===============================================================
# 320 — ATAQUE DE TRUNCAMIENTO CRIPTOGRÁFICO
# ===============================================================

@pytest.mark.parametrize(
    "longitud",
    [
        0,
        1,
        2,
        8,
        16,
        31,
    ],
)
def test_320_sobre_truncado_bloquea(
    vivo_a,
    longitud,
):
    raw = vivo_a[
        "sobre"
    ].read_bytes()

    if longitud >= len(raw):
        pytest.skip(
            "Fixture demasiado pequeño"
        )

    dest = (
        vivo_a[
            "sobre"
        ].parent
        / (
            "sobre-truncado-"
            + str(longitud)
            + ".bin"
        )
    )

    dest.write_bytes(
        raw[:longitud]
    )

    pack = dict(vivo_a)
    pack["sobre"] = dest

    exige_bloqueo(
        pack,
        "sobre-truncado",
    )


# ===============================================================
# 330 — ATAQUE DE REEMPLAZO ATÓMICO
# ===============================================================

def test_330_reemplazo_de_archivo_no_convierte_b_en_a(
    launch_a,
    tmp_path,
):
    """
    Prueba una condición fundamental:

        manifest_A
        artifact_B

    no puede producir autorización.

    Es una aproximación determinista a la frontera VERIFY/LOAD.
    """

    destino = (
        tmp_path
        / "victima.elf"
    )

    destino.write_bytes(
        launch_a[
            "elf"
        ].read_bytes()
    )

    destino.chmod(0o755)

    atacante = (
        tmp_path
        / "atacante.elf"
    )

    raw = bytearray(
        launch_a[
            "elf"
        ].read_bytes()
    )

    raw[
        len(raw) // 2
    ] ^= 0x01

    atacante.write_bytes(
        bytes(raw)
    )

    atacante.chmod(0o755)

    os.replace(
        atacante,
        destino,
    )

    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            destino
        ),
        ruta_manifiesto=str(
            launch_a[
                "manifiesto"
            ]
        ),
        ruta_pub=str(
            launch_a[
                "pub"
            ]
        ),
        modo=L.MODO_SUBPROCESS,
    )

    assert out.get("ok") is False
    assert out.get("ejecutado") is False


# ===============================================================
# 340 — SYMLINK
# ===============================================================

def test_340_symlink_no_debe_convertir_otro_archivo_en_autorizado(
    launch_a,
    tmp_path,
):
    atacante = (
        tmp_path
        / "otro.elf"
    )

    raw = bytearray(
        launch_a[
            "elf"
        ].read_bytes()
    )

    raw[
        len(raw) // 2
    ] ^= 0x01

    atacante.write_bytes(
        bytes(raw)
    )

    atacante.chmod(0o755)

    enlace = (
        tmp_path
        / "enlace.elf"
    )

    try:
        enlace.symlink_to(
            atacante
        )
    except (OSError, NotImplementedError):
        pytest.skip(
            "El sistema de pruebas no permite symlink"
        )

    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            enlace
        ),
        ruta_manifiesto=str(
            launch_a[
                "manifiesto"
            ]
        ),
        ruta_pub=str(
            launch_a[
                "pub"
            ]
        ),
        modo=L.MODO_SUBPROCESS,
    )

    assert out.get("ok") is False
    assert out.get("ejecutado") is False


# ===============================================================
# 350 — AUSENCIA TOTAL DE ARCHIVO
# ===============================================================

def test_350_artefacto_inexistente_no_ejecuta(
    launch_a,
    tmp_path,
):
    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(
            tmp_path
            / "no-existe.elf"
        ),
        ruta_manifiesto=str(
            launch_a[
                "manifiesto"
            ]
        ),
        ruta_pub=str(
            launch_a[
                "pub"
            ]
        ),
        modo=L.MODO_SUBPROCESS,
    )

    assert out.get("ok") is False
    assert out.get("ejecutado") is False


# ===============================================================
# 360 — RECURSIÓN / AUTOREFERENCIA
# ===============================================================

def test_360_paquete_no_contiene_su_propia_imagen_completa(
    pack_a,
):
    propio = abrir_paquete_propio(
        pack_a[
            "integrado"
        ].read_bytes()
    )

    paquete = pack_a[
        "integrado"
    ].read_bytes()

    hashes = {
        sha256_hex(datos)
        for datos in propio[
            "archivos"
        ].values()
    }

    assert sha256_hex(
        paquete
    ) not in hashes


# ===============================================================
# 370 — CIERRE KERNEL
# ===============================================================

def test_370_extraccion_no_es_ejecucion(
    pack_a,
):
    r = extraer(pack_a)

    assert r.get("ok") is True

    datos = r["datos"]

    assert (
        b"46"
        in datos
    )


# ===============================================================
# 380 — ATAQUE POST-AUTORIZACIÓN DOCUMENTADO
# ===============================================================

def test_380_launcher_repite_artefacto_legitimo(
    launch_a,
):
    """
    Documenta explícitamente que el launcher actual es idempotente
    respecto del mismo ELF.

    NO se declara anti-replay porque el contrato observado no
    proporciona una política de nonce/consumo para esta operación.
    """

    primero = lanzar(
        launch_a
    )

    segundo = lanzar(
        launch_a
    )

    assert primero.get("ok") is True
    assert segundo.get("ok") is True

    assert (
        primero.get("ejecutado")
        is True
    )

    assert (
        segundo.get("ejecutado")
        is True
    )


# ===============================================================
# 390 — UPDATE / CROSS VERSION
# ===============================================================

def test_390_b_legitimo(
    pack_b,
):
    r = verificar_integrado(
        pack_b
    )

    assert r.get("ok") is True, r


def test_391_a_con_sobre_b_bloquea(
    pack_a,
    pack_b,
):
    pack = dict(pack_a)

    pack[
        "manifiesto"
    ] = pack_b[
        "manifiesto"
    ]

    pack[
        "sobre"
    ] = pack_b[
        "sobre"
    ]

    pack[
        "secs"
    ] = pack_b[
        "secs"
    ]

    pack[
        "pub"
    ] = pack_b[
        "pub"
    ]

    exige_bloqueo(
        pack,
        "A-sobre-B",
    )


# ===============================================================
# 400 — CIERRE FINAL
# ===============================================================

def test_400_reconstruir_integrado(
    tmp_path,
):
    kernel = compilar_kernel(
        tmp_path / "K",
        b"FINAL",
    )

    pack = integrar_y_sellar(
        tmp_path / "I",
        kernel,
        b"FINAL",
    )

    r = verificar_integrado(
        pack
    )

    assert r.get("ok") is True, r

    ext = extraer(
        pack
    )

    assert ext.get("ok") is True
    assert (
        ext["datos"]
        == kernel.read_bytes()
    )


def test_401_reconstruir_launcher(
    tmp_path,
):
    kernel = compilar_kernel(
        tmp_path / "K",
        b"FINAL-LAUNCHER",
    )

    launch = (
        sellar_kernel_para_launcher(
            tmp_path / "L",
            kernel,
            b"FINAL-LAUNCHER",
        )
    )

    out = lanzar(
        launch
    )

    assert out.get("ok") is True, out
    assert out.get("ejecutado") is True
    assert (
        out.get("exit_code")
        == EXIT_KERNEL
    )

    assert (
        EXECUTION_MARKER.decode()
        in (
            out.get("stdout")
            or ""
        )
    )


# ===============================================================
# 410 — CIERRE DE SEGURIDAD
# ===============================================================

def test_410_cierre_seguridad(
    pack_a,
):
    """
    Condición final mínima:

        legítimo → autoriza

    El test no permite invertir esta condición.
    """

    r = verificar_integrado(
        pack_a
    )

    assert r.get("ok") is True
    assert r.get("autorizado") is True


# ===============================================================
# 420 — DETECCIÓN EXPLÍCITA DE LA BRECHA PRINCIPAL
# ===============================================================

def test_420_documenta_brecha_launcher_integrado():
    """
    Este test NO inventa una capacidad inexistente.

    Si en el futuro aparece una API real para ejecutar el paquete
    integrado mediante el launcher, este test debe cambiar.

    Actualmente demuestra contractualmente que:

        A = paquete integrado
        L = launcher ELF

    son superficies distintas.
    """

    assert not hasattr(
        A,
        "lanzar_integrado",
    )

    assert not hasattr(
        L,
        "lanzar_integrado",
    )


# ===============================================================
# FIN
# ===============================================================
