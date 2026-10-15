# ===============================================================
# TEST ESPARTACO — HARNESS ADVERSARIAL MEDIBLE
# tests/test_espartaco_multi_atacante_montecarlo.py
# ===============================================================
# Una autoridad. Atacantes sin privada. RNG 100% determinista.
# NO_OP != BLOCKED. Sin break ante BREACH. Detector por claves.
# proteccion.py intacto.
# ===============================================================

from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import traceback
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import modules.spartaco_seguridad.proteccion as P


# ===============================================================
# PROCEDENCIA
# ===============================================================

SPEC_ID = "TEST-ESPARTACO-HARNESS-2.0"
SPEC_REVISION = "2026-08-11"
SPEC_HASH = hashlib.sha256(
    b"ESPARTACO|HARNESS-2|DETERMINISTA|NO-HEURISTICA|CLAVE-FALLOS"
).hexdigest()

MASTER_SEED = int(os.environ.get("ESPARTACO_SEED", "20260811"))
N_ATACANTES = int(os.environ.get("MULTI_ATTACK_N", "100000"))
MIN_POR_FRENTE = int(os.environ.get("ESPARTACO_MIN_FRENTE", "50"))

ESTACIONES = (
    "entrada_datos",
    "manifiesto_forma",
    "firma",
    "esquema_cuerpo",
    "nucleo",
    "canales",
    "n_bytes",
)
PROFUNDIDAD = {e: i + 1 for i, e in enumerate(ESTACIONES)}
PROFUNDIDAD["NINGUNA_BREACH"] = 8
PROFUNDIDAD["INDETERMINATE"] = 0

FALLO_DATOS = "datos"
FALLO_MANIFIESTO = "manifiesto"
CONCEPTO_MANIFIESTO_AUSENTE = "MANIFIESTO_AUSENTE"
CONCEPTO_FIRMA_INVALIDA = "FIRMA_INVÁLIDA"
CONCEPTO_CODIGO_INVALIDO = "CÓDIGO_INVÁLIDO"
CONCEPTO_VERSION_REGRESIVA = "VERSIÓN_REGRESIVA"
PASO_MANIFIESTO = "manifiesto"
PASO_NUCLEO = "nucleo"
PASO_CANALES = "canales"
PASO_N_BYTES = "n_bytes"

PESOS_FRENTE = {
    "entrada": 5,
    "forma": 10,
    "firma": 10,
    "esquema": 8,
    "cuerpo": 10,
    "datos": 14,
    "nucleo_campo": 6,
    "canales_campo": 6,
    "longitud": 6,
    "recomposicion": 8,
    "forja_cero": 8,
    "compuesto": 9,
}
FRENTES = list(PESOS_FRENTE.keys())


# ===============================================================
# ORÁCULO INDEPENDIENTE
# ===============================================================

def oracle_canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
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


# ===============================================================
# DETECTOR DETERMINISTA — claves fallos/conceptos/pasos.ok
# ===============================================================

def trayectoria_y_estacion(resultado: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    traj = {e: "SKIP" for e in ESTACIONES}

    if resultado.get("ok") is True:
        for e in ESTACIONES:
            traj[e] = "PASS"
        return "NINGUNA_BREACH", traj

    fallos = list(resultado.get("fallos") or [])
    conceptos = frozenset(resultado.get("conceptos") or [])
    pasos = resultado.get("pasos") or {}

    if FALLO_DATOS in fallos:
        traj["entrada_datos"] = "FAIL"
        return "entrada_datos", traj
    traj["entrada_datos"] = "PASS"

    man = pasos.get(PASO_MANIFIESTO)
    man_ok = isinstance(man, dict) and man.get("ok") is True
    man_fail = isinstance(man, dict) and man.get("ok") is False

    if man_fail or (FALLO_MANIFIESTO in fallos and not man_ok):
        if CONCEPTO_FIRMA_INVALIDA in conceptos:
            traj["manifiesto_forma"] = "PASS"
            traj["firma"] = "FAIL"
            return "firma", traj
        if CONCEPTO_VERSION_REGRESIVA in conceptos:
            traj["manifiesto_forma"] = "PASS"
            traj["firma"] = "PASS"
            traj["esquema_cuerpo"] = "FAIL"
            return "esquema_cuerpo", traj
        if CONCEPTO_MANIFIESTO_AUSENTE in conceptos or CONCEPTO_CODIGO_INVALIDO in conceptos:
            traj["manifiesto_forma"] = "FAIL"
            return "manifiesto_forma", traj
        traj["manifiesto_forma"] = "FAIL"
        return "INDETERMINATE", traj

    if man_ok:
        traj["manifiesto_forma"] = "PASS"
        traj["firma"] = "PASS"
        traj["esquema_cuerpo"] = "PASS"
    else:
        return "INDETERMINATE", traj

    for est, clave in (
        ("nucleo", PASO_NUCLEO),
        ("canales", PASO_CANALES),
        ("n_bytes", PASO_N_BYTES),
    ):
        p = pasos.get(clave)
        if isinstance(p, dict) and p.get("ok") is False:
            traj[est] = "FAIL"
            return est, traj
        if isinstance(p, dict) and p.get("ok") is True:
            traj[est] = "PASS"

    if fallos:
        return "INDETERMINATE", traj
    return "INDETERMINATE", traj


def clasificar(resultado: Dict[str, Any], hostil: bool) -> str:
    if not isinstance(resultado, dict) or "ok" not in resultado:
        return "INDETERMINATE"
    if hostil and resultado.get("ok") is True:
        return "BREACH"
    if resultado.get("ok") is False:
        return "BLOCKED"
    return "INDETERMINATE"


# ===============================================================
# ATACANTE
# ===============================================================

class AtacanteMonteCarlo:
    __slots__ = ("attacker_id", "seed", "rng", "pub_bytes", "datos", "manifiesto", "frente")

    def __init__(
        self,
        attacker_id: int,
        master_seed: int,
        pub_bytes: bytes,
        datos: bytes,
        manifiesto: Dict[str, Any],
        frente: str,
    ):
        self.attacker_id = attacker_id
        self.seed = int.from_bytes(
            hashlib.sha256(f"{master_seed}|{attacker_id}|{frente}".encode()).digest()[:8],
            "big",
        )
        self.rng = random.Random(self.seed)
        self.pub_bytes = bytes(pub_bytes)
        self.datos = bytes(datos)
        self.manifiesto = copy.deepcopy(manifiesto)
        self.frente = frente
        assert self.no_tiene_clave_privada()

    def no_tiene_clave_privada(self) -> bool:
        prohibido = ("private_key", "priv", "ruta_priv", "seed_crypto", "Ed25519PrivateKey")
        slots = getattr(type(self), "__slots__", ())
        for k in prohibido:
            if k in slots:
                return False
            if k in getattr(self, "__dict__", {}):
                return False
        return True

    def scenario_id(self, ops: str) -> str:
        raw = f"{self.seed}|{self.attacker_id}|{self.frente}|{ops}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]


# ===============================================================
# MUTADORES — solo RNG del atacante
# ===============================================================

CAMPOS_CUERPO = (
    "artifact_id", "clave_publica_id", "version", "emitido",
    "algoritmo_hash", "algoritmo_firma", "nucleo", "S", "Q",
    "n_bytes", "n_neutro", "valuaciones", "identidad_neutra", "esquema",
)


def _hex_rng(rng: random.Random, n_bytes: int) -> str:
    return bytes(rng.getrandbits(8) for _ in range(n_bytes)).hex()


def mutar_entrada(rng, datos, man):
    opciones = [None, "texto", 0, 1.5, True, False, list(datos), {"x": 1}, b""]
    return rng.choice(opciones), man, ["entrada_tipo"]


def mutar_forma(rng, datos, man):
    m = copy.deepcopy(man)
    op = rng.randint(0, 9)
    if op == 0:
        return datos, None, ["manifiesto_none"]
    if op == 1:
        return datos, [], ["manifiesto_lista"]
    if op == 2:
        return datos, "basura", ["manifiesto_str"]
    if op == 3:
        return datos, {}, ["manifiesto_vacio"]
    if op == 4:
        m["extra"] = "x"
        return datos, m, ["clave_extra"]
    if op == 5:
        del m["cuerpo"]
        return datos, m, ["sin_cuerpo"]
    if op == 6:
        del m["firma"]
        return datos, m, ["sin_firma"]
    if op == 7:
        m["cuerpo"] = "no-dict"
        return datos, m, ["cuerpo_str"]
    if op == 8:
        m["firma"] = 12345
        return datos, m, ["firma_int"]
    m["firma"] = ""
    return datos, m, ["firma_vacia"]


def mutar_firma(rng, datos, man):
    m = copy.deepcopy(man)
    op = rng.randint(0, 6)
    if op == 0:
        m["firma"] = _hex_rng(rng, 64)
        return datos, m, ["firma_random"]
    if op == 1:
        m["firma"] = m["firma"][:60]
        return datos, m, ["firma_truncada"]
    if op == 2:
        m["firma"] = m["firma"] + "ab"
        return datos, m, ["firma_extra"]
    if op == 3:
        m["firma"] = "zz" * 32
        return datos, m, ["firma_hex_invalido"]
    if op == 4:
        fh = m["firma"]
        i = rng.randint(0, max(0, len(fh) - 2))
        m["firma"] = fh[:i] + ("0" if fh[i] != "0" else "1") + fh[i + 1:]
        return datos, m, ["firma_flip_nibble"]
    if op == 5:
        m["firma"] = "00" * 64
        return datos, m, ["firma_ceros"]
    m["firma"] = "ff" * 64
    return datos, m, ["firma_ff"]


def mutar_cuerpo(rng, datos, man):
    m = copy.deepcopy(man)
    campo = rng.choice(CAMPOS_CUERPO)
    c = m["cuerpo"]
    if campo == "artifact_id":
        c["artifact_id"] = "ATK-" + str(rng.randint(0, 10**9))
    elif campo == "clave_publica_id":
        c["clave_publica_id"] = "FAKE-KEY"
    elif campo == "version":
        c["version"] = rng.choice([-1, 0, 10**9, "3", 1.5])
    elif campo == "emitido":
        c["emitido"] = 12345
    elif campo == "algoritmo_hash":
        c["algoritmo_hash"] = "MD5"
    elif campo == "algoritmo_firma":
        c["algoritmo_firma"] = "RSA"
    elif campo in ("nucleo", "S", "Q"):
        c[campo] = rng.choice(["00" * 32, "ff" * 32, "ab" * 32, "0" * 63, True, None, 0])
    elif campo == "n_bytes":
        c["n_bytes"] = rng.choice([-1, 0, 10**9, "10", True])
    elif campo == "n_neutro":
        c["n_neutro"] = rng.choice([-1, 0, 1, 3.0, True, "3"])
    elif campo == "valuaciones":
        c["valuaciones"] = rng.choice([None, "x", [999], [], list(range(100)), True])
    elif campo == "identidad_neutra":
        c["identidad_neutra"] = rng.choice([0, 1, "true", None])
    elif campo == "esquema":
        c["esquema"] = rng.choice([0, 2, "1", None])
    return datos, m, [f"cuerpo_{campo}"]


def mutar_esquema(rng, datos, man):
    m = copy.deepcopy(man)
    c = m["cuerpo"]
    op = rng.randint(0, 5)
    if op == 0:
        k = rng.choice(CAMPOS_CUERPO)
        if k in c:
            del c[k]
            return datos, m, [f"elimina_{k}"]
    if op == 1:
        c["campo_fantasma"] = "x"
        return datos, m, ["clave_extra_cuerpo"]
    if op == 2:
        c["nucleo"] = "not-hex"
        return datos, m, ["nucleo_mal_hex"]
    if op == 3:
        c["version"] = -100
        return datos, m, ["version_negativa"]
    if op == 4:
        c["S"] = "aa" * 16
        return datos, m, ["S_corto"]
    c["valuaciones"] = [1, 2, "x"]
    return datos, m, ["valuaciones_tipo"]


def mutar_datos(rng, datos, man):
    d = bytearray(datos) if datos else bytearray(b"\x00")
    op = rng.randint(0, 8)
    if op == 0:
        i = rng.randint(0, len(d) - 1)
        d[i] ^= 0x01
        return bytes(d), man, ["flip_bit"]
    if op == 1:
        i = rng.randint(0, len(d) - 1)
        d[i] ^= 0xFF
        return bytes(d), man, ["flip_byte"]
    if op == 2:
        i = rng.randint(0, len(d) - 1)
        nuevo = rng.randint(0, 255)
        if nuevo == d[i]:
            nuevo = (d[i] + 1) % 256
        d[i] = nuevo
        return bytes(d), man, ["byte_random"]
    if op == 3:
        return (bytes(d[:-1]) if len(d) > 1 else b""), man, ["truncar"]
    if op == 4:
        return bytes(d) + bytes([rng.randint(0, 255)]), man, ["extender"]
    if op == 5:
        return b"\x00" + bytes(d), man, ["prefijo"]
    if op == 6:
        return bytes(d) + b"\xff\xff", man, ["sufijo"]
    if op == 7:
        mid = len(d) // 2
        d[mid:mid + 1] = b"\xaa"
        return bytes(d), man, ["region_media"]
    for _ in range(rng.randint(2, 5)):
        if d:
            d[rng.randint(0, len(d) - 1)] ^= rng.randint(1, 255)
    return bytes(d), man, ["multi_flip"]


def mutar_nucleo_campo(rng, datos, man):
    m = copy.deepcopy(man)
    m["cuerpo"]["nucleo"] = _hex_rng(rng, 32)
    return datos, m, ["nucleo_en_cuerpo"]


def mutar_canales_campo(rng, datos, man):
    m = copy.deepcopy(man)
    op = rng.randint(0, 2)
    if op == 0:
        m["cuerpo"]["S"] = "11" * 32
        return datos, m, ["S_solo"]
    if op == 1:
        m["cuerpo"]["Q"] = "22" * 32
        return datos, m, ["Q_solo"]
    m["cuerpo"]["S"] = "33" * 32
    m["cuerpo"]["Q"] = "44" * 32
    return datos, m, ["S_y_Q"]


def mutar_longitud(rng, datos, man):
    d = bytearray(datos)
    if rng.random() < 0.5:
        d.append(0xAB)
        return bytes(d), man, ["len_mas_1"]
    if len(d) > 1:
        return bytes(d[:-1]), man, ["len_menos_1"]
    return bytes(d) + b"\x00\x00", man, ["len_mas_2"]


def mutar_recomposicion(rng, datos, man, datos_b, man_b):
    op = rng.randint(0, 7)
    if op == 0:
        return datos_b, man, ["man_A_datos_B"]
    if op == 1:
        return datos, man_b, ["man_B_datos_A"]
    if op == 2:
        m = copy.deepcopy(man)
        m["firma"] = man_b["firma"]
        return datos, m, ["firma_B_cuerpo_A"]
    if op == 3:
        m = copy.deepcopy(man_b)
        m["firma"] = man["firma"]
        return datos_b, m, ["firma_A_cuerpo_B"]
    if op == 4:
        m = copy.deepcopy(man)
        m["cuerpo"] = copy.deepcopy(man_b["cuerpo"])
        return datos, m, ["cuerpo_B_firma_A_datos_A"]
    if op == 5:
        m = copy.deepcopy(man_b)
        m["cuerpo"] = copy.deepcopy(man["cuerpo"])
        return datos_b, m, ["cuerpo_A_firma_B_datos_B"]
    if op == 6:
        m = copy.deepcopy(man)
        m["cuerpo"] = copy.deepcopy(man_b["cuerpo"])
        m["firma"] = man_b["firma"]
        return datos, m, ["todo_B_datos_A"]
    m = copy.deepcopy(man_b)
    m["cuerpo"] = copy.deepcopy(man["cuerpo"])
    m["firma"] = man["firma"]
    return datos_b, m, ["todo_A_datos_B"]


def mutar_forja_cero(rng, datos, man):
    op = rng.randint(0, 5)
    if op == 0:
        cuerpo = {
            "esquema": 1, "version": 1, "emitido": "forjado",
            "artifact_id": "FORJA", "clave_publica_id": "FAKE",
            "algoritmo_hash": "SHA-256", "algoritmo_firma": "Ed25519",
            "nucleo": _hex_rng(rng, 32), "S": _hex_rng(rng, 32), "Q": _hex_rng(rng, 32),
            "n_bytes": len(datos), "n_neutro": 3,
            "valuaciones": [0, 0, 0, 0, 0, 0, 0, 0], "identidad_neutra": True,
        }
        return datos, {"cuerpo": cuerpo, "firma": _hex_rng(rng, 64)}, ["forja_cuerpo_firma"]
    if op == 1:
        m = copy.deepcopy(man)
        m["firma"] = _hex_rng(rng, 64)
        return datos, m, ["forja_solo_firma"]
    if op == 2:
        m = copy.deepcopy(man)
        m["cuerpo"]["artifact_id"] = "FORJA-" + str(rng.randint(0, 10**6))
        m["firma"] = _hex_rng(rng, 64)
        return datos, m, ["forja_id_y_firma"]
    if op == 3:
        m = copy.deepcopy(man)
        m["cuerpo"]["nucleo"] = oracle_nucleo(datos)
        m["firma"] = _hex_rng(rng, 64)
        return datos, m, ["forja_nucleo_real_firma_falsa"]
    if op == 4:
        d = bytes(rng.getrandbits(8) for _ in range(max(1, len(datos))))
        m = copy.deepcopy(man)
        m["firma"] = _hex_rng(rng, 64)
        return d, m, ["forja_datos_y_firma"]
    m = {"cuerpo": copy.deepcopy(man["cuerpo"]), "firma": _hex_rng(rng, 32)}
    return datos, m, ["forja_firma_corta"]


def mutar_compuesto(rng, datos, man):
    d, m, ops = datos, copy.deepcopy(man), []
    n = rng.randint(2, 5)
    gens = [mutar_datos, mutar_cuerpo, mutar_firma, mutar_esquema, mutar_longitud]
    for _ in range(n):
        g = rng.choice(gens)
        d, m, op = g(rng, d if isinstance(d, (bytes, bytearray)) else datos, m if isinstance(m, dict) else man)
        ops.extend(op)
        if not isinstance(d, (bytes, bytearray)) or not isinstance(m, dict):
            break
    return d, m, ops


GENERADORES = {
    "entrada": mutar_entrada,
    "forma": mutar_forma,
    "firma": mutar_firma,
    "esquema": mutar_esquema,
    "cuerpo": mutar_cuerpo,
    "datos": mutar_datos,
    "nucleo_campo": mutar_nucleo_campo,
    "canales_campo": mutar_canales_campo,
    "longitud": mutar_longitud,
    "forja_cero": mutar_forja_cero,
    "compuesto": mutar_compuesto,
}


def elegir_frente(rng):
    total = sum(PESOS_FRENTE.values())
    r = rng.randint(1, total)
    acc = 0
    for f, w in PESOS_FRENTE.items():
        acc += w
        if r <= acc:
            return f
    return "datos"


# ===============================================================
# FIXTURE
# ===============================================================

@pytest.fixture(scope="module")
def autoridad_unica(tmp_path_factory):
    base = tmp_path_factory.mktemp("espartaco")
    priv = base / "legit.key"
    pub = base / "legit.pub"
    assert P.generar_claves(str(priv), str(pub))["ok"] is True
    pub_bytes = pub.read_bytes()
    built = P.build(
        b"ESPARTACO::ARTEFACTO::LEGITIMO::HARNESS2",
        str(priv), n_neutro=3, artifact_id="ESP-LEGIT-001", version=1, clave_publica_id="ROOT-ESP",
    )
    assert built["ok"] is True
    priv_b = base / "b.key"
    pub_b = base / "b.pub"
    P.generar_claves(str(priv_b), str(pub_b))
    built_b = P.build(
        b"ESPARTACO::ARTEFACTO::B::DISTINTO",
        str(priv_b), n_neutro=3, artifact_id="ESP-B-002", version=1, clave_publica_id="ROOT-B",
    )
    assert built_b["ok"] is True
    return {
        "pub_bytes": pub_bytes,
        "datos": built["datos"],
        "manifiesto": built["manifiesto"],
        "datos_b": built_b["datos"],
        "manifiesto_b": built_b["manifiesto"],
    }


# ===============================================================
# CALIBRACIÓN
# ===============================================================

def test_00_espartaco_procedencia():
    assert SPEC_ID.startswith("TEST-ESPARTACO")
    assert len(SPEC_HASH) == 64
    assert MASTER_SEED > 0


def test_01_calibracion_estaciones(autoridad_unica):
    pub = autoridad_unica["pub_bytes"]
    datos = autoridad_unica["datos"]
    man = copy.deepcopy(autoridad_unica["manifiesto"])

    r = P.verificar(datos, manifiesto=man, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is True
    est, traj = trayectoria_y_estacion(r)
    assert est == "NINGUNA_BREACH"
    assert all(traj[e] == "PASS" for e in ESTACIONES)

    m = copy.deepcopy(man)
    m["cuerpo"]["artifact_id"] = "X"
    r = P.verificar(datos, manifiesto=m, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, _ = trayectoria_y_estacion(r)
    assert est == "firma"
    assert CONCEPTO_FIRMA_INVALIDA in (r.get("conceptos") or [])

    m = copy.deepcopy(man)
    m["cuerpo"]["nucleo"] = "00" * 32
    r = P.verificar(datos, manifiesto=m, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, _ = trayectoria_y_estacion(r)
    assert est == "firma"

    d = bytearray(datos)
    d[0] ^= 0xFF
    r = P.verificar(bytes(d), manifiesto=man, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, traj = trayectoria_y_estacion(r)
    assert est == "nucleo"
    assert traj["firma"] == "PASS"
    assert traj["nucleo"] == "FAIL"

    r = P.verificar(autoridad_unica["datos_b"], manifiesto=man, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, _ = trayectoria_y_estacion(r)
    assert est == "nucleo"

    r = P.verificar(datos, manifiesto=None, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, _ = trayectoria_y_estacion(r)
    assert est == "manifiesto_forma"
    assert CONCEPTO_MANIFIESTO_AUSENTE in (r.get("conceptos") or [])

    m = copy.deepcopy(man)
    m["extra"] = 1
    r = P.verificar(datos, manifiesto=m, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, _ = trayectoria_y_estacion(r)
    assert est == "manifiesto_forma"

    r = P.verificar("texto", manifiesto=man, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r["ok"] is False
    est, _ = trayectoria_y_estacion(r)
    assert est == "entrada_datos"
    assert FALLO_DATOS in (r.get("fallos") or [])


# ===============================================================
# MOTOR MONTE CARLO
# ===============================================================

def test_99_espartaco_montecarlo_demolicion(autoridad_unica):
    pub = autoridad_unica["pub_bytes"]
    datos0 = autoridad_unica["datos"]
    man0 = autoridad_unica["manifiesto"]
    datos_b = autoridad_unica["datos_b"]
    man_b = autoridad_unica["manifiesto_b"]

    r_ok = P.verificar(datos0, manifiesto=man0, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r_ok["ok"] is True

    n_generados = 0
    n_noop = 0
    n_executed = 0
    blocked = 0
    breaches = 0
    exceptions = 0
    indeterminate = 0

    conteo_estacion = {e: 0 for e in ESTACIONES}
    conteo_estacion["NINGUNA_BREACH"] = 0
    conteo_estacion["INDETERMINATE"] = 0
    conteo_frente = {f: 0 for f in FRENTES}
    matriz = defaultdict(int)
    profundidad_sum = 0
    profundidad_max = 0
    estacion_max = ""
    breach_cases = []
    exception_cases = []
    indeterminate_cases = []

    meta_rng = random.Random(MASTER_SEED)

    for i in range(N_ATACANTES):
        frente = elegir_frente(meta_rng)
        atk = AtacanteMonteCarlo(i, MASTER_SEED, pub, datos0, man0, frente)
        assert atk.no_tiene_clave_privada()
        n_generados += 1
        conteo_frente[frente] += 1

        try:
            if frente == "recomposicion":
                d, m, ops = mutar_recomposicion(atk.rng, atk.datos, atk.manifiesto, datos_b, man_b)
            elif frente in GENERADORES:
                d, m, ops = GENERADORES[frente](atk.rng, atk.datos, atk.manifiesto)
            else:
                d, m, ops = mutar_datos(atk.rng, atk.datos, atk.manifiesto)

            mismo_datos = isinstance(d, (bytes, bytearray)) and bytes(d) == atk.datos
            mismo_man = isinstance(m, dict) and m == atk.manifiesto
            if mismo_datos and mismo_man:
                n_noop += 1
                continue

            resultado = P.verificar(d, manifiesto=m, pub_bytes=atk.pub_bytes, modo=P.MODO_PROTEGIDO)
        except Exception as ex:
            exceptions += 1
            exception_cases.append({
                "attacker_id": i, "seed": atk.seed, "frente": frente,
                "error": repr(ex), "tb": traceback.format_exc()[-400:],
            })
            continue

        n_executed += 1
        clase = clasificar(resultado, hostil=True)
        est, traj = trayectoria_y_estacion(resultado)
        sid = atk.scenario_id("|".join(ops) if isinstance(ops, list) else str(ops))

        registro = {
            "attacker_id": i, "seed": atk.seed, "frente": frente,
            "operaciones": ops, "scenario_id": sid,
            "ok": resultado.get("ok") if isinstance(resultado, dict) else None,
            "clasificacion": clase, "estacion": est,
            "profundidad": PROFUNDIDAD.get(est, 0), "trayectoria": traj,
            "fallos": list(resultado.get("fallos") or []) if isinstance(resultado, dict) else [],
            "conceptos": list(resultado.get("conceptos") or []) if isinstance(resultado, dict) else [],
        }

        if clase == "BREACH":
            breaches += 1
            breach_cases.append(registro)
            continue  # NO break

        if clase == "INDETERMINATE" or est == "INDETERMINATE":
            indeterminate += 1
            indeterminate_cases.append(registro)
            continue

        if clase == "BLOCKED":
            blocked += 1
            conteo_estacion[est] = conteo_estacion.get(est, 0) + 1
            matriz[(frente, est)] += 1
            prof = PROFUNDIDAD.get(est, 0)
            profundidad_sum += prof
            if prof > profundidad_max:
                profundidad_max = prof
                estacion_max = est
            assert atk.no_tiene_clave_privada()
            continue

        indeterminate += 1
        indeterminate_cases.append(registro)

    cobertura_ok = all(conteo_frente[f] >= MIN_POR_FRENTE for f in FRENTES)
    upper = (3.0 / n_executed) if n_executed else 1.0
    prof_media = (profundidad_sum / blocked) if blocked else 0.0

    lineas = [
        "", "=" * 62,
        "ESPARTACO SECURITY ADVERSARIAL ASSESSMENT",
        "=" * 62,
        f"SPEC_ID={SPEC_ID}  REV={SPEC_REVISION}",
        f"MASTER_SEED={MASTER_SEED}",
        f"ATTACKERS_GENERATED       {n_generados}",
        f"NO_OP                     {n_noop}",
        f"ATTACKS_EXECUTED          {n_executed}",
        f"BLOCKED                   {blocked}",
        f"BREACH                    {breaches}",
        f"EXCEPTION                 {exceptions}",
        f"INDETERMINATE             {indeterminate}",
        "-" * 62, "DEPTH REACHED (BLOCKED only)", "-" * 62,
    ]
    for e in ESTACIONES:
        lineas.append(f"{e:<24}{conteo_estacion.get(e, 0)}")
    lineas.append(f"{'ACCEPTED/BREACH':<24}{breaches}")
    lineas.append("-" * 62)
    lineas.append("ATTACK SURFACE COVERAGE (generated)")
    lineas.append("-" * 62)
    for f in FRENTES:
        pct = 100.0 * conteo_frente[f] / max(1, n_generados)
        flag = "OK" if conteo_frente[f] >= MIN_POR_FRENTE else "LOW"
        lineas.append(f"{f:<20}{conteo_frente[f]:>8}  {pct:5.1f}%  {flag}")
    lineas.append("-" * 62)
    lineas.append("MATRIX frente x estacion (blocked)")
    hdr = f"{'FRENTE':<16}" + "".join(f"{e[:7]:>8}" for e in ESTACIONES)
    lineas.append(hdr)
    for f in FRENTES:
        row = f"{f:<16}"
        for e in ESTACIONES:
            row += f"{matriz.get((f, e), 0):>8}"
        lineas.append(row)
    lineas.append("-" * 62)
    lineas.append("CRYPTOGRAPHIC OUTCOME")
    lineas.append("-" * 62)
    lineas.append(f"UNAUTHORIZED_ACCEPTANCE   {breaches}")
    lineas.append(f"BREACH                    {breaches}")
    lineas.append(f"PRIVATE_KEY_EXPOSURE      0")
    lineas.append(f"EXCEPTIONS                {exceptions}")
    lineas.append(f"INDETERMINATE             {indeterminate}")
    lineas.append(f"PROFUNDIDAD_MAX={profundidad_max}  ESTACION_MAX={estacion_max}")
    lineas.append(f"PROFUNDIDAD_MEDIA={prof_media:.3f}")
    lineas.append("-" * 62)
    lineas.append("STATISTICAL BOUND (sobre EXECUTED)")
    lineas.append("-" * 62)
    lineas.append(f"EXECUTED = {n_executed}")
    lineas.append(f"BREACH   = {breaches}")
    if breaches == 0 and n_executed > 0:
        lineas.append(f"UPPER 95% BOUND ≈ {upper:.2e}")
    if breach_cases:
        lineas.append("-" * 62)
        lineas.append("CRITICAL BREACH CASES")
        for bc in breach_cases[:10]:
            lineas.append(
                f"  id={bc['attacker_id']} seed={bc['seed']} frente={bc['frente']} "
                f"ops={bc['operaciones']} est={bc['estacion']} sid={bc['scenario_id']}"
            )
    status = "PASS"
    if breaches > 0:
        status = "CRITICAL FAILURE"
    elif exceptions > 0 or indeterminate > 0 or not cobertura_ok:
        status = "FAIL"
    lineas.append("-" * 62)
    lineas.append(f"STATUS: {status}")
    lineas.append("=" * 62)
    print("\n".join(lineas))

    assert exceptions == 0, f"EXCEPTIONS={exceptions} {exception_cases[:3]}"
    assert indeterminate == 0, f"INDETERMINATE={indeterminate} {indeterminate_cases[:3]}"
    assert breaches == 0, f"CRITICAL_BREACH x{breaches}: {breach_cases[:5]}"
    assert cobertura_ok, f"cobertura insuficiente: {conteo_frente}"
    assert n_executed > 0
    assert profundidad_max >= 2

    r_final = P.verificar(
        autoridad_unica["datos"],
        manifiesto=autoridad_unica["manifiesto"],
        pub_bytes=autoridad_unica["pub_bytes"],
        modo=P.MODO_PROTEGIDO,
    )
    assert r_final["ok"] is True
