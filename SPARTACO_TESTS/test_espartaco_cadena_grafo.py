# ===============================================================
# TEST ESPARTACO — CADENA / GRAFO DE CONSISTENCIA
# tests/test_espartaco_cadena_grafo.py
# ===============================================================
# Atacantes CON clave pública, SIN clave privada.
# Objetivo: mapear en qué NODO de la cadena se tranca el atacante
# cuando muta bytes (ej. "53") y rompe dependencias verificables.
#
# Cadena conceptual:
#   datos → nucleo → canales(S/Q) → n_bytes → cuerpo canónico → firma
#                                      ↑
#                               pub_bytes solo VERIFICA
#                               (no firma de nuevo)
#
# No protege el SUT. Busca BREACH. Mide dónde queda atrapado.
# proteccion.py intacto.
# ===============================================================

from __future__ import annotations

import copy
import hashlib
import os
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import pytest

import modules.spartaco_seguridad.proteccion as P


# ===============================================================
# PROCEDENCIA
# ===============================================================

SPEC_ID = "TEST-ESPARTACO-CADENA-GRAFO-1.0"
SPEC_REVISION = "2026-08-11"
SPEC_HASH = hashlib.sha256(
    b"ESPARTACO|CADENA|GRAFO|NODOS|PUB-ONLY|SIN-PRIV"
).hexdigest()

MASTER_SEED = int(os.environ.get("ESPARTACO_CADENA_SEED", "20260811"))
N_ATACANTES = int(os.environ.get("ESPARTACO_CADENA_N", "100000"))

# ===============================================================
# GRAFO DE LA CADENA (nodos y aristas de dependencia)
# ===============================================================
# Cada nodo es un punto de verificación observable.
# Cada arista A → B significa: B depende de A; mutar A sin
# reconstruir B produce inconsistencia detectable.

NODOS = (
    "datos",           # bytes del artefacto
    "nucleo",          # SHA-256(datos) sellado en cuerpo
    "canales_S",       # canal S autenticado en cuerpo
    "canales_Q",       # canal Q autenticado en cuerpo
    "n_bytes",         # longitud autenticada
    "cuerpo",          # resto de campos del cuerpo firmado
    "canónico",        # serialización del cuerpo firmado
    "firma",           # Ed25519 sobre canónico
    "manifiesto",      # contenedor {cuerpo, firma}
    "aceptacion",      # ok is True (solo legítimo o BREACH)
)

# Aristas dirigidas: origen → destino (destino depende de origen)
ARISTAS = (
    ("datos", "nucleo"),
    ("datos", "canales_S"),
    ("datos", "canales_Q"),
    ("datos", "n_bytes"),
    ("nucleo", "cuerpo"),
    ("canales_S", "cuerpo"),
    ("canales_Q", "cuerpo"),
    ("n_bytes", "cuerpo"),
    ("cuerpo", "canónico"),
    ("canónico", "firma"),
    ("firma", "manifiesto"),
    ("manifiesto", "aceptacion"),
)

FALLO_DATOS = "datos"
FALLO_MANIFIESTO = "manifiesto"
CONCEPTO_MANIFIESTO_AUSENTE = "MANIFIESTO_AUSENTE"
CONCEPTO_FIRMA_INVALIDA = "FIRMA_INVÁLIDA"
CONCEPTO_CODIGO_INVALIDO = "CÓDIGO_INVÁLIDO"
CONCEPTO_INTEGRIDAD = "INTEGRIDAD_COMPROMETIDA"


# ===============================================================
# DETECTOR DE NODO — claves del SUT, sin heurística de texto
# ===============================================================

def nodo_detencion(resultado: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    """
    Devuelve (nodo_donde_se_tranca, trayectoria_por_nodo).
    trayectoria[n] ∈ {PASS, FAIL, SKIP, NA}
    """
    traj = {n: "SKIP" for n in NODOS}

    if resultado.get("ok") is True:
        for n in NODOS:
            traj[n] = "PASS"
        return "aceptacion", traj

    fallos = list(resultado.get("fallos") or [])
    conceptos = frozenset(resultado.get("conceptos") or [])
    pasos = resultado.get("pasos") or {}

    if FALLO_DATOS in fallos:
        traj["datos"] = "FAIL"
        return "datos", traj
    traj["datos"] = "PASS"

    man = pasos.get("manifiesto")
    man_ok = isinstance(man, dict) and man.get("ok") is True
    man_fail = isinstance(man, dict) and man.get("ok") is False

    if man_fail or (FALLO_MANIFIESTO in fallos and not man_ok):
        if CONCEPTO_FIRMA_INVALIDA in conceptos:
            traj["manifiesto"] = "PASS"
            traj["firma"] = "FAIL"
            traj["canónico"] = "PASS"
            traj["cuerpo"] = "PASS"
            return "firma", traj
        if CONCEPTO_MANIFIESTO_AUSENTE in conceptos or CONCEPTO_CODIGO_INVALIDO in conceptos:
            traj["manifiesto"] = "FAIL"
            return "manifiesto", traj
        traj["manifiesto"] = "FAIL"
        return "manifiesto", traj

    if man_ok:
        traj["manifiesto"] = "PASS"
        traj["firma"] = "PASS"
        traj["canónico"] = "PASS"
        traj["cuerpo"] = "PASS"
    else:
        return "manifiesto", traj

    p_nuc = pasos.get("nucleo")
    if isinstance(p_nuc, dict) and p_nuc.get("ok") is False:
        traj["nucleo"] = "FAIL"
        return "nucleo", traj
    if isinstance(p_nuc, dict) and p_nuc.get("ok") is True:
        traj["nucleo"] = "PASS"

    p_can = pasos.get("canales")
    if isinstance(p_can, dict) and p_can.get("ok") is False:
        traj["canales_S"] = "FAIL"
        traj["canales_Q"] = "FAIL"
        return "canales", traj
    if isinstance(p_can, dict) and p_can.get("ok") is True:
        traj["canales_S"] = "PASS"
        traj["canales_Q"] = "PASS"

    p_nb = pasos.get("n_bytes")
    if isinstance(p_nb, dict) and p_nb.get("ok") is False:
        traj["n_bytes"] = "FAIL"
        return "n_bytes", traj
    if isinstance(p_nb, dict) and p_nb.get("ok") is True:
        traj["n_bytes"] = "PASS"

    return "manifiesto", traj


def clasificar(resultado: Dict[str, Any], hostil: bool) -> str:
    if not isinstance(resultado, dict) or "ok" not in resultado:
        return "INDETERMINATE"
    if hostil and resultado.get("ok") is True:
        return "BREACH"
    if resultado.get("ok") is False:
        return "BLOCKED"
    return "INDETERMINATE"


# ===============================================================
# ATACANTE CON CLAVE PÚBLICA (sin privada)
# ===============================================================

class AtacanteCadena:
    """
    Posee: datos interceptados, manifiesto, firma, pub_bytes.
    No posee: clave privada.
    Intenta mutar y rearmar la cadena. Sin privada no puede
    regenerar firma Ed25519 válida para el nuevo contenido.
    """
    __slots__ = (
        "attacker_id", "seed", "rng",
        "pub_bytes", "datos", "manifiesto", "frente",
    )

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
            hashlib.sha256(
                f"{master_seed}|CADENA|{attacker_id}|{frente}".encode()
            ).digest()[:8],
            "big",
        )
        self.rng = random.Random(self.seed)
        self.pub_bytes = bytes(pub_bytes)
        self.datos = bytes(datos)
        self.manifiesto = copy.deepcopy(manifiesto)
        self.frente = frente
        assert self.tiene_solo_publica()

    def tiene_solo_publica(self) -> bool:
        prohibido = ("private_key", "priv", "ruta_priv", "Ed25519PrivateKey", "seed_crypto")
        for k in prohibido:
            if k in getattr(type(self), "__slots__", ()):
                return False
            if k in getattr(self, "__dict__", {}):
                return False
        return isinstance(self.pub_bytes, (bytes, bytearray)) and len(self.pub_bytes) == 32

    def scenario_id(self, ops: str) -> str:
        raw = f"{self.seed}|{self.attacker_id}|{self.frente}|{ops}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]


# ===============================================================
# FRENTES DE INTERCEPTACIÓN
# ===============================================================

PESOS = {
    "intercepta_byte": 20,
    "intercepta_region": 12,
    "intercepta_longitud": 10,
    "intercepta_nucleo": 10,
    "intercepta_canal_S": 8,
    "intercepta_canal_Q": 8,
    "intercepta_firma": 12,
    "intercepta_cuerpo": 10,
    "rearma_parcial": 10,
}
FRENTES = list(PESOS.keys())


def _hex(rng: random.Random, n: int) -> str:
    return bytes(rng.getrandbits(8) for _ in range(n)).hex()


def mut_intercepta_byte(rng, datos, man):
    d = bytearray(datos)
    if not d:
        d = bytearray(b"\x00")
    i = rng.randint(0, len(d) - 1)
    old = d[i]
    nuevo = rng.randint(0, 255)
    if nuevo == old:
        nuevo = (old + 1) % 256
    d[i] = nuevo
    return bytes(d), man, [f"byte_pos_{i}", f"old_{old}", f"new_{nuevo}"]


def mut_intercepta_region(rng, datos, man):
    d = bytearray(datos) if datos else bytearray(b"\x00\x00")
    a = rng.randint(0, max(0, len(d) - 1))
    b = rng.randint(a, min(len(d), a + 8))
    for i in range(a, b):
        d[i] = rng.randint(0, 255)
    return bytes(d), man, [f"region_{a}_{b}"]


def mut_intercepta_longitud(rng, datos, man):
    d = bytearray(datos)
    op = rng.randint(0, 2)
    if op == 0:
        d.append(rng.randint(0, 255))
        return bytes(d), man, ["len_plus_1"]
    if op == 1 and len(d) > 1:
        return bytes(d[:-1]), man, ["len_minus_1"]
    return bytes(d) + bytes([rng.randint(0, 255), rng.randint(0, 255)]), man, ["len_plus_2"]


def mut_intercepta_nucleo(rng, datos, man):
    m = copy.deepcopy(man)
    m["cuerpo"]["nucleo"] = _hex(rng, 32)
    return datos, m, ["nucleo_forzado"]


def mut_intercepta_canal_S(rng, datos, man):
    m = copy.deepcopy(man)
    m["cuerpo"]["S"] = _hex(rng, 32)
    return datos, m, ["S_forzado"]


def mut_intercepta_canal_Q(rng, datos, man):
    m = copy.deepcopy(man)
    m["cuerpo"]["Q"] = _hex(rng, 32)
    return datos, m, ["Q_forzado"]


def mut_intercepta_firma(rng, datos, man):
    m = copy.deepcopy(man)
    op = rng.randint(0, 3)
    if op == 0:
        m["firma"] = _hex(rng, 64)
        return datos, m, ["firma_random"]
    if op == 1:
        m["firma"] = m["firma"][:60]
        return datos, m, ["firma_truncada"]
    if op == 2:
        fh = m["firma"]
        i = rng.randint(0, max(0, len(fh) - 2))
        m["firma"] = fh[:i] + ("0" if fh[i] != "0" else "1") + fh[i + 1:]
        return datos, m, ["firma_flip"]
    m["firma"] = "00" * 64
    return datos, m, ["firma_ceros"]


def mut_intercepta_cuerpo(rng, datos, man):
    m = copy.deepcopy(man)
    campo = rng.choice([
        "artifact_id", "clave_publica_id", "version", "n_neutro",
        "valuaciones", "identidad_neutra", "emitido",
    ])
    c = m["cuerpo"]
    if campo == "artifact_id":
        c["artifact_id"] = "ATK-" + str(rng.randint(0, 10**9))
    elif campo == "clave_publica_id":
        c["clave_publica_id"] = "FAKE"
    elif campo == "version":
        c["version"] = rng.choice([-1, 0, 999])
    elif campo == "n_neutro":
        c["n_neutro"] = rng.choice([-1, 0, 1, True, "3"])
    elif campo == "valuaciones":
        c["valuaciones"] = [999]
    elif campo == "identidad_neutra":
        c["identidad_neutra"] = not c.get("identidad_neutra", True)
    else:
        c["emitido"] = 0
    return datos, m, [f"cuerpo_{campo}"]


def mut_rearma_parcial(rng, datos, man):
    """
    Recalcula nucleo localmente tras mutar datos y lo escribe en cuerpo.
    Sin privada no puede re-firmar → tranca en firma.
    """
    m = copy.deepcopy(man)
    d = bytearray(datos)
    if d:
        d[rng.randint(0, len(d) - 1)] ^= 0xFF
    d2 = bytes(d)
    nucleo_local = hashlib.sha256(d2).hexdigest()
    m["cuerpo"]["nucleo"] = nucleo_local
    m["cuerpo"]["n_bytes"] = len(d2)
    return d2, m, ["rearma_nucleo_sin_firma"]


GENERADORES = {
    "intercepta_byte": mut_intercepta_byte,
    "intercepta_region": mut_intercepta_region,
    "intercepta_longitud": mut_intercepta_longitud,
    "intercepta_nucleo": mut_intercepta_nucleo,
    "intercepta_canal_S": mut_intercepta_canal_S,
    "intercepta_canal_Q": mut_intercepta_canal_Q,
    "intercepta_firma": mut_intercepta_firma,
    "intercepta_cuerpo": mut_intercepta_cuerpo,
    "rearma_parcial": mut_rearma_parcial,
}


def elegir_frente(rng: random.Random) -> str:
    total = sum(PESOS.values())
    r = rng.randint(1, total)
    acc = 0
    for f, w in PESOS.items():
        acc += w
        if r <= acc:
            return f
    return "intercepta_byte"


# ===============================================================
# FIXTURE — UNA AUTORIDAD, CLAVE PÚBLICA PARA TODOS
# ===============================================================

@pytest.fixture(scope="module")
def autoridad_cadena(tmp_path_factory):
    base = tmp_path_factory.mktemp("cadena")
    priv = base / "legit.key"
    pub = base / "legit.pub"
    assert P.generar_claves(str(priv), str(pub))["ok"] is True
    pub_bytes = pub.read_bytes()
    payload = b"CADENA-ESPARTACO-53-GRAFO-CONSISTENCIA"
    built = P.build(
        payload,
        str(priv),
        n_neutro=3,
        artifact_id="CADENA-001",
        version=1,
        clave_publica_id="ROOT-CADENA",
    )
    assert built["ok"] is True
    return {
        "pub_bytes": pub_bytes,
        "datos": built["datos"],
        "manifiesto": built["manifiesto"],
        "payload_original": payload,
    }


# ===============================================================
# CALIBRACIÓN DE LA CADENA
# ===============================================================

def test_00_cadena_procedencia():
    assert SPEC_ID.startswith("TEST-ESPARTACO-CADENA")
    assert len(SPEC_HASH) == 64


def test_01_cadena_legitima_completa(autoridad_cadena):
    r = P.verificar(
        autoridad_cadena["datos"],
        manifiesto=autoridad_cadena["manifiesto"],
        pub_bytes=autoridad_cadena["pub_bytes"],
        modo=P.MODO_PROTEGIDO,
    )
    assert r["ok"] is True
    nodo, traj = nodo_detencion(r)
    assert nodo == "aceptacion"
    assert traj["firma"] == "PASS"
    assert traj["nucleo"] == "PASS"


def test_02_cambiar_byte_rompe_nucleo(autoridad_cadena):
    """
    Atacante cambia un byte. Tiene pub. No tiene priv.
    datos' ≠ datos ⇒ SHA256(datos') ≠ nucleo sellado ⇒ tranca en nucleo.
    Firma del cuerpo sigue válida (cuerpo no tocado).
    """
    datos = bytearray(autoridad_cadena["datos"])
    assert len(datos) > 0
    pos = 0
    for i, b in enumerate(datos):
        if b in (0x35, 0x33, 0x53):
            pos = i
            break
    old = datos[pos]
    datos[pos] = (old + 1) % 256
    r = P.verificar(
        bytes(datos),
        manifiesto=autoridad_cadena["manifiesto"],
        pub_bytes=autoridad_cadena["pub_bytes"],
        modo=P.MODO_PROTEGIDO,
    )
    assert r["ok"] is False
    nodo, traj = nodo_detencion(r)
    assert nodo == "nucleo"
    assert traj["firma"] == "PASS"
    assert traj["nucleo"] == "FAIL"
    assert CONCEPTO_INTEGRIDAD in (r.get("conceptos") or []) or "nucleo" in (r.get("fallos") or [])


def test_03_rearma_nucleo_sin_privada_tranca_en_firma(autoridad_cadena):
    d, m, ops = mut_rearma_parcial(
        random.Random(1),
        autoridad_cadena["datos"],
        autoridad_cadena["manifiesto"],
    )
    r = P.verificar(
        d, manifiesto=m, pub_bytes=autoridad_cadena["pub_bytes"], modo=P.MODO_PROTEGIDO
    )
    assert r["ok"] is False
    nodo, traj = nodo_detencion(r)
    assert nodo == "firma"
    assert CONCEPTO_FIRMA_INVALIDA in (r.get("conceptos") or [])


def test_04_atacante_tiene_pub_no_priv(autoridad_cadena):
    atk = AtacanteCadena(
        0, MASTER_SEED,
        autoridad_cadena["pub_bytes"],
        autoridad_cadena["datos"],
        autoridad_cadena["manifiesto"],
        "intercepta_byte",
    )
    assert atk.tiene_solo_publica() is True
    r = P.verificar(
        autoridad_cadena["datos"],
        manifiesto=autoridad_cadena["manifiesto"],
        pub_bytes=atk.pub_bytes,
        modo=P.MODO_PROTEGIDO,
    )
    assert r["ok"] is True


# ===============================================================
# MONTE CARLO — MAPA DEL GRAFO
# ===============================================================

def test_99_cadena_montecarlo_grafo(autoridad_cadena):
    pub = autoridad_cadena["pub_bytes"]
    datos0 = autoridad_cadena["datos"]
    man0 = autoridad_cadena["manifiesto"]

    r_ok = P.verificar(datos0, manifiesto=man0, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r_ok["ok"] is True

    n_gen = 0
    n_noop = 0
    n_exec = 0
    blocked = 0
    breaches = 0
    exceptions = 0
    indeterminate = 0

    conteo_nodo: Dict[str, int] = defaultdict(int)
    conteo_frente: Dict[str, int] = defaultdict(int)
    matriz: Dict[Tuple[str, str], int] = defaultdict(int)
    breach_cases: List[Dict] = []

    meta = random.Random(MASTER_SEED)

    for i in range(N_ATACANTES):
        frente = elegir_frente(meta)
        atk = AtacanteCadena(i, MASTER_SEED, pub, datos0, man0, frente)
        assert atk.tiene_solo_publica()
        n_gen += 1
        conteo_frente[frente] += 1

        try:
            d, m, ops = GENERADORES[frente](atk.rng, atk.datos, atk.manifiesto)
            mismo_d = isinstance(d, (bytes, bytearray)) and bytes(d) == atk.datos
            mismo_m = isinstance(m, dict) and m == atk.manifiesto
            if mismo_d and mismo_m:
                n_noop += 1
                continue
            resultado = P.verificar(d, manifiesto=m, pub_bytes=atk.pub_bytes, modo=P.MODO_PROTEGIDO)
        except Exception:
            exceptions += 1
            continue

        n_exec += 1
        clase = clasificar(resultado, hostil=True)
        nodo, traj = nodo_detencion(resultado)

        if clase == "BREACH":
            breaches += 1
            breach_cases.append({
                "id": i, "seed": atk.seed, "frente": frente,
                "ops": ops, "nodo": nodo,
                "sid": atk.scenario_id("|".join(ops)),
            })
            continue

        if clase != "BLOCKED":
            indeterminate += 1
            continue

        blocked += 1
        conteo_nodo[nodo] += 1
        matriz[(frente, nodo)] += 1
        assert atk.tiene_solo_publica()

    upper = (3.0 / n_exec) if n_exec else 1.0

    lineas = [
        "",
        "=" * 64,
        "ESPARTACO CADENA / GRAFO DE CONSISTENCIA",
        "=" * 64,
        f"SPEC_ID={SPEC_ID}  REV={SPEC_REVISION}",
        f"MASTER_SEED={MASTER_SEED}",
        f"ATTACKERS_GENERATED  {n_gen}",
        f"NO_OP                {n_noop}",
        f"ATTACKS_EXECUTED     {n_exec}",
        f"BLOCKED              {blocked}",
        f"BREACH               {breaches}",
        f"EXCEPTION            {exceptions}",
        f"INDETERMINATE        {indeterminate}",
        "-" * 64,
        "GRAFO DE DEPENDENCIAS (aristas)",
        "-" * 64,
    ]
    for a, b in ARISTAS:
        lineas.append(f"  {a}  →  {b}")
    lineas.append("-" * 64)
    lineas.append("DONDE SE TRANCA EL ATACANTE (nodo de detención)")
    lineas.append("-" * 64)
    for n in ("datos", "manifiesto", "firma", "nucleo", "canales", "n_bytes", "aceptacion"):
        lineas.append(f"  {n:<16}{conteo_nodo.get(n, 0)}")
    lineas.append("-" * 64)
    lineas.append("MATRIZ  frente × nodo_detencion")
    hdr = f"{'FRENTE':<22}" + "".join(
        f"{n[:8]:>10}" for n in ("datos", "manifiesto", "firma", "nucleo", "canales", "n_bytes")
    )
    lineas.append(hdr)
    for f in FRENTES:
        row = f"{f:<22}"
        for n in ("datos", "manifiesto", "firma", "nucleo", "canales", "n_bytes"):
            row += f"{matriz.get((f, n), 0):>10}"
        lineas.append(row)
    lineas.append("-" * 64)
    lineas.append("COBERTURA POR FRENTE DE INTERCEPTACIÓN")
    for f in FRENTES:
        lineas.append(f"  {f:<22}{conteo_frente[f]}")
    lineas.append("-" * 64)
    lineas.append("LECTURA CAUSAL")
    lineas.append("  intercepta_byte/region/longitud → rompe datos→nucleo (firma PASS)")
    lineas.append("  intercepta_nucleo/S/Q/cuerpo    → rompe cuerpo→firma")
    lineas.append("  intercepta_firma / rearma       → rompe firma (sin privada no re-firma)")
    lineas.append("  pub_bytes permite VERIFICAR; no permite GENERAR firma Ed25519 nueva")
    lineas.append("-" * 64)
    lineas.append(f"EXECUTED={n_exec}  BREACH={breaches}  UPPER95≈{upper:.2e}")
    status = "PASS"
    if breaches or exceptions or indeterminate:
        status = "CRITICAL FAILURE" if breaches else "FAIL"
    lineas.append(f"STATUS: {status}")
    lineas.append("=" * 64)
    print("\n".join(lineas))

    assert exceptions == 0
    assert indeterminate == 0
    assert breaches == 0, f"BREACH: {breach_cases[:5]}"
    assert n_exec > 0
    assert conteo_nodo.get("nucleo", 0) > 0
    assert conteo_nodo.get("firma", 0) > 0

    r_final = P.verificar(datos0, manifiesto=man0, pub_bytes=pub, modo=P.MODO_PROTEGIDO)
    assert r_final["ok"] is True
