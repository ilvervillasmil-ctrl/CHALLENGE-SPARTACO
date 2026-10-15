# ===========================================================================
# SPARTACO-SECURITY — tests/test_acceso_adversarial.py  (v1.3)
# ===========================================================================
#
# ADVERSARIAL SUITE FOR
#     modules/spartaco_seguridad/acceso.py
#
# WHAT THIS FILE COVERS
# ---------------------------------------------------------------------------
#   Legitimate flow                must AUTHORIZE
#   Replay of the same nonce       must BLOCK with NONCE_REUSADO
#   Signature reuse on a different access request
#                                  must BLOCK under INTEGRIDAD_COMPROMETIDA
#                                  or FIRMA_INVALIDA
#   Future timestamp               must BLOCK with SOLICITUD_FUERA_DE_RELOJ
#   Expired TTL                    must BLOCK with SOLICITUD_EXPIRADA
#   Expired TTL does not consume   second attempt must still be
#                                  SOLICITUD_EXPIRADA, not NONCE_REUSADO
#   Missing policy                 must BLOCK with POLITICA_DENEGADA
#   Denied policy consumes nonce   second attempt with valid rules must
#                                  return NONCE_REUSADO
#   Storage-layer exception        must fail-closed with CODIGO_INVALIDO
#   Missing permissions            must BLOCK with POLITICA_DENEGADA
#   Race, 2 threads, same nonce    exactly 1 AUTORIZADO
#   Race, 20 threads, same nonce   exactly 1 AUTORIZADO, remainder
#                                  NONCE_REUSADO, sum = 20
#
# OBSERVABLE CONTRACT
# ---------------------------------------------------------------------------
# The module exposes two operations:
#
#   A.construir_solicitud(...)  -> {"ok": True, "solicitud": {...}}
#   A.verificar_acceso(...)     -> {"estado": ..., "conceptos": [...]}
#
# The verification result's `estado` is one of AUTORIZADO or BLOQUEADO.
# The `conceptos` list carries the specific rejection reason when blocked.
# A rejection without a specific concept is not accepted as PASS; the
# tests require the exact concept that corresponds to each failure mode.
#
# POLICY FIXTURE
# ---------------------------------------------------------------------------
# REGLA_OK declares a minimal policy:
#   resource "servidor-pagos", operation "debitar"
#   identity "cliente-1" with permission "debito.permitido"
# This policy is the reference against which every test verifies.
#
# TIME CONTROL
# ---------------------------------------------------------------------------
# Tests 03, 04 and 04b monkeypatch A._ahora_iso to simulate future and
# expired timestamps without waiting for real time. This makes the tests
# deterministic and fast, and it isolates the time checks from the
# clock of the host.
#
# ATOMICITY
# ---------------------------------------------------------------------------
# Tests 08 and 09 use a threading.Barrier to make N threads call
# verificar_acceso at the same instant with the same request. The
# contract requires exactly one AUTORIZADO. The rest must return
# NONCE_REUSADO. The test counts both and requires the sum to equal N,
# so a thread that returned something else would fail the test rather
# than being silently ignored.
#
# CONSUMPTION SEMANTICS
# ---------------------------------------------------------------------------
# The suite pins two architectural decisions in executable form:
#
#   test_04b  A TTL-expired request does NOT consume the nonce.
#             Consumption happens after the time checks.
#
#   test_05b  A policy-denied request DOES consume the nonce.
#             Once a request reaches the verification stage, the nonce
#             is spent regardless of whether the policy authorized it.
#             This is the fail-closed choice: the system prefers a
#             false negative (a denied request consumes a nonce) over
#             a false positive (a denied request leaves the nonce
#             available for a second attempt).
#
# STIMULUS SOURCE
# ---------------------------------------------------------------------------
# This file is the source of stimuli for other tests in the suite.
# test_monitoreo_diario.py imports the same construction and verification
# patterns to generate correlated telemetry. Changes to the fixtures or
# to the request shape here propagate to that observer, so this file is
# a maintenance reference for the rest of the suite.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It is not an audit of proteccion.py or credencial.py.
#   - It does not qualify an instrument.
#   - It does not persist evidence.
#   - It does not run a Monte Carlo.
#   - It does not certify the whole system: it certifies the observable
#     contract of acceso.py under the attacks listed above.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# This is the traditional adversarial file for the access module. It is
# shorter than the metrological auditors and does not carry doctrine
# beyond the fail-closed denial rule. It is the first file to read when
# learning the contract of acceso.py, and the reference for the stimuli
# that other observers reuse.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# A rejected request must be rejected by the contract, with the specific
# concept that corresponds to the failure mode. The nonce is consumed
# after the time checks and after the request reaches the verification
# stage, so fail-closed applies to the sequence, not only to the final
# decision. Under concurrency, exactly one authorization is granted for
# a single nonce.
#
# ===========================================================================
from __future__ import annotations

import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets   # solo en el archivo de test
sys.path.insert(0, str(Path(__file__).parent))

import pytest

from modules.spartaco_seguridad import proteccion as P
from modules.spartaco_seguridad import acceso as A

REGLA_OK = {
    "servidor-pagos": {
        "debitar": {
            "identidades": ["cliente-1"],
            "permisos_requeridos": ["debito.permitido"],
        }
    }
}


@pytest.fixture(scope="module")
def claves() -> tuple:
    tmp = Path(tempfile.mkdtemp(prefix="acceso_test_"))
    priv, pub = tmp / "priv.bin", tmp / "pub.bin"
    r = P.generar_claves(str(priv), str(pub))
    assert r.get("ok"), r
    return str(priv), pub.read_bytes()




def construir(priv: str, **kw) -> dict:
    base = dict(
        identidad="cliente-1",
        recurso="servidor-pagos",
        operacion="debitar",
        ruta_priv=priv,
        clave_publica_id="AUTORIDAD-1",
        permisos=["debito.permitido"],
        nonce=secrets.token_hex(16),   # 32 hex aleatorios, únicos por llamada
    )
    base.update(kw)
    return A.construir_solicitud(**base)

def verificar(solicitud: dict, pub: bytes, **kw) -> dict:
    return A.verificar_acceso(solicitud, pub_bytes=pub, reglas=REGLA_OK, **kw)


# ---------------------------------------------------------------- 00 flujo legÃ­timo
def test_00_flujo_legitimo_autoriza(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), f"construir_solicitud falla: {s}"
    v = verificar(s["solicitud"], pub)
    assert v["estado"] == A.AUTORIZADO, f"BUG: solicitud legitima bloqueada: {v}"


# ---------------------------------------------------------------- 01 replay
def test_01_replay_nonce_reusado(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    v1 = verificar(sol, pub)
    assert v1["estado"] == A.AUTORIZADO, v1
    v2 = verificar(sol, pub)
    assert v2["estado"] == A.BLOQUEADO and "NONCE_REUSADO" in v2["conceptos"], v2


# ---------------------------------------------------------------- 02 firma vÃ¡lida reusada en OTRO acceso
def test_02_firma_reusada_en_otro_acceso(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    # el atacante tiene un manifiesto VÃLIDO pero altera el dict 'acceso'
    # (mismo recurso/operacion, nonce distinto): el verificador debe bloquear
    # contrato v1.2: la solicitud transporta datos_firmados (bytes sellados)
    sol2 = {
        "acceso": {**sol["acceso"], "nonce": "f" * 32},
        "datos_firmados": sol["datos_firmados"],
        "manifiesto": sol["manifiesto"],
    }
    v = verificar(sol2, pub)
    assert v["estado"] == A.BLOQUEADO, v
    # el nÃºcleo del canÃ³nico del acceso alterado ya no cuadra con el cuerpo
    # firmado â†’ detenciÃ³n criptogrÃ¡fica (nucleo), no por forma
    assert "INTEGRIDAD_COMPROMETIDA" in v["conceptos"] or "FIRMA_INVALIDA" in v["conceptos"], v


# ---------------------------------------------------------------- 03 reloj futuro
def test_03_reloj_futuro_bloqueado(claves, monkeypatch):
    priv, pub = claves
    futura = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(A, "_ahora_iso", lambda: futura)
    s = construir(priv)
    assert s.get("ok"), s
    v = verificar(s["solicitud"], pub)
    assert v["estado"] == A.BLOQUEADO and "SOLICITUD_FUERA_DE_RELOJ" in v["conceptos"], v


# ---------------------------------------------------------------- 04 TTL expirado
def test_04_ttl_expirado_bloqueado(claves, monkeypatch):
    priv, pub = claves
    pasada = (datetime.now(timezone.utc) - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(A, "_ahora_iso", lambda: pasada)
    s = construir(priv)
    assert s.get("ok"), s
    v = verificar(s["solicitud"], pub)
    assert v["estado"] == A.BLOQUEADO and "SOLICITUD_EXPIRADA" in v["conceptos"], v


# ---------------------------------------------------------------- 04b TTL expirado no consume el nonce
def test_04b_ttl_expirado_no_consume(claves, monkeypatch):
    priv, pub = claves
    pasada = (datetime.now(timezone.utc) - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(A, "_ahora_iso", lambda: pasada)
    s = construir(priv)
    assert s.get("ok"), s
    v1 = verificar(s["solicitud"], pub)
    assert v1["estado"] == A.BLOQUEADO and "SOLICITUD_EXPIRADA" in v1["conceptos"], v1
    # se reenvÃ­a: sigue dando EXPIRADA (el consumo ocurre despuÃ©s del TTL)
    v2 = verificar(s["solicitud"], pub)
    assert v2["estado"] == A.BLOQUEADO and "SOLICITUD_EXPIRADA" in v2["conceptos"], v2


# ---------------------------------------------------------------- 05 polÃ­tica ausente
def test_05_politica_ausente_deniega(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s
    v = A.verificar_acceso(s["solicitud"], pub_bytes=pub, reglas={})
    assert v["estado"] == A.BLOQUEADO and "POLITICA_DENEGADA" in v["conceptos"], v


# ---------------------------------------------------------------- 05b polÃ­tica denegada CONSUME el nonce (C2)
def test_05b_politica_denegada_consume_nonce(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    v1 = A.verificar_acceso(sol, pub_bytes=pub, reglas={})
    assert v1["estado"] == A.BLOQUEADO and "POLITICA_DENEGADA" in v1["conceptos"], v1
    # el reenvÃ­o NO debe dar otra vez polÃ­tica: el nonce ya se consumiÃ³ (C2)
    v2 = A.verificar_acceso(sol, pub_bytes=pub, reglas=REGLA_OK)
    assert v2["estado"] == A.BLOQUEADO and "NONCE_REUSADO" in v2["conceptos"], v2


# ---------------------------------------------------------------- 06 almacÃ©n que lanza excepciÃ³n
def test_06_almacen_excepcion_fail_closed(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s

    class Rota:
        def visto(self, nonce):
            raise RuntimeError("boom")

        def registrar(self, nonce, *, expira_en):
            raise RuntimeError("boom")

        def consumir(self, nonce, *, expira_en):
            raise RuntimeError("boom")

    v = A.verificar_acceso(
        s["solicitud"], pub_bytes=pub, reglas=REGLA_OK, almacen_nonces=Rota()
    )
    assert v["estado"] == A.BLOQUEADO and "CODIGO_INVALIDO" in v["conceptos"], v


# ---------------------------------------------------------------- 07 permisos faltantes
def test_07_permisos_faltantes_deniega(claves):
    priv, pub = claves
    s = construir(priv, permisos=[])
    assert s.get("ok"), s
    v = verificar(s["solicitud"], pub)
    assert v["estado"] == A.BLOQUEADO and "POLITICA_DENEGADA" in v["conceptos"], v


# ---------------------------------------------------------------- 08 carrera 2 hilos mismo nonce
def test_08_mismo_nonce_paralelo_solo_uno_ok(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    barrier = threading.Barrier(2)
    resultados: list = []

    def worker():
        barrier.wait()
        resultados.append(A.verificar_acceso(sol, pub_bytes=pub, reglas=REGLA_OK))

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    n_ok = sum(1 for r in resultados if r["estado"] == A.AUTORIZADO)
    assert n_ok == 1, f"se esperaba exactamente 1 AUTORIZADO, hubo {n_ok}: {resultados}"


# ---------------------------------------------------------------- 09 carrera 20 hilos mismo nonce
def test_09_carrera_20_hilos_mismo_nonce(claves):
    priv, pub = claves
    s = construir(priv)
    assert s.get("ok"), s
    sol = s["solicitud"]
    n = 20
    barrier = threading.Barrier(n)
    resultados: list = []

    def worker():
        barrier.wait()
        resultados.append(A.verificar_acceso(sol, pub_bytes=pub, reglas=REGLA_OK))

    hilos = [threading.Thread(target=worker) for _ in range(n)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    n_ok = sum(1 for r in resultados if r["estado"] == A.AUTORIZADO)
    n_replay = sum(1 for r in resultados if "NONCE_REUSADO" in r["conceptos"])
    assert n_ok == 1, f"atomicidad rota: {n_ok} AUTORIZADOS para el mismo nonce"
    assert n_ok + n_replay == n, f"veredictos inesperados: {resultados}"
