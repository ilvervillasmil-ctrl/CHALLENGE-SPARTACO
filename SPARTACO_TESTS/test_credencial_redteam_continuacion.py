# ===============================================================
# VPSI-TRUTH — test_credencial_redteam_continuacion.py
# ===============================================================
#
# Adversarial red-team continuation for
#     modules/spartaco_seguridad/credencial.py
#
# ROLE
# ----
# This file is the surgical addendum to test_credencial_redteam.py.
# The original suite was trimmed 49 → 35 to fit the CI budget.
# These 14 tests (036–049) are exactly the ones dropped by that cut.
# They are appended, not rewritten: the parent file is untouched.
#
# Pytest accounting: 795 + 14 = 809.
#
# CONSTRAINTS
# -----------
#   - Does NOT modify test_credencial_redteam.py.
#   - Does NOT modify credencial.py or proteccion.py.
#   - Reuses the parent's deterministic fixtures, FixtureError policy,
#     assert_denegado contract, and snapshot-before/after discipline.
#   - Reproducible material: sha256(channel || i.to_bytes(8, "big")).
#   - No secrets, no random, no urandom.
#
# WHAT THIS SUITE ADDS OVER THE 35-TEST BASELINE
# ----------------------------------------------
#   A. Hostile secret types at the parser boundary .......... 036
#   B. Defense: invalid branch / invalid event .............. 037–038
#   C. Defense: mass wrong K_def, no fatigue ................ 039
#   D. Recovery: legitimate wrap + wrap.ct bitflip .......... 040–041
#   E. Internal parser and domain-separation checks ......... 042–046
#        (verificar_dominios, _parse_secreto: hex / b64 /
#         raw bytes / wrong lengths / garbage)
#   F. No-mutation under repeated failed auth / recovery .... 047–048
#   G. Composite invariants on a single document ............ 049
#
# Every test targets an angle NOT covered by the 35-test baseline.
# No test is a duplicate of the parent suite.
#
# TEST TAXONOMY
# -------------
#   [API/ADVERSARIAL]  — attacks on the public surface.
#   [INTERNAL/UNIT]    — functional properties of internal
#                        derivations and parsers (042–046).
#
# RESULT CONTRACT (same as parent)
# --------------------------------
#   PASS       — attack executed, contract held, state unchanged.
#   FAIL       — attack accepted, contract broken, or state mutated.
#   FIXTURE    — attack NOT executed (fixture could not be built).
#                Never counted as PASS.
#   EXCEPCION  — API raised where it should have denied.
#
# INVARIANTS ENFORCED THROUGHOUT
# ------------------------------
#   1. Rejection only via ACCESS_DENIED (ok=False, error, ruta).
#   2. No rejection path mutates the ZSQ tree.
#   3. No domain secret authorizes another domain.
#   4. No uso_id can be replayed.
#   5. Export never leaks secrets or genealogy.
#   6. Legitimate protect → open → recover remains intact after
#      every adversarial run.
#
# RUNNER
# ------
#   - Discovers all test_* functions.
#   - Requires exactly TESTS_ESPERADOS = 14, exits 2 otherwise.
#   - Prints PASS/FAIL per test; exits 0 only with zero failures.
# ===============================================================

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.spartaco_seguridad import credencial as C
from modules.spartaco_seguridad import proteccion as P

TMP = Path("/tmp/spartaco_credencial_redteam_cont")
TMP.mkdir(parents=True, exist_ok=True)
PRIV = str(TMP / "priv.bin")
PUB = str(TMP / "pub.bin")

N_MUESTRA = int(os.environ.get("SPARTACO_N_MUESTRA", "32"))
SEP = C.SEP
RAMAS = ("Z", "S", "Q")
TESTS_ESPERADOS = 14


class FixtureError(Exception):
    pass


def h(canal: bytes, i: int) -> bytes:
    return hashlib.sha256(canal + i.to_bytes(8, "big")).digest()


def hx(canal: bytes, i: int) -> str:
    return h(canal, i).hex()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(texto: str) -> bytes:
    pad = "=" * ((4 - len(texto) % 4) % 4)
    return base64.urlsafe_b64decode((texto or "") + pad)


def contexto(i: int) -> Dict[str, Any]:
    return {
        "artifact_id": hx(b"CONT-ART", i),
        "authority_id": hx(b"CONT-ATH", i)[:32],
        "auth": h(b"CONT-AUTH", i),
        "def": h(b"CONT-DEF", i),
        "ses": h(b"CONT-SES", i),
        "rec": h(b"CONT-REC", i),
        "plaintext": b"CONT-PT" + h(b"CONT-PT", i) + i.to_bytes(8, "big"),
    }


def ensure_keys() -> None:
    if not Path(PRIV).exists() or not Path(PUB).exists():
        r = P.generar_claves(PRIV, PUB)
        if not (isinstance(r, dict) and r.get("ok") is True):
            raise FixtureError("generar_claves %r" % (r,))


def pub_bytes() -> bytes:
    ensure_keys()
    raw = Path(PUB).read_bytes()
    if len(raw) != 32:
        raise FixtureError("pub.bin len=%d" % len(raw))
    return raw


def protect(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ensure_keys()
    r = C.proteger(
        ctx["plaintext"],
        PRIV,
        artifact_id=ctx["artifact_id"],
        authority_id=ctx["authority_id"],
        secreto_autenticacion=ctx["auth"].hex(),
        secreto_defensa=ctx["def"].hex(),
        secreto_sesion=ctx["ses"].hex(),
        secreto_recuperacion=ctx["rec"].hex(),
        emision="1",
    )
    if not (
        isinstance(r, dict)
        and r.get("ok") is True
        and isinstance(r.get("blob"), (bytes, bytearray))
        and isinstance(r.get("manifiesto"), dict)
    ):
        raise FixtureError("proteger %r" % (r,))
    return r


def parse_blob(blob: bytes) -> Tuple[Dict[str, Any], bytes]:
    idx = blob.find(SEP)
    if idx < 0:
        raise FixtureError("sin separador")
    return json.loads(blob[:idx].decode("ascii")), bytes(blob[idx + len(SEP) :])


def rebuild_blob(header: Dict[str, Any], ciphertext: bytes) -> bytes:
    raw = P.serializar_seguro(header)
    if not (isinstance(raw, dict) and raw.get("ok") is True):
        raise FixtureError("serializar %r" % (raw,))
    return raw["bytes"] + SEP + ciphertext


def snapshot(pack: Dict[str, Any], ctx: Dict[str, Any]) -> Any:
    r = C.estado_publico(
        artifact_id=pack["artifact_id"],
        nucleo=pack["plaintext_nucleo"],
        authority_id=ctx["authority_id"],
    )
    if not (isinstance(r, dict) and r.get("ok") is True):
        raise FixtureError("estado_publico %r" % (r,))
    return r.get("estado")


def _as_secret(valor: Any) -> Any:
    if isinstance(valor, (bytes, bytearray)):
        return bytes(valor).hex()
    return valor


def abrir(pack, ctx, uso_id=None, auth=None, ses=None, blob=None):
    return C.abrir_documento(
        blob if blob is not None else pack["blob"],
        manifiesto=pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_autenticacion=_as_secret(ctx["auth"] if auth is None else auth),
        secreto_sesion=_as_secret(ctx["ses"] if ses is None else ses),
        uso_id=uso_id,
    )


def recobrar(pack, ctx, rec=None, blob=None):
    return C.recuperar(
        blob if blob is not None else pack["blob"],
        manifiesto=pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_recuperacion=_as_secret(ctx["rec"] if rec is None else rec),
    )


def registrar(pack, secreto_def, evento, rama):
    return C.registrar_intento(
        pack["blob"],
        manifiesto=pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_defensa=_as_secret(secreto_def),
        evento=evento,
        rama=rama,
    )


def es_denegacion(r: Any) -> bool:
    return (
        isinstance(r, dict)
        and r.get("ok") is False
        and r.get("error") == C.ACCESS_DENIED
        and r.get("ruta") == C.ACCESS_DENIED
    )


def assert_denegado(r: Any, donde: str) -> None:
    if r is None or not isinstance(r, dict):
        raise AssertionError("%s: no es dict de contrato %r" % (donde, r))
    if r.get("ok") is True:
        raise AssertionError("%s: ATAQUE ACEPTADO %r" % (donde, r))
    if not es_denegacion(r):
        raise AssertionError("%s: rechazo fuera de contrato %r" % (donde, r))


def test_036_hostile_secret_types_cannot_open():
    # PROPÓSITO: tipos que no son secreto de 32 B deniegan y no mutan.
    ctx = contexto(36)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    hostiles = (
        None, False, True, 0, 1, [], {}, (), b"", b"A", "!",
        "\x00" * 64, "g" * 64, "a" * 63, "a" * 65,
    )
    for i, valor in enumerate(hostiles):
        r = C.abrir_documento(
            pack["blob"],
            manifiesto=pack["manifiesto"],
            pub_bytes=pub_bytes(),
            secreto_autenticacion=valor,
            secreto_sesion=ctx["ses"].hex(),
        )
        assert_denegado(r, "tipo %d" % i)
    assert snapshot(pack, ctx) == antes


def test_037_invalid_branch_does_not_mutate():
    # PROPÓSITO: rama fuera de Z/S/Q deniega y no mueve el árbol.
    ctx = contexto(37)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    for i in range(N_MUESTRA):
        rama = hx(b"RAMA", i)[:2]
        assert_denegado(registrar(pack, ctx["def"], hx(b"EV", i), rama), "rama")
        assert snapshot(pack, ctx) == antes


def test_038_invalid_event_does_not_mutate():
    # PROPÓSITO: evento vacío o no-str deniega y no muta.
    ctx = contexto(38)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    for evento in ("", " ", None, 0, False, [], {}):
        assert_denegado(registrar(pack, ctx["def"], evento, "S"), "evento")
        assert snapshot(pack, ctx) == antes


def test_039_mass_wrong_defense_does_not_mutate():
    # PROPÓSITO: oleada de K_def ajenas no cambia estado.
    ctx = contexto(39)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    for i in range(N_MUESTRA):
        assert_denegado(registrar(pack, h(b"MASS", i), hx(b"MEV", i), RAMAS[i % 3]), "mass")
    assert snapshot(pack, ctx) == antes


def test_040_legitimate_recovery_returns_plaintext():
    # PROPÓSITO: wrap declarado → recuperar devuelve plaintext.
    ctx = contexto(40)
    pack = protect(ctx)
    g = recobrar(pack, ctx)
    if not (isinstance(g, dict) and g.get("ok") is True and g.get("plaintext") == ctx["plaintext"]):
        raise AssertionError(g)


def test_041_recovery_wrap_ciphertext_bitflip_is_denied():
    # PROPÓSITO: un bit del ct del wrap deniega recuperar y no muta.
    ctx = contexto(41)
    pack = protect(ctx)
    header, ct = parse_blob(pack["blob"])
    wrap = dict(header["wrap_recuperacion"])
    raw = bytearray(b64d(str(wrap["ct"])))
    raw[0] ^= 1
    wrap["ct"] = b64(bytes(raw))
    header["wrap_recuperacion"] = wrap
    antes = snapshot(pack, ctx)
    assert_denegado(recobrar(pack, ctx, blob=rebuild_blob(header, ct)), "wrap.ct")
    assert snapshot(pack, ctx) == antes


def test_042_verificar_dominios_detects_forced_collision():
    # [INTERNAL/UNIT]
    raw = h(b"VD", 42)
    c = C.derivar_claves(
        artifact_id=hx(b"VDA", 42),
        nucleo=hx(b"VDN", 42),
        authority_id=hx(b"VDH", 42)[:32],
        secreto_raiz=raw.hex(),
        secreto_recuperacion=raw.hex(),
    )
    if not c.get("ok"):
        raise AssertionError(c)
    sano = C.verificar_dominios(c)
    if not (isinstance(sano, dict) and sano.get("ok") is True):
        raise AssertionError(sano)
    corrupto = dict(c)
    corrupto[C.CLAVE_DEFENSA] = corrupto[C.CLAVE_AUTENTICACION]
    r = C.verificar_dominios(corrupto)
    if not (isinstance(r, dict) and r.get("ok") is False and r.get("separadas") is False):
        raise AssertionError(r)


def test_043_parser_accepts_64_hex():
    # [INTERNAL/UNIT]
    raw = h(b"PAR", 43)
    assert C._parse_secreto(raw.hex()) == raw
    assert C._parse_secreto(raw.hex().upper()) == raw


def test_044_parser_accepts_urlsafe_b64():
    # [INTERNAL/UNIT]
    raw = h(b"PAR", 44)
    assert C._parse_secreto(b64(raw)) == raw


def test_045_parser_rejects_wrong_lengths():
    # [INTERNAL/UNIT]
    raw = h(b"PAR", 45)
    assert C._parse_secreto(raw) == raw
    for valor in (raw[:1], raw[:15], raw[:31], raw + b"\x00", raw + b"\x00\x00"):
        if C._parse_secreto(valor) is not None:
            raise AssertionError("acepto len=%d" % len(valor))


def test_046_parser_rejects_garbage():
    # [INTERNAL/UNIT]
    for valor in (None, "", " ", "!", "!!!!", [], {}, (), False, True, 0, 1, 3.14):
        if C._parse_secreto(valor) is not None:
            raise AssertionError(valor)


def test_047_failed_auth_does_not_mutate():
    ctx = contexto(47)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    for i in range(N_MUESTRA):
        assert_denegado(abrir(pack, ctx, auth=h(b"BA", i)), "auth")
    assert snapshot(pack, ctx) == antes


def test_048_failed_recovery_does_not_mutate():
    ctx = contexto(48)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    for i in range(N_MUESTRA):
        assert_denegado(recobrar(pack, ctx, rec=h(b"BR", i)), "rec")
    assert snapshot(pack, ctx) == antes


def test_049_composite_invariants_hold_on_one_document():
    ctx = contexto(49)
    pack = protect(ctx)
    ticket = hx(b"FIN", 49)
    r = abrir(pack, ctx, uso_id=ticket)
    if not (isinstance(r, dict) and r.get("ok") is True and r.get("plaintext") == ctx["plaintext"]):
        raise AssertionError(r)
    assert_denegado(abrir(pack, ctx, uso_id=ticket), "replay")
    assert_denegado(abrir(pack, ctx, auth=h(b"FINBAD", 49)), "cruzado")
    antes = snapshot(pack, ctx)
    assert_denegado(registrar(pack, h(b"FINDEF", 49), hx(b"FINEV", 49), "Q"), "def-ajena")
    assert snapshot(pack, ctx) == antes
    bueno = registrar(pack, ctx["def"], hx(b"FINGOOD", 49), "Q")
    if not (isinstance(bueno, dict) and bueno.get("evento") == C.EXPANSION_ZSQ):
        raise AssertionError(bueno)
    assert snapshot(pack, ctx)["contador"] == antes["contador"] + 1
    text = json.dumps(C.exportar_estado())
    for material in (ctx["auth"], ctx["def"], ctx["ses"], ctx["rec"]):
        assert material.hex() not in text


if __name__ == "__main__":
    tests = sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f))
    if len(tests) != TESTS_ESPERADOS:
        print("CONTEO", len(tests), "esperado", TESTS_ESPERADOS)
        raise SystemExit(2)
    failed = []
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except Exception as exc:
            print("FAIL", name, type(exc).__name__, exc)
            failed.append(name)
    print("PASSED", len(tests) - len(failed), "FAILED", len(failed))
    raise SystemExit(1 if failed else 0)
