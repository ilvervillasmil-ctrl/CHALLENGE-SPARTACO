# ===============================================================
# VPSI-TRUTH — test_credencial_redteam.py
# ===============================================================
#
# Red-team adversarial de modules/spartaco_seguridad/credencial.py
# "EL MONTECARLO SE HIZO DE 10 MILLONES PERO POR PRACTICIDAD Y TIEMPO SE MANTIENE 
# EN 100 ATAQUES y 10 DOC 
# NO modifica credencial.py ni proteccion.py.
# NO convierte un fixture roto en ACCESS_DENIED.
# NO usa la función bajo prueba como oráculo de sí misma
#     (salvo tests marcados [INTERNAL/UNIT]).
#
# Semilla reproducible: sha256(canal || i.to_bytes(8, "big"))
# ===============================================================

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.spartaco_seguridad import credencial as C
from modules.spartaco_seguridad import proteccion as P


# ===============================================================
# A. FIXTURES Y GENERACIÓN DETERMINISTA
# ===============================================================
#
# Todo lo de esta sección PREPARA entradas.
# Nada de aquí afirma una propiedad de seguridad.
# Si C.proteger() falla, se aborta el test: el ataque no se ejecutó.
# ===============================================================

TMP = Path("/tmp/spartaco_credencial_redteam")
TMP.mkdir(parents=True, exist_ok=True)
PRIV = str(TMP / "priv.bin")
PUB = str(TMP / "pub.bin")

N_MUESTRA = int(os.environ.get("SPARTACO_N_MUESTRA", "32"))
MONTECARLO_KDF = int(os.environ.get("SPARTACO_MC_KDF", "100"))
MONTECARLO_DOCUMENTOS = int(os.environ.get("SPARTACO_MC_DOCUMENTOS", "10"))

SEP = C.SEP
RAMAS = ("Z", "S", "Q")
TESTS_ESPERADOS = 35


class FixtureError(Exception):
    """C.proteger() no construyó un documento. El ataque no llegó a correr."""


def h(canal: bytes, i: int) -> bytes:
    """Material determinista. No es un oráculo de credencial."""
    return hashlib.sha256(canal + i.to_bytes(8, "big")).digest()


def hx(canal: bytes, i: int) -> str:
    return h(canal, i).hex()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(texto: str) -> bytes:
    pad = "=" * ((4 - len(texto) % 4) % 4)
    return base64.urlsafe_b64decode((texto or "") + pad)


def contexto(i: int) -> Dict[str, Any]:
    """Entradas del documento i. No llama a credencial."""
    return {
        "artifact_id": hx(b"ART", i),
        "authority_id": hx(b"ATH", i)[:32],
        "auth": h(b"AUTH", i),
        "def": h(b"DEF", i),
        "ses": h(b"SES", i),
        "rec": h(b"REC", i),
        "raiz": h(b"ROOT", i),
        "plaintext": b"PT" + h(b"PT", i) + i.to_bytes(8, "big"),
    }


def ensure_keys() -> None:
    """Crea el par Ed25519 si /tmp está vacío. No valida el sobre."""
    if not Path(PRIV).exists() or not Path(PUB).exists():
        r = P.generar_claves(PRIV, PUB)
        if not (isinstance(r, dict) and r.get("ok") is True):
            raise FixtureError("generar_claves fallo: %r" % (r,))


def pub_bytes() -> bytes:
    ensure_keys()
    raw = Path(PUB).read_bytes()
    if len(raw) != 32:
        raise FixtureError("pub.bin invalido len=%d" % len(raw))
    return raw


def protect(ctx: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    """
    Fixture legítimo: pide a C.proteger un documento válido.

    NO valida ataques.
    Si proteger() no devuelve ok+blob+manifiesto, lanza FixtureError
    con la respuesta original. Nunca se traduce a ACCESS_DENIED.
    """
    ensure_keys()
    kwargs = {
        "artifact_id": ctx["artifact_id"],
        "authority_id": ctx["authority_id"],
        "secreto_autenticacion": ctx["auth"].hex(),
        "secreto_defensa": ctx["def"].hex(),
        "secreto_sesion": ctx["ses"].hex(),
        "secreto_recuperacion": ctx["rec"].hex(),
        "emision": "1",
    }
    kwargs.update(extra)
    r = C.proteger(ctx["plaintext"], PRIV, **kwargs)
    if not (
        isinstance(r, dict)
        and r.get("ok") is True
        and isinstance(r.get("blob"), (bytes, bytearray))
        and isinstance(r.get("manifiesto"), dict)
    ):
        raise FixtureError("proteger no construyo documento: %r" % (r,))
    return r


def parse_blob(blob: bytes) -> Tuple[Dict[str, Any], bytes]:
    """
    Parte el sobre por el separador público C.SEP + JSON.
    No usa C._parse_sobre. Solo inspecciona para mutar bytes.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise FixtureError("blob no es bytes")
    idx = blob.find(SEP)
    if idx < 0:
        raise FixtureError("blob sin separador")
    header = json.loads(blob[:idx].decode("ascii"))
    return header, bytes(blob[idx + len(SEP) :])


def rebuild_blob(header: Dict[str, Any], ciphertext: bytes) -> bytes:
    """Reconstruye bytes del sobre. No afirma autenticidad."""
    raw = P.serializar_seguro(header)
    if not (isinstance(raw, dict) and raw.get("ok") is True):
        raise FixtureError("serializar_seguro fallo: %r" % (raw,))
    return raw["bytes"] + SEP + ciphertext


def snapshot(pack: Dict[str, Any], ctx: Dict[str, Any]) -> Any:
    """Foto pública del estado. No es un ataque."""
    r = C.estado_publico(
        artifact_id=pack["artifact_id"],
        nucleo=pack["plaintext_nucleo"],
        authority_id=ctx["authority_id"],
    )
    if not isinstance(r, dict) or r.get("ok") is not True:
        raise FixtureError("estado_publico invalido: %r" % (r,))
    return r.get("estado")


def _as_secret(valor: Any) -> Any:
    if isinstance(valor, (bytes, bytearray)):
        return bytes(valor).hex()
    return valor


def abrir(pack, ctx, uso_id=None, auth=None, ses=None, blob=None, manifiesto=None):
    """Llama la API pública. Devuelve la respuesta cruda. No interpreta."""
    return C.abrir_documento(
        blob if blob is not None else pack["blob"],
        manifiesto=manifiesto if manifiesto is not None else pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_autenticacion=_as_secret(ctx["auth"] if auth is None else auth),
        secreto_sesion=_as_secret(ctx["ses"] if ses is None else ses),
        uso_id=uso_id,
    )


def recobrar(pack, ctx, rec=None, blob=None, manifiesto=None):
    return C.recuperar(
        blob if blob is not None else pack["blob"],
        manifiesto=manifiesto if manifiesto is not None else pack["manifiesto"],
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
    """
    Denegación esperada del contrato.
    None / excepción / dict corrupto / ok=True → FAIL, no PASS.
    """
    if r is None:
        raise AssertionError("%s: None, no es denegacion de contrato" % donde)
    if not isinstance(r, dict):
        raise AssertionError("%s: tipo inesperado %s valor=%r" % (donde, type(r), r))
    if r.get("ok") is True:
        raise AssertionError("%s: ATAQUE ACEPTADO %r" % (donde, r))
    if not es_denegacion(r):
        raise AssertionError("%s: rechazo fuera de contrato %r" % (donde, r))


def assert_abierto(r: Any, plaintext: bytes, donde: str) -> None:
    if not (isinstance(r, dict) and r.get("ok") is True):
        raise AssertionError("%s: apertura legitima fallo %r" % (donde, r))
    if r.get("plaintext") != plaintext:
        raise AssertionError("%s: plaintext distinto" % donde)


# ===============================================================
# B. INTEGRIDAD DEL CIPHERTEXT
# [API/ADVERSARIAL]
# Mutación exclusiva del ciphertext. El header no se toca.
# ===============================================================

def test_002_ciphertext_bitflip_is_denied():
    # PROPÓSITO: un byte del ciphertext cambiado no abre ni muta estado.
    ctx = contexto(2)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    header, ct = parse_blob(pack["blob"])
    pos = int.from_bytes(h(b"POS", 2)[:2], "big") % len(ct)
    mut = bytearray(ct)
    mut[pos] ^= 1 + (h(b"XOR", 2)[0] % 255)
    r = abrir(pack, ctx, blob=rebuild_blob(header, bytes(mut)))
    assert_denegado(r, "bitflip pos=%d" % pos)
    assert snapshot(pack, ctx) == antes


def test_003_ciphertext_every_byte_flip_is_denied():
    # PROPÓSITO: cada posición del ciphertext, bitflip, deniega.
    ctx = contexto(3)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    header, ct = parse_blob(pack["blob"])
    for i in range(min(len(ct), 64)):
        mut = bytearray(ct)
        mut[i] ^= 1
        r = abrir(pack, ctx, blob=rebuild_blob(header, bytes(mut)))
        assert_denegado(r, "byte %d" % i)
    assert snapshot(pack, ctx) == antes


# ===============================================================
# C. INTEGRIDAD DEL HEADER Y DEL SOBRE
# [API/ADVERSARIAL]
# Se muta el JSON del header o el wrap, no el plaintext.
# ===============================================================

def test_004_live_header_field_mutation_is_denied():
    # PROPÓSITO: alterar cualquier campo vivo del header impide abrir
    # y no muta el estado ZSQ.
    ctx = contexto(4)
    pack = protect(ctx)
    header, ct = parse_blob(pack["blob"])
    antes = snapshot(pack, ctx)
    for campo, valor in list(header.items()):
        if campo == "wrap_recuperacion":
            continue
        sucio = dict(header)
        if isinstance(valor, str):
            sucio[campo] = hx(b"MUT-" + campo.encode(), 4)
        elif isinstance(valor, int):
            sucio[campo] = valor + 1 + (h(b"INT", 4)[0] % 7)
        else:
            sucio[campo] = hx(b"MUT", 4)
        r = abrir(pack, ctx, blob=rebuild_blob(sucio, ct))
        assert_denegado(r, "header.%s" % campo)
        assert snapshot(pack, ctx) == antes, campo


def test_005_recovery_wrap_mutation_is_denied():
    # PROPÓSITO: mutar nonce o ct del wrap impide recuperar.
    ctx = contexto(5)
    pack = protect(ctx)
    header, ct = parse_blob(pack["blob"])
    if "wrap_recuperacion" not in header:
        raise AssertionError("fixture: se pidio recuperacion y no hay wrap")
    wrap = dict(header["wrap_recuperacion"])
    antes = snapshot(pack, ctx)
    for campo in list(wrap.keys()):
        sucio = dict(wrap)
        raw = bytearray(b64d(str(wrap[campo])))
        raw[0] ^= 1
        sucio[campo] = b64(bytes(raw))
        h2 = dict(header)
        h2["wrap_recuperacion"] = sucio
        r = recobrar(pack, ctx, blob=rebuild_blob(h2, ct))
        assert_denegado(r, "wrap.%s" % campo)
    assert snapshot(pack, ctx) == antes


# ===============================================================
# D. SEPARACIÓN DE SECRETOS / DOMINIOS
# [API/ADVERSARIAL] salvo 029/030 [INTERNAL/UNIT] de derivación
# Un secreto de un dominio no autoriza otro dominio.
# ===============================================================

def test_006_auth_secret_cannot_expand_defense():
    # PROPÓSITO: K_auth no registra defensa ni mueve el árbol.
    ctx = contexto(6)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    r = registrar(pack, ctx["auth"], hx(b"EV", 6), "S")
    assert_denegado(r, "auth-as-def")
    assert snapshot(pack, ctx) == antes


def test_007_defense_secret_cannot_open():
    # PROPÓSITO: K_def no abre el documento.
    ctx = contexto(7)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    assert_denegado(abrir(pack, ctx, auth=ctx["def"]), "def-as-auth")
    assert snapshot(pack, ctx) == antes


def test_008_session_secret_cannot_authenticate():
    # PROPÓSITO: K_doc/sesión no autentica la apertura.
    ctx = contexto(8)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    assert_denegado(abrir(pack, ctx, auth=ctx["ses"]), "ses-as-auth")
    assert snapshot(pack, ctx) == antes


def test_009_recovery_secret_cannot_authenticate():
    # PROPÓSITO: K_rec no autentica la apertura.
    ctx = contexto(9)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    assert_denegado(abrir(pack, ctx, auth=ctx["rec"]), "rec-as-auth")
    assert snapshot(pack, ctx) == antes


def test_010_auth_secret_cannot_recover():
    # PROPÓSITO: K_auth no desenvuelve la recuperación.
    ctx = contexto(10)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    assert_denegado(recobrar(pack, ctx, rec=ctx["auth"]), "auth-as-rec")
    assert snapshot(pack, ctx) == antes


def test_029_same_ikm_yields_distinct_domain_keys():
    # [INTERNAL/UNIT]
    # PROPÓSITO: el mismo IKM bajo labels distintos no produce la misma clave.
    # No es un ataque externo.
    raw = h(b"DOM", 30)
    c = C.derivar_claves(
        artifact_id=hx(b"CA", 30),
        nucleo=hx(b"CN", 30),
        authority_id=hx(b"CH", 30)[:32],
        secreto_raiz=raw.hex(),
        secreto_recuperacion=raw.hex(),
    )
    if not (isinstance(c, dict) and c.get("ok") is True):
        raise AssertionError("derivar_claves fallo %r" % (c,))
    s = {c[C.CLAVE_AUTENTICACION], c[C.CLAVE_DEFENSA], c[C.CLAVE_CIFRADO_DOCUMENTO], c[C.CLAVE_RECUPERACION]}
    assert len(s) == 4


def test_030_context_change_changes_all_derived_domains():
    # [INTERNAL/UNIT]
    # PROPÓSITO: cambiar artifact_id cambia las cuatro claves derivadas.
    raw = h(b"CTX", 31)
    comun = dict(
        nucleo=hx(b"CN", 31),
        authority_id=hx(b"CH", 31)[:32],
        secreto_raiz=raw.hex(),
        secreto_recuperacion=raw.hex(),
    )
    a = C.derivar_claves(artifact_id=hx(b"CA", 31), **comun)
    b = C.derivar_claves(artifact_id=hx(b"CA", 32), **comun)
    if not (a.get("ok") and b.get("ok")):
        raise AssertionError((a, b))
    for nombre in (C.CLAVE_AUTENTICACION, C.CLAVE_DEFENSA, C.CLAVE_CIFRADO_DOCUMENTO, C.CLAVE_RECUPERACION):
        assert a[nombre] != b[nombre], nombre


# ===============================================================
# E. BINDING DOCUMENTO / CONTEXTO / MANIFIESTO
# [API/ADVERSARIAL]
# ===============================================================

def test_011_foreign_credentials_cannot_open_document():
    # PROPÓSITO: credenciales del documento i no abren el documento j.
    a, b = contexto(11), contexto(12)
    pa, pb = protect(a), protect(b)
    assert_denegado(abrir(pb, a), "creds-a sobre blob-b")
    assert_denegado(abrir(pa, b), "creds-b sobre blob-a")


def test_012_foreign_recovery_cannot_unwrap():
    # PROPÓSITO: K_rec de j no recupera el documento i.
    a, b = contexto(13), contexto(14)
    pa, pb = protect(a), protect(b)
    assert_denegado(recobrar(pa, a, rec=b["rec"]), "rec-b sobre a")
    assert_denegado(recobrar(pb, b, rec=a["rec"]), "rec-a sobre b")


def test_013_foreign_manifest_cannot_authorize():
    # PROPÓSITO: el manifiesto de j no autoriza el blob de i.
    a, b = contexto(15), contexto(16)
    pa, pb = protect(a), protect(b)
    assert_denegado(abrir(pa, a, manifiesto=pb["manifiesto"]), "manifiesto cruzado")


def test_014_tampered_manifest_field_is_denied():
    # PROPÓSITO: alterar artifact_id del manifiesto deniega y no muta.
    ctx = contexto(17)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    man = dict(pack["manifiesto"])
    cuerpo = dict(man["cuerpo"])
    cuerpo["artifact_id"] = hx(b"ATT", 17)
    man["cuerpo"] = cuerpo
    assert_denegado(abrir(pack, ctx, manifiesto=man), "manifiesto.artifact_id")
    assert snapshot(pack, ctx) == antes


# ===============================================================
# F. ANTI-REPLAY Y CONSUMO ÚNICO
# [API/ADVERSARIAL]
# El mismo uso lógico no se reutiliza, ni en hex ni en base64.
# ===============================================================

def test_015_usage_ticket_is_single_use():
    # PROPÓSITO: el primer uso_id abre; el segundo deniega.
    ctx = contexto(18)
    pack = protect(ctx)
    ticket = hx(b"TCK", 18)
    assert_abierto(abrir(pack, ctx, uso_id=ticket), ctx["plaintext"], "primer uso")
    assert_denegado(abrir(pack, ctx, uso_id=ticket), "replay")


def test_016_equivalent_encoding_cannot_replay_ticket():
    # PROPÓSITO: el mismo ticket no se recicla presentando el secreto en b64.
    ctx = contexto(19)
    pack = protect(ctx)
    ticket = hx(b"TCK", 19)
    assert_abierto(abrir(pack, ctx, uso_id=ticket), ctx["plaintext"], "primer uso")
    r = C.abrir_documento(
        pack["blob"],
        manifiesto=pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_autenticacion=b64(ctx["auth"]),
        secreto_sesion=b64(ctx["ses"]),
        uso_id=ticket,
    )
    assert_denegado(r, "replay b64")


# ===============================================================
# G. CONCURRENCIA Y ATOMICIDAD
# [API/ADVERSARIAL]
# Un ticket → una autorización. Defensa concurrente no pierde golpes.
# ===============================================================

def test_017_concurrent_ticket_exactly_one_success():
    # PROPÓSITO: 2 hilos, mismo uso_id → 1 ok y 1 denegado.
    ctx = contexto(20)
    pack = protect(ctx)
    ticket = hx(b"RACE", 20)

    def worker(_):
        return abrir(pack, ctx, uso_id=ticket)

    with ThreadPoolExecutor(max_workers=2) as ex:
        res = list(ex.map(worker, range(2)))
    oks = [r for r in res if isinstance(r, dict) and r.get("ok") is True]
    dens = [r for r in res if es_denegacion(r)]
    if len(oks) + len(dens) != 2:
        raise AssertionError("respuesta fuera de contrato: %r" % res)
    assert len(oks) == 1 and len(dens) == 1


def test_018_concurrent_ticket_32_exactly_one_success():
    # PROPÓSITO: 32 hilos, mismo uso_id → 1 ok y 31 denegados.
    ctx = contexto(21)
    pack = protect(ctx)
    ticket = hx(b"RACE", 21)

    def worker(_):
        return abrir(pack, ctx, uso_id=ticket)

    with ThreadPoolExecutor(max_workers=32) as ex:
        res = list(ex.map(worker, range(32)))
    oks = sum(1 for r in res if isinstance(r, dict) and r.get("ok") is True)
    dens = sum(1 for r in res if es_denegacion(r))
    if oks + dens != 32:
        raise AssertionError("respuesta fuera de contrato oks=%d dens=%d" % (oks, dens))
    assert oks == 1 and dens == 31


def test_021_concurrent_defense_does_not_drop_updates():
    # PROPÓSITO: 20 expansiones concurrentes → contador=20 nivel=20.
    ctx = contexto(24)
    pack = protect(ctx)

    def worker(i):
        return registrar(pack, ctx["def"], hx(b"RDEF", i), RAMAS[i % 3])

    with ThreadPoolExecutor(max_workers=20) as ex:
        res = list(ex.map(worker, range(20)))
    expansiones = sum(1 for r in res if isinstance(r, dict) and r.get("evento") == C.EXPANSION_ZSQ)
    assert expansiones == 20, res
    final = snapshot(pack, ctx)
    assert final["contador"] == 20 and final["nivel"] == 20


# ===============================================================
# H. DEFENSA Y MUTACIÓN DE ESTADO
# [API/ADVERSARIAL]
# Rechazo ⇒ estado idéntico. K_def válida ⇒ árbol avanza o resetea.
# ===============================================================

def test_019_valid_defense_expands_tree():
    # PROPÓSITO: K_def correcta incrementa contador/nivel y fija rama.
    ctx = contexto(22)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    r = registrar(pack, ctx["def"], hx(b"EV", 22), "S")
    if not (isinstance(r, dict) and r.get("evento") == C.EXPANSION_ZSQ):
        raise AssertionError("defensa valida no expandio: %r" % (r,))
    despues = snapshot(pack, ctx)
    assert despues["contador"] == antes["contador"] + 1
    assert despues["rama"] == "S"


def test_020_wrong_defense_does_not_mutate():
    # PROPÓSITO: K_def ajena deniega y deja el estado igual.
    ctx = contexto(23)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    for i in range(N_MUESTRA):
        r = registrar(pack, h(b"BADDEF", i), hx(b"BAD", i), RAMAS[i % 3])
        assert_denegado(r, "bad-def %d" % i)
        assert snapshot(pack, ctx) == antes


def test_022_reset_with_valid_defense_returns_root():
    # PROPÓSITO: reset con K_def deja contador 0 y rama ROOT.
    ctx = contexto(25)
    pack = protect(ctx)
    for i in range(3):
        r = registrar(pack, ctx["def"], hx(b"PRE", i), "S")
        if not (isinstance(r, dict) and r.get("evento") == C.EXPANSION_ZSQ):
            raise AssertionError(r)
    r = C.resetear_defensa(
        blob=pack["blob"],
        manifiesto=pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_defensa=ctx["def"].hex(),
    )
    if not (isinstance(r, dict) and r.get("ok") is True):
        raise AssertionError("reset valido fallo %r" % (r,))
    despues = snapshot(pack, ctx)
    assert despues["contador"] == 0 and despues["rama"] == "ROOT"


def test_023_reset_with_wrong_defense_does_not_mutate():
    # PROPÓSITO: reset con secreto ajeno deniega y no mueve el árbol.
    ctx = contexto(26)
    pack = protect(ctx)
    registrar(pack, ctx["def"], hx(b"PRE", 26), "Q")
    antes = snapshot(pack, ctx)
    r = C.resetear_defensa(
        blob=pack["blob"],
        manifiesto=pack["manifiesto"],
        pub_bytes=pub_bytes(),
        secreto_defensa=h(b"BADRST", 26).hex(),
    )
    assert_denegado(r, "reset-ajeno")
    assert snapshot(pack, ctx) == antes


# ===============================================================
# I. EXPORTACIÓN / IMPORTACIÓN Y AISLAMIENTO
# [API/ADVERSARIAL]
# Serialización sin secretos ni genealogía. Import hostil no pisa vivo.
# ===============================================================

def test_024_export_does_not_contain_secrets():
    # PROPÓSITO: el JSON exportado no incluye hex ni b64 de los 4 secretos.
    ctx = contexto(27)
    pack = protect(ctx)
    registrar(pack, ctx["def"], hx(b"EX", 27), "Q")
    exported = C.exportar_estado()
    if not (isinstance(exported, dict) and exported.get("ok") is True):
        raise AssertionError(exported)
    text = json.dumps(exported)
    for material in (ctx["auth"], ctx["def"], ctx["ses"], ctx["rec"]):
        assert material.hex() not in text
        assert b64(material) not in text


def test_025_export_does_not_contain_genealogy():
    # PROPÓSITO: no se serializan nodos/hijos/compromiso/parent_id.
    ctx = contexto(28)
    pack = protect(ctx)
    registrar(pack, ctx["def"], hx(b"GEN", 28), "Z")
    text = json.dumps(C.exportar_estado())
    for palabra in ('"nodos"', '"hijos"', '"compromiso"', '"parent_id"'):
        assert palabra not in text


def test_026_import_rejects_embedded_genealogy():
    # PROPÓSITO: un paquete con "nodos" se rechaza por contrato.
    r = C.importar_estado(
        {
            "estados": {
                hx(b"K", 0): {
                    "artifact_id": hx(b"A", 0),
                    "nucleo": hx(b"N", 0),
                    "authority_id": hx(b"H", 0),
                    "bind": hx(b"B", 0),
                    "estado_id": hx(b"E", 0),
                    "nivel": 0,
                    "contador": 0,
                    "rama": "ROOT",
                    "nodos": {},
                }
            },
            "tickets": {},
        }
    )
    assert_denegado(r, "import genealogia")


def test_027_import_rejects_malformed_types():
    # PROPÓSITO: tipos que no son el esquema de paquete se deniegan.
    for i, valor in enumerate((None, [], "", {"estados": [], "tickets": {}}, {"estados": {}, "tickets": []})):
        assert_denegado(C.importar_estado(valor), "tipo %d" % i)


def test_028_import_cannot_overwrite_live_state():
    # PROPÓSITO: mutar contador/nivel del snapshot no pisa el estado vivo.
    ctx = contexto(29)
    pack = protect(ctx)
    antes = snapshot(pack, ctx)
    exported = C.exportar_estado()
    if not (isinstance(exported, dict) and "paquete" in exported):
        raise AssertionError(exported)
    paquete = exported["paquete"]
    for estado in paquete["estados"].values():
        estado["contador"] = estado["contador"] + 1 + h(b"INC", 0)[0]
        estado["nivel"] = estado["nivel"] + 1 + h(b"INC", 1)[0]
    assert_denegado(C.importar_estado(paquete), "import rollback")
    assert snapshot(pack, ctx) == antes


# ===============================================================
# J. NONCES Y DERIVACIÓN
# [INTERNAL/UNIT]
# Propiedad funcional del nonce. NO es un ataque externo.
# Se llama _nonce_documento dos veces: igualdad/desigualdad,
# no se compara contra un segundo oráculo escrito en el test.
# ===============================================================

def test_031_nonce_is_deterministic_for_same_inputs():
    # [INTERNAL/UNIT]
    # PROPÓSITO: mismos (k_doc, salt, nucleo, emision) → mismo nonce de 12 B.
    ctx = contexto(33)
    nucleo = P.nucleo(ctx["plaintext"])
    d = C.derivar_claves(
        artifact_id=ctx["artifact_id"],
        nucleo=nucleo,
        authority_id=ctx["authority_id"],
        secreto_autenticacion=ctx["auth"].hex(),
        secreto_defensa=ctx["def"].hex(),
        secreto_sesion=ctx["ses"].hex(),
        secreto_recuperacion=ctx["rec"].hex(),
    )
    if not d.get("ok"):
        raise AssertionError(d)
    n1 = C._nonce_documento(d[C.CLAVE_CIFRADO_DOCUMENTO], d["salt"], nucleo, "1")
    n2 = C._nonce_documento(d[C.CLAVE_CIFRADO_DOCUMENTO], d["salt"], nucleo, "1")
    assert n1 == n2 and len(n1) == 12


def test_032_nonce_changes_when_emission_changes():
    # [INTERNAL/UNIT]
    # PROPÓSITO: cambiar solo emision cambia el nonce.
    ctx = contexto(34)
    nucleo = P.nucleo(ctx["plaintext"])
    d = C.derivar_claves(
        artifact_id=ctx["artifact_id"],
        nucleo=nucleo,
        authority_id=ctx["authority_id"],
        secreto_sesion=ctx["ses"].hex(),
        secreto_raiz=ctx["auth"].hex(),
    )
    if not d.get("ok"):
        raise AssertionError(d)
    n1 = C._nonce_documento(d[C.CLAVE_CIFRADO_DOCUMENTO], d["salt"], nucleo, "1")
    n2 = C._nonce_documento(d[C.CLAVE_CIFRADO_DOCUMENTO], d["salt"], nucleo, "2")
    assert n1 != n2


# ===============================================================
# K. MONTE CARLO KDF
# [INTERNAL/UNIT] evidencia de muestra, no demostración matemática
# ===============================================================

def test_033_montecarlo_kdf_no_observed_collisions_in_sample():
    # PROPÓSITO: en N muestras reproducibles no se observó colisión
    # de dominio, de muestra ni de nonce. No demuestra ausencia global.
    n = MONTECARLO_KDF
    vistos = {k: set() for k in ("auth", "def", "doc", "rec", "nonce")}
    medida = {"ok": 0, "deny": 0, "colision_dominio": 0, "colision_muestra": 0, "nonce_repetido": 0}
    for i in range(n):
        nucleo = hx(b"MCN", i)
        c = C.derivar_claves(
            artifact_id=hx(b"MCA", i),
            nucleo=nucleo,
            authority_id=hx(b"MCH", i)[:32],
            secreto_autenticacion=h(b"MCAA", i),
            secreto_defensa=h(b"MCDD", i),
            secreto_sesion=h(b"MCSS", i),
            secreto_recuperacion=h(b"MCRR", i),
        )
        if not (isinstance(c, dict) and c.get("ok") is True):
            medida["deny"] += 1
            continue
        medida["ok"] += 1
        ka, kd, kc, kr = (
            c[C.CLAVE_AUTENTICACION],
            c[C.CLAVE_DEFENSA],
            c[C.CLAVE_CIFRADO_DOCUMENTO],
            c[C.CLAVE_RECUPERACION],
        )
        if len({ka, kd, kc, kr}) != 4:
            medida["colision_dominio"] += 1
        for nombre, clave in (("auth", ka), ("def", kd), ("doc", kc), ("rec", kr)):
            if clave in vistos[nombre]:
                medida["colision_muestra"] += 1
            vistos[nombre].add(clave)
        nonce = C._nonce_documento(kc, c["salt"], nucleo, "1")
        if nonce in vistos["nonce"]:
            medida["nonce_repetido"] += 1
        vistos["nonce"].add(nonce)
    assert medida["ok"] == n, "muestra KDF: deny inesperado %s" % medida
    assert medida["colision_dominio"] == 0, "colision de dominio OBSERVADA en la muestra %s" % medida
    assert medida["colision_muestra"] == 0, "colision entre muestras OBSERVADA %s" % medida
    assert medida["nonce_repetido"] == 0, "nonce repetido OBSERVADO en la muestra %s" % medida


# ===============================================================
# L. MONTE CARLO DE DOCUMENTOS
# [API/ADVERSARIAL] estabilidad del ciclo, no un millón de ataques
# ===============================================================

def test_034_montecarlo_documents_cycle_stable_in_sample():
    # PROPÓSITO: N documentos independientes se protegen, abren y
    # recuperan. No equivale a N ataques. Reporta colisión de blob
    # observada en la muestra, no ausencia matemática.
    n = MONTECARLO_DOCUMENTOS
    vistos = set()
    medida = {
        "proteger_ok": 0,
        "abrir_ok": 0,
        "recuperar_ok": 0,
        "mismatch": 0,
        "deny": 0,
        "blob_colision": 0,
    }
    for i in range(n):
        ctx = contexto(i + 100)
        pack = protect(ctx)
        medida["proteger_ok"] += 1
        d = hashlib.sha256(pack["blob"]).digest()
        if d in vistos:
            medida["blob_colision"] += 1
        vistos.add(d)
        opened = abrir(pack, ctx, uso_id=hx(b"MCU", i))
        if not (isinstance(opened, dict) and opened.get("ok") is True):
            if es_denegacion(opened):
                medida["deny"] += 1
            else:
                raise AssertionError("abrir fuera de contrato i=%d %r" % (i, opened))
            continue
        medida["abrir_ok"] += 1
        if opened.get("plaintext") != ctx["plaintext"]:
            medida["mismatch"] += 1
        recovered = recobrar(pack, ctx)
        if not (isinstance(recovered, dict) and recovered.get("ok") is True):
            if es_denegacion(recovered):
                medida["deny"] += 1
            else:
                raise AssertionError("recuperar fuera de contrato i=%d %r" % (i, recovered))
            continue
        medida["recuperar_ok"] += 1
        if recovered.get("plaintext") != ctx["plaintext"]:
            medida["mismatch"] += 1
    assert medida["proteger_ok"] == n, medida
    assert medida["abrir_ok"] == n, "ciclo no estable en la muestra %s" % medida
    assert medida["recuperar_ok"] == n, medida
    assert medida["deny"] == 0 and medida["mismatch"] == 0, medida
    assert medida["blob_colision"] == 0, "colision de blob OBSERVADA en la muestra %s" % medida


# ===============================================================
# RECUPERACIÓN OPCIONAL
# [API/ADVERSARIAL]
# ===============================================================

def test_035_undeclared_recovery_has_no_wrap_and_cannot_recover():
    # PROPÓSITO: si no se declara secreto_recuperacion no hay wrap,
    # recuperar deniega, y la raíz no inventa K_rec. Abrir con auth+ses
    # sigue siendo posible.
    ctx = contexto(35)
    pack = protect(
        ctx,
        secreto_recuperacion=None,
        secreto_raiz=ctx["raiz"].hex(),
    )
    header, _ = parse_blob(pack["blob"])
    assert "wrap_recuperacion" not in header
    assert_denegado(recobrar(pack, ctx, rec=ctx["raiz"]), "raiz-como-rec")
    assert_denegado(recobrar(pack, ctx, rec=ctx["rec"]), "rec-no-declarado")
    assert_abierto(abrir(pack, ctx, uso_id=hx(b"USO", 35)), ctx["plaintext"], "abrir-sin-wrap")


def test_001_legitimate_protect_open_recover_cycle():
    # PROPÓSITO: el camino honesto funciona. Si esto falla es fixture
    # o regresión de API, no un ataque.
    ctx = contexto(1)
    pack = protect(ctx)
    assert_abierto(abrir(pack, ctx, uso_id=hx(b"USO", 1)), ctx["plaintext"], "abrir")
    g = recobrar(pack, ctx)
    if not (isinstance(g, dict) and g.get("ok") is True and g.get("plaintext") == ctx["plaintext"]):
        raise AssertionError("recuperacion legitima fallo %r" % (g,))


# ===============================================================
# RUNNER
# ===============================================================

def _clasificar(exc: BaseException) -> str:
    if isinstance(exc, FixtureError):
        return "FIXTURE"
    return "EXCEPCION"


if __name__ == "__main__":
    tests = sorted(
        (n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)
    )
    if len(tests) != TESTS_ESPERADOS:
        print("CONTEO", len(tests), "esperado", TESTS_ESPERADOS)
        raise SystemExit(2)

    passed = 0
    fails: List[Tuple[str, str, str]] = []
    print("=" * 70)
    print("SPARTACO RED TEAM")
    print("tests", len(tests), "KDF", MONTECARLO_KDF, "DOCS", MONTECARLO_DOCUMENTOS)
    print("=" * 70)
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
            passed += 1
        except FixtureError as exc:
            print("FIXTURE", name, exc)
            fails.append((name, "FIXTURE", str(exc)))
        except AssertionError as exc:
            print("FAIL", name, exc)
            fails.append((name, "FAIL", str(exc)))
        except Exception as exc:
            print("EXCEPCION", name, type(exc).__name__, exc)
            traceback.print_exc()
            fails.append((name, "EXCEPCION", "%s: %s" % (type(exc).__name__, exc)))

    print("=" * 70)
    print("TOTAL", len(tests), "PASS", passed, "FAIL", len(fails))
    n_fix = sum(1 for _, k, _ in fails if k == "FIXTURE")
    n_ex = sum(1 for _, k, _ in fails if k == "EXCEPCION")
    n_as = sum(1 for _, k, _ in fails if k == "FAIL")
    print("FIXTURE", n_fix, "ASSERT", n_as, "EXCEPCION", n_ex)
    if fails:
        print("--- detalle ---")
        for name, kind, msg in fails:
            print("%s [%s] %s" % (name, kind, msg))
            if kind == "FIXTURE":
                print("  el ataque NO se ejecuto")
        raise SystemExit(1)
    raise SystemExit(0)
