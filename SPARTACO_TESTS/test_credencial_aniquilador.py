# ===============================================================
# test_credencial_aniquilador.py
# Batería adversarial integral — credencial.py v2.2
# Un solo archivo. No modifica producción.
# Determinista: sin secrets, random, urandom.
# ===============================================================

from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.spartaco_seguridad import credencial as C
from modules.spartaco_seguridad import proteccion as P


def H(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


SEC_RAIZ = H("RAIZ-FIJA-ANIQ-v22")
SEC_AUTH = H("AUTH-FIJA-ANIQ-v22")
SEC_DEF = H("DEF-FIJA-ANIQ-v22")
SEC_SES = H("SES-FIJA-ANIQ-v22")
SEC_REC = H("REC-FIJA-ANIQ-v22")
SEC_BASURA = H("BASURA-ANIQ-v22")

DOC_A = b"DOC-A-ANIQ"
DOC_B = b"DOC-B-ANIQ-DISTINTO"
ART_A = "artifact-A"
ART_B = "artifact-B"
AUTH_A = "authority-A"
AUTH_B = "authority-B"

TMP = Path("/tmp/aniq_credencial_v22")
TMP.mkdir(parents=True, exist_ok=True)
PRIV = str(TMP / "priv.bin")
PUBP = str(TMP / "pub.bin")
PRIV_B = str(TMP / "priv_b.bin")
PUBP_B = str(TMP / "pub_b.bin")


class Hallazgo:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def add(
        self,
        nivel: str,
        ataque: str,
        propiedad: str,
        esperado: Any,
        obtenido: Any,
        razon: str,
        estado_antes: Any = None,
        estado_despues: Any = None,
    ) -> None:
        self.items.append(
            {
                "nivel": nivel,
                "ataque": ataque,
                "propiedad": propiedad,
                "esperado": esperado,
                "obtenido": _corto(obtenido),
                "razon": razon,
                "estado_antes": estado_antes,
                "estado_despues": estado_despues,
            }
        )

    def criticos(self) -> List[Dict[str, Any]]:
        return [x for x in self.items if x["nivel"] == "CRITICO"]

    def altos(self) -> List[Dict[str, Any]]:
        return [x for x in self.items if x["nivel"] == "ALTO"]

    def medios(self) -> List[Dict[str, Any]]:
        return [x for x in self.items if x["nivel"] == "MEDIO"]


HALL = Hallazgo()


def _corto(obj: Any, n: int = 220) -> Any:
    if obj is None:
        return None
    if isinstance(obj, (bytes, bytearray)):
        return f"bytes[{len(obj)}] {bytes(obj)[:16].hex()}"
    s = repr(obj)
    return s if len(s) <= n else s[:n] + "…"


def _pub(path: str = PUBP) -> bytes:
    return Path(path).read_bytes()


def _claves() -> None:
    if not Path(PRIV).exists():
        assert P.generar_claves(PRIV, PUBP).get("ok")
    if not Path(PRIV_B).exists():
        assert P.generar_claves(PRIV_B, PUBP_B).get("ok")


def _proteger(
    texto: bytes,
    artifact_id: str,
    authority_id: str,
    priv: str = PRIV,
    emision: str = "1",
    separados: bool = False,
) -> Dict[str, Any]:
    kw: Dict[str, Any] = {
        "artifact_id": artifact_id,
        "authority_id": authority_id,
        "emision": emision,
        "secreto_recuperacion": SEC_REC,
    }
    if separados:
        kw.update(
            {
                "secreto_autenticacion": SEC_AUTH,
                "secreto_defensa": SEC_DEF,
                "secreto_sesion": SEC_SES,
            }
        )
    else:
        kw["secreto_raiz"] = SEC_RAIZ
    out = C.proteger(texto, priv, **kw)
    assert out.get("ok"), out
    return out


def _abrir(pack: Dict[str, Any], pub: Optional[bytes] = None, **kw: Any) -> Dict[str, Any]:
    args = {
        "manifiesto": pack["manifiesto"],
        "pub_bytes": pub if pub is not None else _pub(),
        "secreto_raiz": SEC_RAIZ,
    }
    args.update(kw)
    return C.abrir_documento(pack["blob"], **args)


def _estado(pack: Dict[str, Any]) -> Any:
    auth = pack["manifiesto"]["cuerpo"].get("clave_publica_id") or AUTH_A
    return C.estado_publico(
        artifact_id=pack["artifact_id"],
        nucleo=pack["plaintext_nucleo"],
        authority_id=auth,
    ).get("estado")


def _call(fn, *a, **k) -> Tuple[Any, Optional[str]]:
    try:
        return fn(*a, **k), None
    except TypeError as e:
        return None, "TypeError:" + str(e)
    except Exception as e:
        return None, type(e).__name__ + ":" + str(e)


def _reconstruir(header: Dict[str, Any], ciphertext: bytes, cola: bytes = b"") -> bytes:
    ser = P.serializar_seguro(header)
    if not ser.get("ok"):
        raise ValueError("serializar")
    return ser["bytes"] + C.SEP + ciphertext + cola


def _partir(blob: bytes) -> Tuple[Dict[str, Any], bytes, bytes]:
    parsed = C._parse_sobre(blob)
    idx = blob.find(C.SEP)
    if parsed is None:
        raise ValueError("parse")
    header, ct = parsed
    cola = blob[idx + len(C.SEP) + len(ct) :]
    return header, ct, cola


def test_aniquilador() -> None:
    _claves()
    pub_a = _pub(PUBP)
    pub_b = _pub(PUBP_B)
    pack_a = _proteger(DOC_A, ART_A, AUTH_A, emision="eA")
    pack_b = _proteger(DOC_B, ART_B, AUTH_B, priv=PRIV_B, emision="eB")
    man = pack_a["manifiesto"]

    contextos = [
        (ART_A, pack_a["plaintext_nucleo"], AUTH_A),
        (ART_B, pack_b["plaintext_nucleo"], AUTH_B),
        ("ax", "n" * 64, "ux"),
        ("ay", "m" * 64, "uy"),
    ]
    vistos = []
    for art, nuc, auth in contextos:
        cl = C.derivar_claves(
            artifact_id=art,
            nucleo=nuc,
            authority_id=auth,
            secreto_autenticacion=SEC_AUTH,
            secreto_defensa=SEC_DEF,
            secreto_sesion=SEC_SES,
            secreto_recuperacion=SEC_REC,
        )
        if not cl.get("ok"):
            HALL.add("CRITICO", f"kdf {art}", "derivación válida", "ok", cl, "secretos válidos rechazados")
            continue
        ks = [
            cl[C.CLAVE_AUTENTICACION],
            cl[C.CLAVE_DEFENSA],
            cl[C.CLAVE_CIFRADO_DOCUMENTO],
            cl[C.CLAVE_RECUPERACION],
        ]
        if len({bytes(x) for x in ks}) != 4:
            HALL.add("CRITICO", f"kdf colisión {art}", "4 claves distintas", False, True, "dominios HKDF colisionan")
        vistos.append(ks)
    if len(vistos) >= 2 and any(a == b for a, b in zip(vistos[0], vistos[1])):
        HALL.add("CRITICO", "kdf contexto", "claves distintas por artifact", "distintas", "iguales", "K no depende del contexto")

    pack_sep = _proteger(b"DOC-SEP", "artifact-SEP", AUTH_A, emision="sep", separados=True)
    res_sep, exc = _call(
        C.abrir_documento,
        pack_sep["blob"],
        manifiesto=pack_sep["manifiesto"],
        pub_bytes=pub_a,
        secreto_autenticacion=SEC_AUTH,
        secreto_sesion=SEC_SES,
    )
    if exc:
        HALL.add("ALTO", "abrir separados excepción", "fail-closed", "ACCESS_DENIED", exc, "excepción no controlada")
    elif res_sep and res_sep.get("ok"):
        HALL.add("MEDIO", "abrir separados sin K_def", "API", "observar", res_sep, "abrió sin parámetro secreto_defensa")
    else:
        HALL.add(
            "CRITICO",
            "secretos separados no se pueden abrir",
            "K_auth+K_doc bastan para abrir",
            "ok",
            res_sep,
            "proteger admite 3 IKM; autorizar_ruta llama derivar_claves sin secreto_defensa y deniega",
        )

    res = C.abrir_documento(pack_a["blob"], manifiesto=pack_a["manifiesto"], pub_bytes=pub_a, secreto_raiz=SEC_REC)
    if res.get("ok"):
        HALL.add("CRITICO", "K_rec como raíz de apertura", "denied", "denied", res, "recuperación usó canal de auth")

    header, ct, cola = _partir(pack_a["blob"])

    def atacar_blob(nombre: str, blob: Any, manifiesto: Any = None) -> None:
        antes = _estado(pack_a)
        res, exc = _call(
            C.abrir_documento,
            blob,
            manifiesto=manifiesto if manifiesto is not None else pack_a["manifiesto"],
            pub_bytes=pub_a,
            secreto_raiz=SEC_RAIZ,
        )
        if exc:
            HALL.add("ALTO", nombre, "fail-closed ACCESS_DENIED", "sin excepción", exc, "excepción no controlada", antes)
            return
        if res and res.get("ok"):
            HALL.add("CRITICO", nombre, "no autorizar inválido", "denied", res, "entrada malformada aceptada", antes)
        despues = _estado(pack_a)
        if despues != antes:
            HALL.add("CRITICO", nombre + " mutó ZSQ", "fallo no muta", antes, despues, "blob inválido mutó árbol", antes, despues)

    atacar_blob("json truncado", pack_a["blob"][:40])
    atacar_blob("utf8 invalido", b"\xff\xfe" + C.SEP + ct)
    atacar_blob("sep multiple", pack_a["blob"].replace(C.SEP, C.SEP + C.SEP, 1))
    atacar_blob("blobs concatenados", pack_a["blob"] + pack_b["blob"])
    atacar_blob("basura antes", b"XXXX" + pack_a["blob"])
    atacar_blob("basura despues", pack_a["blob"] + b"XXXX")
    atacar_blob("ciphertext vacio", _reconstruir(dict(header), b"", cola))

    for campo, valor in {
        "schema": "no",
        "version": -1,
        "artifact_id": None,
        "authority_id": 123,
        "algorithm": True,
        "kdf": ["HKDF"],
        "salt": None,
        "nonce": 0,
        "emision": False,
        "ciphertext_length": -5,
        "ciphertext_digest": None,
        "plaintext_nucleo": 3.14,
        "tag_auth": [],
        "tag_def": {},
    }.items():
        h2 = dict(header)
        h2[campo] = valor
        try:
            atacar_blob(f"tipo {campo}", _reconstruir(h2, ct, cola))
        except Exception:
            continue

    for nlen in (0, 1, 10**6, max(0, len(ct) - 1), len(ct) + 50):
        h2 = dict(header)
        h2["ciphertext_length"] = nlen
        try:
            atacar_blob(f"ct_len={nlen}", _reconstruir(h2, ct, cola))
        except Exception:
            continue

    muts = {
        "schema": 99,
        "version": 99,
        "artifact_id": ART_B,
        "authority_id": AUTH_B,
        "algorithm": "AES-128-GCM",
        "kdf": "PBKDF2",
        "nonce": "AA",
        "emision": "eB",
        "ciphertext_digest": "00" * 32,
        "plaintext_nucleo": "11" * 32,
        "tag_auth": "22" * 32,
        "tag_def": "33" * 32,
    }
    for campo, valor in muts.items():
        h2 = dict(header)
        h2[campo] = valor
        try:
            atacar_blob(f"header.{campo}", _reconstruir(h2, ct, cola))
        except Exception:
            continue

    if ct:
        ct2 = bytearray(ct)
        ct2[-1] ^= 0x5A
        atacar_blob("ciphertext flip", _reconstruir(dict(header), bytes(ct2), cola))

    hb, _ctb, _ = _partir(pack_b["blob"])
    for campo in ("nonce", "salt", "tag_auth", "tag_def", "emision", "plaintext_nucleo"):
        h2 = dict(header)
        h2[campo] = hb.get(campo)
        try:
            atacar_blob(f"swap {campo} A<-B", _reconstruir(h2, ct, cola))
        except Exception:
            continue
    if header.get("wrap_recuperacion") and hb.get("wrap_recuperacion"):
        h2 = dict(header)
        h2["wrap_recuperacion"] = hb["wrap_recuperacion"]
        rec, exc = _call(
            C.recuperar,
            _reconstruir(h2, ct, cola),
            manifiesto=pack_a["manifiesto"],
            pub_bytes=pub_a,
            secreto_recuperacion=SEC_REC,
        )
        if exc:
            HALL.add("ALTO", "wrap cruzado exc", "fail-closed", "denied", exc, "excepción")
        elif rec and rec.get("ok"):
            HALL.add("CRITICO", "wrap B sobre A", "no cross-recovery", "denied", rec, "wrap ajeno recuperó A")

    for nombre, blob, mf, pub in [
        ("blobA+manB", pack_a["blob"], pack_b["manifiesto"], pub_a),
        ("blobA+pubB", pack_a["blob"], pack_a["manifiesto"], pub_b),
        ("blobB+manA", pack_b["blob"], pack_a["manifiesto"], pub_b),
        ("blobB+pubA", pack_b["blob"], pack_b["manifiesto"], pub_a),
    ]:
        antes = _estado(pack_a)
        res, exc = _call(C.abrir_documento, blob, manifiesto=mf, pub_bytes=pub, secreto_raiz=SEC_RAIZ)
        if exc:
            HALL.add("ALTO", nombre + " exc", "fail-closed", "denied", exc, "excepción")
        elif res and res.get("ok"):
            HALL.add("CRITICO", nombre, "identidad no cruza", "denied", res, "autorización cruzada")
        if nombre.startswith("blobA") and _estado(pack_a) != antes:
            HALL.add("CRITICO", nombre + " mutó", "no mutar", antes, _estado(pack_a), "cruce mutó ZSQ")

    for nombre, mf in [
        ("firma vacia", {"cuerpo": man["cuerpo"], "firma": ""}),
        ("firma truncada", {"cuerpo": man["cuerpo"], "firma": man["firma"][:8]}),
        ("firma extendida", {"cuerpo": man["cuerpo"], "firma": man["firma"] + "aa"}),
        ("firma flip", {"cuerpo": man["cuerpo"], "firma": ("0" if man["firma"][:1] != "0" else "1") + man["firma"][1:]}),
        ("firma B", {"cuerpo": man["cuerpo"], "firma": pack_b["manifiesto"]["firma"]}),
        ("cuerpo B firma A", {"cuerpo": pack_b["manifiesto"]["cuerpo"], "firma": man["firma"]}),
        ("cuerpo mutado", {"cuerpo": dict(man["cuerpo"], artifact_id=ART_B), "firma": man["firma"]}),
        ("sin firma", {"cuerpo": man["cuerpo"]}),
        ("sin cuerpo", {"firma": man["firma"]}),
    ]:
        atacar_blob(nombre, pack_a["blob"], mf)

    pack_r = _proteger(b"DOC-REPLAY", "artifact-R", AUTH_A, emision="r1")
    r1 = _abrir(pack_r, uso_id="U-FIJO")
    r2 = _abrir(pack_r, uso_id="U-FIJO")
    if not r1.get("ok"):
        HALL.add("ALTO", "primer uso_id", "primera autorización", "ok", r1, "primer consumo falló")
    if r2.get("ok"):
        HALL.add("CRITICO", "replay uso_id", "máximo una autorización", "denied", r2, "mismo uso_id dos veces")

    for n in (2, 10, 20, 50, 100):
        acc: List[bool] = []
        lock = threading.Lock()

        def hilo(uid: str = f"U-{n}") -> None:
            ok = _abrir(pack_r, uso_id=uid).get("ok") is True
            with lock:
                acc.append(ok)

        hs = [threading.Thread(target=hilo) for _ in range(n)]
        for t in hs:
            t.start()
        for t in hs:
            t.join()
        if sum(acc) != 1:
            HALL.add("CRITICO", f"replay {n} hilos", "exactamente 1 ok", 1, sum(acc), "carrera de ticket")

    for nombre, uid in [("uso vacio", ""), ("uso unicode", "使用"), ("uso largo", "U" * 4000)]:
        _res, exc = _call(
            C.abrir_documento,
            pack_r["blob"],
            manifiesto=pack_r["manifiesto"],
            pub_bytes=pub_a,
            secreto_raiz=SEC_RAIZ,
            uso_id=uid,
        )
        if exc:
            HALL.add("ALTO", nombre + " exc", "fail-closed", "controlado", exc, "excepción")

    r_otro = _abrir(pack_r, uso_id="U-OTRO")
    if not r_otro.get("ok"):
        HALL.add("MEDIO", "uso_id distinto", "otro id autoriza", "ok", r_otro, "ids distintos se bloquean")

    pack_c = _proteger(b"DOC-CONC", "artifact-C", AUTH_A, emision="c1")
    tags: List[str] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        try:
            mod = i % 7
            if mod == 0:
                r = _abrir(pack_c, uso_id="CONC-U")
                tag = "abrir_ok" if r.get("ok") else "abrir_no"
            elif mod == 1:
                r = C.autorizar_ruta(
                    pack_c["blob"],
                    manifiesto=pack_c["manifiesto"],
                    pub_bytes=pub_a,
                    secreto_raiz=SEC_RAIZ,
                    uso_id="CONC-U2",
                )
                tag = "auth_ok" if r.get("ok") else "auth_no"
            elif mod == 2:
                C.registrar_intento(
                    pack_c["blob"],
                    manifiesto=pack_c["manifiesto"],
                    pub_bytes=pub_a,
                    secreto_raiz=SEC_RAIZ,
                    rama="S",
                )
                tag = "def"
            elif mod == 3:
                C.resetear_defensa(
                    blob=pack_c["blob"],
                    manifiesto=pack_c["manifiesto"],
                    pub_bytes=pub_a,
                    secreto_raiz=SEC_RAIZ,
                )
                tag = "reset"
            elif mod == 4:
                C.exportar_estado()
                tag = "exp"
            elif mod == 5:
                C.recuperar(
                    pack_c["blob"],
                    manifiesto=pack_c["manifiesto"],
                    pub_bytes=pub_a,
                    secreto_recuperacion=SEC_REC,
                )
                tag = "rec"
            else:
                C.importar_estado(C.exportar_estado().get("paquete"))
                tag = "imp"
        except Exception as e:
            tag = "EXC:" + type(e).__name__
        with lock:
            tags.append(tag)

    hs = [threading.Thread(target=worker, args=(i,)) for i in range(28)]
    for t in hs:
        t.start()
    for t in hs:
        t.join()
    if any(t.startswith("EXC:") for t in tags):
        HALL.add("ALTO", "concurrencia mixta exc", "sin excepciones", "ok", tags, "carrera con excepción")
    if tags.count("abrir_ok") > 1:
        HALL.add("CRITICO", "doble abrir concurrente", "<=1", 1, tags.count("abrir_ok"), "doble autorización")

    est_antes = _estado(pack_a)
    atacar_blob("firma basura", pack_a["blob"], {"cuerpo": man["cuerpo"], "firma": "00" * 64})
    if _estado(pack_a) != est_antes:
        HALL.add("CRITICO", "firma basura mutó ZSQ", "no mutar", est_antes, _estado(pack_a), "blob no autenticado mutó")

    for rama, secreto in [("S", SEC_BASURA), ("S", SEC_AUTH), ("S", SEC_SES), ("S", SEC_REC), ("X", SEC_RAIZ)]:
        antes = _estado(pack_a)
        r, exc = _call(
            C.registrar_intento,
            pack_a["blob"],
            manifiesto=pack_a["manifiesto"],
            pub_bytes=pub_a,
            secreto_defensa=secreto,
            rama=rama,
        )
        if exc:
            HALL.add("ALTO", f"defensa {rama} exc", "fail-closed", "denied", exc, "excepción")
        if r and r.get("evento") == C.EXPANSION_ZSQ and secreto != SEC_RAIZ:
            HALL.add("CRITICO", "defensa secreto ajeno", "solo K_def", "denied", r, "otro dominio expandió")
        if secreto != SEC_RAIZ and rama != "X" and _estado(pack_a) != antes:
            HALL.add("CRITICO", "defensa ilegítima mutó", "no mutar", antes, _estado(pack_a), "K_def falsa mutó")

    for rama in ("Z", "S", "Q"):
        r = C.registrar_intento(
            pack_a["blob"],
            manifiesto=pack_a["manifiesto"],
            pub_bytes=pub_a,
            secreto_raiz=SEC_RAIZ,
            rama=rama,
        )
        if r.get("evento") != C.EXPANSION_ZSQ:
            HALL.add("ALTO", f"expansión {rama}", "EXPANSION_ZSQ", "evento", r, "defensa legítima no avanzó")

    r_ev = C.registrar_intento(
        pack_a["blob"],
        manifiesto=pack_a["manifiesto"],
        pub_bytes=pub_a,
        secreto_raiz=SEC_RAIZ,
        rama="S",
        evento="",
    )
    if r_ev.get("evento") == C.EXPANSION_ZSQ:
        HALL.add("MEDIO", "evento vacío", "política", "decidir", r_ev.get("estado"), "evento vacío aceptado")

    dump = json.dumps(C.exportar_estado())
    for clave in ("parent_id", "hijos", "compromiso"):
        if clave in dump:
            HALL.add("ALTO", f"export expone {clave}", "sin genealogía pública", "ausente", clave, "viola no_hace del contrato")

    r, exc = _call(
        C.importar_estado,
        {
            "estados": {
                "k": {
                    "nodos": {"x": {"role": "HACK", "parent_id": "p", "hijos": {}}},
                    "bind": "00",
                    "contador": -1,
                    "actual": "x",
                    "estado_id": "00",
                    "artifact_id": "z",
                    "nucleo": "n",
                    "authority_id": "a",
                }
            },
            "tickets": {},
        },
    )
    if exc:
        HALL.add("ALTO", "import nodos exc", "fail-closed", "denied", exc, "excepción")
    elif r and r.get("ok"):
        HALL.add("ALTO", "import nodos falsos", "validar o rechazar", "denied", r, "import no valida esquema")

    pack_rb = _proteger(b"DOC-ROLLBACK", "artifact-RB", AUTH_A, emision="rb")
    snap = C.exportar_estado()["paquete"]
    first = _abrir(pack_rb, uso_id="TICKET-RB")
    second = _abrir(pack_rb, uso_id="TICKET-RB")
    if first.get("ok") and second.get("ok"):
        HALL.add("CRITICO", "doble ticket pre-import", "1 ok", "1", second, "replay sin import")
    C.importar_estado(snap)
    third = _abrir(pack_rb, uso_id="TICKET-RB")
    if third.get("ok"):
        HALL.add(
            "CRITICO",
            "ROLLBACK tickets importar_estado",
            "ticket consumido no revive",
            "denied",
            third,
            "snapshot anterior restauró autorización gastada",
        )

    pack_rs = _proteger(b"DOC-RST-T", "artifact-RSTT", AUTH_A, emision="rstt")
    u1 = _abrir(pack_rs, uso_id="T-RST")
    C.resetear_defensa(
        blob=pack_rs["blob"],
        manifiesto=pack_rs["manifiesto"],
        pub_bytes=pub_a,
        secreto_raiz=SEC_RAIZ,
    )
    u2 = _abrir(pack_rs, uso_id="T-RST")
    if u1.get("ok") and u2.get("ok"):
        HALL.add("CRITICO", "reset revive uso_id", "reset ≠ rollback replay", "denied", u2, "reset reabrió ticket")

    rec_ok = C.recuperar(pack_a["blob"], manifiesto=pack_a["manifiesto"], pub_bytes=pub_a, secreto_recuperacion=SEC_REC)
    if not rec_ok.get("ok") or rec_ok.get("plaintext") != DOC_A:
        HALL.add("CRITICO", "recuperación legítima", "DOC_A", "ok", rec_ok, "ruta K_rec rota")
    for label, sec in [("basura", SEC_BASURA), ("auth", SEC_AUTH), ("def", SEC_DEF), ("vacio", "")]:
        r, exc = _call(C.recuperar, pack_a["blob"], manifiesto=pack_a["manifiesto"], pub_bytes=pub_a, secreto_recuperacion=sec)
        if exc:
            HALL.add("ALTO", f"rec {label} exc", "fail-closed", "denied", exc, "excepción")
        elif r and r.get("ok"):
            HALL.add("CRITICO", f"rec con {label}", "solo K_rec", "denied", r, "secreto ajeno recuperó")
    HALL.add("MEDIO", "K_rec independiente", "ruta propia", "observado", "ok", "K_rec no exige K_auth. Contrato de ruta independiente.")

    C.registrar_intento(pack_a["blob"], manifiesto=pack_a["manifiesto"], pub_bytes=pub_a, secreto_raiz=SEC_RAIZ, rama="S")
    for label, sec in [("basura", SEC_BASURA), ("auth", SEC_AUTH), ("ses", SEC_SES), ("rec", SEC_REC)]:
        r, exc = _call(
            C.resetear_defensa,
            blob=pack_a["blob"],
            manifiesto=pack_a["manifiesto"],
            pub_bytes=pub_a,
            secreto_defensa=sec,
        )
        if exc:
            HALL.add("ALTO", f"reset {label} exc", "fail-closed", "denied", exc, "excepción")
        elif r and r.get("ok"):
            HALL.add("CRITICO", f"reset con {label}", "solo K_def", "denied", r, "reset con dominio ajeno")
    rst = C.resetear_defensa(blob=pack_a["blob"], manifiesto=pack_a["manifiesto"], pub_bytes=pub_a, secreto_raiz=SEC_RAIZ)
    if not rst.get("ok"):
        HALL.add("ALTO", "reset legítimo", "ok nivel 0", "ok", rst, "reset no volvió a ROOT")

    res, exc = _call(C.abrir_documento, pack_a["blob"])
    if exc is None and res and res.get("ok"):
        HALL.add("CRITICO", "abrir sin pub/secretos", "denied", "denied", res, "defaults peligrosos")

    fin = _abrir(pack_a)
    if not fin.get("ok") or fin.get("plaintext") != DOC_A:
        HALL.add("CRITICO", "invariante abrir A", "DOC_A abre", "ok", fin, "documento legítimo dejó de abrir")
    finr = C.recuperar(pack_a["blob"], manifiesto=pack_a["manifiesto"], pub_bytes=pub_a, secreto_recuperacion=SEC_REC)
    if not finr.get("ok") or finr.get("plaintext") != DOC_A:
        HALL.add("CRITICO", "invariante recuperar A", "DOC_A", "ok", finr, "recuperación rota")
    cruz = C.abrir_documento(pack_a["blob"], manifiesto=pack_b["manifiesto"], pub_bytes=pub_b, secreto_raiz=SEC_RAIZ)
    if cruz.get("ok"):
        HALL.add("CRITICO", "invariante cruce final", "denied", "denied", cruz, "A abrió con identidad B")

    print("=" * 72)
    print("ANIQULADOR credencial.py v2.2")
    print("CRITICOS", len(HALL.criticos()), "ALTOS", len(HALL.altos()), "MEDIOS", len(HALL.medios()))
    print("=" * 72)
    for it in HALL.items:
        print(f"[{it['nivel']}] {it['ataque']}")
        print(f"    propiedad: {it['propiedad']}")
        print(f"    esperado:  {it['esperado']}")
        print(f"    obtenido:  {it['obtenido']}")
        print(f"    razon:     {it['razon']}")
    print("=" * 72)
    assert not HALL.criticos(), f"FALLOS CRITICOS: {len(HALL.criticos())}"
    assert not HALL.altos(), f"FALLOS ALTOS: {len(HALL.altos())}"


if __name__ == "__main__":
    try:
        test_aniquilador()
        print("RESULTADO: SIN FALLOS CRITICOS/ALTOS")
        sys.exit(0)
    except AssertionError as e:
        print("RESULTADO: FALLO —", e)
        sys.exit(1)
