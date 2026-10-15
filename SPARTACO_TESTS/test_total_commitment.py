"""
SPARTACO SECURITY — REAL-WORLD ATTACK: TOTAL COMPROMISE OF THE SIGNING PLANE
======================================================================

OBJECTIVE
--------
To experimentally demonstrate whether an attacker possessing all of the following simultaneously:

    - a REAL .spartaco document
    - a complete REAL manifest
    - a REAL Ed25519 public key
    - a REAL Ed25519 private key
    - knowledge of the format
    - knowledge of AES-256-GCM / HKDF-SHA256
    - the ability to use mature cryptographic libraries
    - the ability to invoke the legitimate CREDENCIAL engine

can recover the plaintext WITHOUT possessing the correct authentication/session/recovery secret material.

THIS IS NOT A THEORETICAL TEST.
It uses the four real artifacts.

ATTACKED PROPERTIES
---------------------
A) External decryption without SPARTACO.
B) Unauthorized derivation from Ed25519 keys and public metadata.
C) Abuse of the recovery wrap.
D) Use of the CREDENCIAL engine itself as a potential oracle.
E) Use of root/auth/session/recovery secrets derived from the stolen material.
F) Domain confusion: signing -> encryption / recovery.
G) Structural verification that .priv actually corresponds to .pub.

ATTACKER SUCCESS CRITERIA
---------------------------
The attacker succeeds if they obtain an AES-GCM authenticated plaintext using
exclusively material available in the four compromised artifacts,
or if the SPARTACO engine returns ok=True/plaintext with one of those candidates.

The test does NOT consider observing hashes, sizes, IDs, or public metadata as "success."

IMPORTANT
----------
This test does not aim for "2^256 brute force." That would not be a useful test. It looks for implementation and domain separation vulnerabilities:
key reuse, loosely bound KDF, secrets derived from public
information, Ed25519/AES confusion, exposed recovery, or an engine
turned into an opening oracle.

FIXTURES
--------
By default, it looks for:

tests/fixtures/spartaco_compromiso_total/
    spartaco_firma 2.pub
    spartaco_firma 2.priv
    recursive_audit.pdf.spartaco
    recursive_audit.pdf.spartaco.manifest.json

It also accepts:
    SPARTACO_ATTACK_FIXTURES=/path/to-directory

If all four are not present, the test generates the Ed25519 pair using
proteccion.generar_claves and the envelope using credencial.proteger.
The authentication/defense/session/recovery IKM is distinct
from the signing pair and is not written to the attack artifacts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import itertools
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PUB_NAME = "spartaco_firma 2.pub"
PRIV_NAME = "spartaco_firma 2.priv"
BLOB_NAME = "recursive_audit.pdf.spartaco"
MANIFEST_NAME = "recursive_audit.pdf.spartaco.manifest.json"

SEP = b"\n--ESPARTACO-DOC--\n"

INFO_AUTH = b"VPSI-AUTENTICACION-V1"
INFO_DEF = b"VPSI-DEFENSA-ZSQ-V1"
INFO_DOC = b"VPSI-DOCUMENTO-CIFRADO-V1"
INFO_REC = b"VPSI-RECUPERACION-V1"
INFO_NONCE_WRAP = b"VPSI-NONCE-WRAP-V1"

ACCESS_DENIED = "ACCESS_DENIED"


def b64d(texto: str) -> bytes:
    pad = "=" * ((4 - len(texto) % 4) % 4)
    return base64.urlsafe_b64decode((texto or "") + pad)


def campo(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def info_ligada(label: bytes, artifact_id: str, nucleo: str, authority_id: str) -> bytes:
    return b"".join(
        (
            campo(label),
            campo(artifact_id.encode("utf-8")),
            campo(nucleo.encode("utf-8")),
            campo(authority_id.encode("utf-8")),
        )
    )


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def parse_blob(blob: bytes) -> Tuple[Dict[str, object], bytes, bytes]:
    idx = blob.find(SEP)
    assert idx >= 0, "El artefacto real no contiene SEP de SPARTACO."
    header_raw = blob[:idx]
    header = json.loads(header_raw.decode("ascii"))
    assert isinstance(header, dict)
    rest = blob[idx + len(SEP):]
    n = header.get("ciphertext_length")
    assert isinstance(n, int) and 0 <= n <= len(rest)
    ciphertext = rest[:n]
    return header, header_raw, ciphertext


def exact_doc_aad(header: Dict[str, object]) -> bytes:
    return (
        info_ligada(
            INFO_DOC,
            str(header["artifact_id"]),
            str(header["plaintext_nucleo"]),
            str(header["authority_id"]),
        )
        + campo(str(header.get("emision", "1")).encode("utf-8"))
    )


def exact_wrap_nonce(k_rec: bytes, header: Dict[str, object]) -> bytes:
    info = info_ligada(
        INFO_NONCE_WRAP,
        str(header["artifact_id"]),
        str(header["plaintext_nucleo"]),
        str(header["authority_id"]),
    )
    return hkdf(k_rec, k_rec, info, length=12)


def try_aesgcm(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> Optional[bytes]:
    if len(key) not in (16, 24, 32):
        return None
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError, TypeError):
        return None


def _candidate_fixture_dirs() -> Iterable[Path]:
    env = os.environ.get("SPARTACO_ATTACK_FIXTURES")
    if env:
        yield Path(env)

    here = Path(__file__).resolve()
    yield here.parent / "fixtures" / "spartaco_compromiso_total"
    yield here.parent.parent / "tests" / "fixtures" / "spartaco_compromiso_total"
    yield Path("/mnt/data")


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for root in (here.parent.parent, here.parent):
        if (root / "modules" / "spartaco_seguridad" / "credencial.py").is_file():
            return root
    return here.parent.parent


def _import_motor():
    root = _repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    cred = importlib.import_module("modules.spartaco_seguridad.credencial")
    prot = importlib.import_module("modules.spartaco_seguridad.proteccion")
    return cred, prot


def _sintetizar_artefactos(destino: Path) -> Path:
    """
    Nace par de FIRMA con el motor y un sobre con IKM distinto.
    El atacante del resto de la suite solo recibe pub/priv/blob/manifiesto.
    """
    destino.mkdir(parents=True, exist_ok=True)
    ruta_priv = destino / PRIV_NAME
    ruta_pub = destino / PUB_NAME
    cred, prot = _import_motor()
    nacido = prot.generar_claves(str(ruta_priv), str(ruta_pub))
    assert nacido.get("ok"), f"generar_claves rechazo: {nacido!r}"

    plaintext = b"%PDF-1.4\n" + (os.urandom(32) * 4000)
    assert len(plaintext) > 100_000

    ikm_auth = os.urandom(32)
    ikm_def = os.urandom(32)
    ikm_ses = os.urandom(32)
    ikm_rec = os.urandom(32)
    assert ikm_auth != ruta_priv.read_bytes()

    sellado = cred.proteger(
        plaintext,
        str(ruta_priv),
        artifact_id="Auditoria-CI",
        authority_id="CI",
        secreto_autenticacion=ikm_auth,
        secreto_defensa=ikm_def,
        secreto_sesion=ikm_ses,
        secreto_recuperacion=ikm_rec,
    )
    assert sellado.get("ok") and sellado.get("blob") and sellado.get("manifiesto"), (
        f"proteger rechazo: {sellado!r}"
    )
    (destino / BLOB_NAME).write_bytes(sellado["blob"])
    (destino / MANIFEST_NAME).write_text(
        json.dumps(sellado["manifiesto"], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return destino


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory) -> Path:
    required = {PUB_NAME, PRIV_NAME, BLOB_NAME, MANIFEST_NAME}
    for d in _candidate_fixture_dirs():
        if d.is_dir() and all((d / name).is_file() for name in required):
            return d
    destino = tmp_path_factory.mktemp("spartaco_compromiso_total")
    return _sintetizar_artefactos(destino)


@dataclass(frozen=True)
class Material:
    pub: bytes
    priv: bytes
    blob: bytes
    manifest_bytes: bytes
    manifest: Dict[str, object]
    header: Dict[str, object]
    header_raw: bytes
    ciphertext: bytes
    nonce: bytes
    salt: bytes
    aad: bytes


@pytest.fixture(scope="module")
def material(fixture_dir: Path) -> Material:
    d = fixture_dir
    pub = (d / PUB_NAME).read_bytes()
    priv = (d / PRIV_NAME).read_bytes()
    blob = (d / BLOB_NAME).read_bytes()
    manifest_bytes = (d / MANIFEST_NAME).read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    header, header_raw, ciphertext = parse_blob(blob)

    return Material(
        pub=pub,
        priv=priv,
        blob=blob,
        manifest_bytes=manifest_bytes,
        manifest=manifest,
        header=header,
        header_raw=header_raw,
        ciphertext=ciphertext,
        nonce=b64d(str(header["nonce"])),
        salt=b64d(str(header["salt"])),
        aad=exact_doc_aad(header),
    )


def public_metadata_fragments(m: Material) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = [
        ("pub_raw", m.pub),
        ("priv_raw", m.priv),
        ("blob_header_raw", m.header_raw),
        ("manifest_raw", m.manifest_bytes),
        ("salt_raw", m.salt),
        ("nonce_raw", m.nonce),
    ]

    for prefix, obj in (("header", m.header), ("manifest", m.manifest)):
        def walk(value, path):
            if isinstance(value, dict):
                for k, v in value.items():
                    walk(v, path + [str(k)])
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    walk(v, path + [str(i)])
            elif isinstance(value, (str, int, float, bool)) or value is None:
                raw = str(value).encode("utf-8")
                out.append((f"{prefix}." + ".".join(path), raw))
        walk(obj, [])

    return out


def candidate_secrets(m: Material) -> List[Tuple[str, bytes]]:
    fragments = public_metadata_fragments(m)
    candidates: Dict[bytes, str] = {}

    def add(name: str, raw: bytes):
        if len(raw) == 32:
            candidates.setdefault(raw, name)
        candidates.setdefault(sha256(raw), f"sha256({name})")

    for name, raw in fragments:
        add(name, raw)

    privileged = [
        ("priv", m.priv),
        ("pub", m.pub),
        ("priv||pub", m.priv + m.pub),
        ("pub||priv", m.pub + m.priv),
        ("priv||salt", m.priv + m.salt),
        ("pub||salt", m.pub + m.salt),
        ("priv||header", m.priv + m.header_raw),
        ("pub||header", m.pub + m.header_raw),
        ("priv||manifest", m.priv + m.manifest_bytes),
        ("pub||manifest", m.pub + m.manifest_bytes),
    ]
    for name, raw in privileged:
        add(name, raw)

    critical = [
        ("salt", m.salt),
        ("header", m.header_raw),
        ("manifest", m.manifest_bytes),
        ("artifact_id", str(m.header["artifact_id"]).encode()),
        ("authority_id", str(m.header["authority_id"]).encode()),
        ("plaintext_nucleo", str(m.header["plaintext_nucleo"]).encode()),
        ("ciphertext_digest", str(m.header["ciphertext_digest"]).encode()),
    ]
    for key_name, key in (("priv", m.priv), ("pub", m.pub)):
        for msg_name, msg in critical:
            add(f"hmac({key_name},{msg_name})", hmac.new(key, msg, hashlib.sha256).digest())

    return sorted(((name, raw) for raw, name in candidates.items()), key=lambda x: x[0])


def derived_key_candidates(m: Material) -> List[Tuple[str, bytes]]:
    base = candidate_secrets(m)
    artifact_id = str(m.header["artifact_id"])
    nucleo = str(m.header["plaintext_nucleo"])
    authority_id = str(m.header["authority_id"])

    infos = [
        ("DOC", info_ligada(INFO_DOC, artifact_id, nucleo, authority_id)),
        ("AUTH", info_ligada(INFO_AUTH, artifact_id, nucleo, authority_id)),
        ("DEF", info_ligada(INFO_DEF, artifact_id, nucleo, authority_id)),
        ("REC", info_ligada(INFO_REC, artifact_id, nucleo, authority_id)),
    ]

    out: Dict[bytes, str] = {}
    for name, secret in base:
        out.setdefault(secret, name)
        for info_name, info in infos:
            k = hkdf(secret, m.salt, info, 32)
            out.setdefault(k, f"HKDF[{info_name}]({name})")

    return sorted(((name, raw) for raw, name in out.items()), key=lambda x: x[0])


def test_00_fixture_real_y_pareja_ed25519(material: Material):
    assert len(material.pub) == 32
    assert len(material.priv) == 32
    assert len(material.blob) > 100_000
    assert len(material.ciphertext) == int(material.header["ciphertext_length"])
    assert material.header["algorithm"] == "AES-256-GCM"
    assert material.header["kdf"] == "HKDF-SHA256"

    derived_pub = (
        Ed25519PrivateKey.from_private_bytes(material.priv)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    assert derived_pub == material.pub, (
        "La .priv entregada no corresponde a la .pub; el escenario de "
        "compromiso total del plano de firma no sería válido."
    )


def test_10_atacante_externo_no_descifra_con_material_robado(material: Material):
    candidates = derived_key_candidates(material)

    aad_variants = [
        ("aad_exacta", material.aad),
        ("aad_vacia", b""),
        ("header_raw", material.header_raw),
        ("manifest_raw", material.manifest_bytes),
        ("artifact_id", str(material.header["artifact_id"]).encode()),
    ]

    wins = []
    for key_name, key in candidates:
        if len(key) != 32:
            continue
        for aad_name, aad in aad_variants:
            pt = try_aesgcm(key, material.nonce, material.ciphertext, aad)
            if pt is not None:
                wins.append(
                    {
                        "key": key_name,
                        "aad": aad_name,
                        "n_bytes": len(pt),
                        "sha256": hashlib.sha256(pt).hexdigest(),
                        "pdf_magic": pt.startswith(b"%PDF"),
                    }
                )

    assert not wins, (
        "VULNERACIÓN: material de firma/metadata pública produjo un plaintext "
        f"autenticado por AES-GCM. Evidencia={wins[:10]}"
    )


def test_20_atacante_no_desenvuelve_kdoc_desde_wrap_recuperacion(material: Material):
    wrap = material.header.get("wrap_recuperacion")
    assert isinstance(wrap, dict), "El artefacto real no contiene wrap_recuperacion."

    wrap_nonce = b64d(str(wrap["nonce"]))
    wrap_ct = b64d(str(wrap["ct"]))

    artifact_id = str(material.header["artifact_id"])
    nucleo = str(material.header["plaintext_nucleo"])
    authority_id = str(material.header["authority_id"])
    rec_info = info_ligada(INFO_REC, artifact_id, nucleo, authority_id)

    wins = []

    for name, secret in candidate_secrets(material):
        for mode, k_rec in (
            ("directo", secret),
            ("hkdf_rec_exacta", hkdf(secret, material.salt, rec_info, 32)),
        ):
            if len(k_rec) != 32:
                continue

            expected_nonce = exact_wrap_nonce(k_rec, material.header)

            for nonce_name, nonce in (
                ("nonce_publicado", wrap_nonce),
                ("nonce_derivado", expected_nonce),
            ):
                k_doc = try_aesgcm(k_rec, nonce, wrap_ct, INFO_REC)
                if k_doc is None:
                    continue

                pt = None
                if len(k_doc) == 32:
                    pt = try_aesgcm(
                        k_doc,
                        material.nonce,
                        material.ciphertext,
                        material.aad,
                    )

                wins.append(
                    {
                        "candidate": name,
                        "mode": mode,
                        "nonce": nonce_name,
                        "k_doc_len": len(k_doc),
                        "plaintext_recuperado": pt is not None,
                        "plaintext_sha256": hashlib.sha256(pt).hexdigest() if pt else None,
                    }
                )

    assert not wins, (
        "VULNERACIÓN: el wrap de recuperación permitió extraer K_doc usando "
        f"material comprometido/público. Evidencia={wins[:10]}"
    )


def import_credencial():
    here = Path(__file__).resolve()
    candidates = [here.parent.parent, here.parent]
    for root in candidates:
        if (root / "modules" / "spartaco_seguridad" / "credencial.py").is_file():
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            break

    return importlib.import_module("modules.spartaco_seguridad.credencial")


def engine_candidate_subset(material: Material) -> List[Tuple[str, bytes]]:
    all_candidates = candidate_secrets(material)

    priority_tokens = (
        "priv", "pub", "salt", "nonce",
        "artifact_id", "authority_id",
        "plaintext_nucleo", "ciphertext_digest",
        "tag_auth", "tag_def",
        "wrap_recuperacion", "firma",
    )

    chosen = []
    seen = set()
    for name, raw in all_candidates:
        if any(tok in name for tok in priority_tokens):
            if raw not in seen:
                chosen.append((name, raw))
                seen.add(raw)

    return chosen[:48]


def _assert_engine_denied(result, context: str):
    assert isinstance(result, dict), f"{context}: respuesta no dict: {type(result)!r}"
    assert not result.get("ok"), f"VULNERACIÓN por motor ({context}): {result!r}"
    assert "plaintext" not in result, f"VULNERACIÓN: plaintext expuesto ({context})"


def test_30_motor_real_no_abre_solo_con_blob_manifest_pub_priv(material: Material):
    cred = import_credencial()

    result = cred.abrir_documento(
        material.blob,
        manifiesto=material.manifest,
        pub_bytes=material.pub,
    )
    _assert_engine_denied(result, "sin secretos")


@pytest.mark.parametrize(
    "source_name",
    ["priv", "pub"],
)
def test_40_motor_no_confunde_clave_firma_con_secreto_apertura(
    material: Material,
    source_name: str,
):
    cred = import_credencial()
    secret = material.priv if source_name == "priv" else material.pub

    attacks = [
        dict(secreto_raiz=secret),
        dict(secreto_autenticacion=secret, secreto_sesion=secret),
        dict(secreto_autenticacion=material.priv, secreto_sesion=material.pub),
        dict(secreto_autenticacion=material.pub, secreto_sesion=material.priv),
    ]

    for i, kwargs in enumerate(attacks):
        result = cred.abrir_documento(
            material.blob,
            manifiesto=material.manifest,
            pub_bytes=material.pub,
            **kwargs,
        )
        _assert_engine_denied(result, f"{source_name}/ataque#{i}")


def test_50_motor_no_es_oraculo_con_candidatos_derivados_de_lo_robado(material: Material):
    cred = import_credencial()
    candidates = engine_candidate_subset(material)

    wins = []
    attempts = 0

    for (auth_name, auth), (sess_name, sess) in itertools.product(candidates, repeat=2):
        attempts += 1
        result = cred.abrir_documento(
            material.blob,
            manifiesto=material.manifest,
            pub_bytes=material.pub,
            secreto_autenticacion=auth,
            secreto_sesion=sess,
        )
        if isinstance(result, dict) and result.get("ok"):
            pt = result.get("plaintext")
            wins.append(
                {
                    "auth": auth_name,
                    "session": sess_name,
                    "has_plaintext": isinstance(pt, (bytes, bytearray)),
                    "n_bytes": len(pt) if isinstance(pt, (bytes, bytearray)) else None,
                    "sha256": hashlib.sha256(pt).hexdigest()
                    if isinstance(pt, (bytes, bytearray)) else None,
                }
            )
            break

    assert attempts > 0
    assert not wins, (
        "VULNERACIÓN: el propio motor abrió el documento usando secretos "
        f"derivados exclusivamente del material robado/público. {wins}"
    )


def test_60_recuperacion_no_acepta_material_de_firma_o_metadata_publica(material: Material):
    cred = import_credencial()
    candidates = engine_candidate_subset(material)

    wins = []
    for name, candidate in candidates:
        result = cred.recuperar(
            material.blob,
            manifiesto=material.manifest,
            pub_bytes=material.pub,
            secreto_recuperacion=candidate,
        )
        if isinstance(result, dict) and result.get("ok"):
            pt = result.get("plaintext")
            wins.append(
                {
                    "candidate": name,
                    "has_plaintext": isinstance(pt, (bytes, bytearray)),
                    "n_bytes": len(pt) if isinstance(pt, (bytes, bytearray)) else None,
                    "sha256": hashlib.sha256(pt).hexdigest()
                    if isinstance(pt, (bytes, bytearray)) else None,
                }
            )
            break

    assert not wins, (
        "VULNERACIÓN: recuperar() aceptó material derivado del plano de "
        f"firma/metadata pública. Evidencia={wins}"
    )


def test_70_no_hay_reutilizacion_literal_obvia_de_privada_como_material_cifrado(material: Material):
    public_surface = material.blob + material.manifest_bytes

    assert material.priv not in public_surface, (
        "VULNERACIÓN CRÍTICA: la clave privada aparece literalmente dentro "
        "del blob/manifiesto."
    )


def test_99_resumen_de_superficie(material: Material, capsys):
    base = candidate_secrets(material)
    engine = engine_candidate_subset(material)
    print("\n=== SPARTACO / COMPROMISO TOTAL DEL PLANO DE FIRMA ===")
    print(f"Blob real:              {len(material.blob):,} bytes")
    print(f"Ciphertext real:        {len(material.ciphertext):,} bytes")
    print(f"Manifest real:          {len(material.manifest_bytes):,} bytes")
    print(f"Priv Ed25519:           {len(material.priv)} bytes")
    print(f"Pub Ed25519:            {len(material.pub)} bytes")
    print(f"Candidatos externos:    {len(base)}")
    print(f"Candidatos motor:       {len(engine)}")
    print(f"Combinaciones motor:    {len(engine) ** 2:,}")
    print("Resultado esperado:     NINGÚN PLAINTEXT SIN IKM LEGÍTIMO")
    print("========================================================\n")
    assert True
