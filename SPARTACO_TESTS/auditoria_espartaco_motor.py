"""Motor independiente del auditor. No importa módulos de producción.

Nunca concede PASS a partir de texto, comentarios, etiquetas o tests autoescritos
por el objetivo. El análisis AST es una barrera adicional, NO prueba formal de
ausencia de criptografía escondida o de ejecución dinámica.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "modules"
BASELINE = Path(__file__).with_name("contrato_original_espartaco.json")
# Sello del expediente original generado antes de ejecutar los tests.
BASELINE_SHA256 = "74fdeb498e78d025b612978fb74755209a905dee0ea13955bfdf5f50e6a4c73c"

BOUNDARY_PATHS = (
    "modules/spartaco_seguridad/user.py",
    "modules/interfaz/paquetes/spartaco_ui/Spartaco_UI.py",
    "modules/interfaz/paquetes/spartaco_ui/capa_universal.py",
    "modules/interfaz/paquetes/spartaco_ui/vista_user.py",
    "modules/interfaz/paquetes/spartaco_ui/interfaz_3.py",
)

FORBIDDEN_MODULES = (
    "cryptography", "Crypto", "Cryptodome", "nacl", "OpenSSL",
    "argon2", "bcrypt", "pyaes", "fernet", "pycryptodome",
)
# Una importación de un recurso Spartaco (por ejemplo CREDENCIAL) SÍ es válida;
# una importación directa de librerías criptográficas en USER/UI NO lo es.
FORBIDDEN_CONSTRUCTORS = (
    "AESGCM", "ChaCha20Poly1305", "Fernet", "MultiFernet",
    "PBKDF2HMAC", "Scrypt", "Ed25519PrivateKey", "Cipher",
    "encrypt", "decrypt", "derive_key", "pbkdf2_hmac", "scrypt",
)


def load_baseline() -> dict:
    raw = BASELINE.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != BASELINE_SHA256:
        raise AssertionError("EXPEDIENTE_ORIGINAL_ALTERADO: SHA256 no coincide")
    return json.loads(raw)


def divergencias_baseline(original: Mapping[str, list[str]], actual: Mapping[str, list[str]]) -> list[str]:
    fallos = []
    for recurso, capacidades in sorted(original.items()):
        perdidas = set(capacidades) - set(actual.get(recurso, []))
        for capability in sorted(perdidas):
            fallos.append(f"CAPACIDAD_ORIGINAL_ELIMINADA: {recurso}.{capability}")
    return fallos


def _expr_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _expr_name(node.value)
        return f"{head}.{node.attr}" if head else node.attr
    return ""


def crypto_violations(source: str, path: str = "<source>") -> list[str]:
    tree = ast.parse(source, filename=path)
    errors: list[str] = []
    import_names: dict[str, str] = {}
    forbidden_alias: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                import_names[alias.asname or name.split(".")[0]] = name
                if any(name == x or name.startswith(x + ".") for x in FORBIDDEN_MODULES):
                    errors.append(f"{path}:{node.lineno} CRYPTO_IMPORT_BYPASS: {name}")
                    forbidden_alias.add(alias.asname or name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            name = node.module or ""
            if any(name == x or name.startswith(x + ".") for x in FORBIDDEN_MODULES):
                errors.append(f"{path}:{node.lineno} CRYPTO_IMPORT_BYPASS: from {name}")
                forbidden_alias.update((a.asname or a.name) for a in node.names)
            for alias in node.names:
                import_names[alias.asname or alias.name] = name + "." + alias.name
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        full = _expr_name(node.func)
        root = full.split(".", 1)[0]
        if root in forbidden_alias:
            errors.append(f"{path}:{node.lineno} CRYPTO_DIRECT_USE: {full}")
        # Do not accept direct encryption primitives in orchestrator/UI, even if
        # imported under a local alias or constructed via injection.
        if any(part in FORBIDDEN_CONSTRUCTORS for part in full.split(".")):
            errors.append(f"{path}:{node.lineno} CRYPTO_PARALLEL_PRIMITIVE: {full}")
        if full in ("__import__", "importlib.import_module", "import_module"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                name = node.args[0].value
                if any(name == x or name.startswith(x + ".") for x in FORBIDDEN_MODULES):
                    errors.append(f"{path}:{node.lineno} CRYPTO_DYNAMIC_IMPORT: {name}")
            elif path.endswith("/spartaco_seguridad/user.py"):
                # USER no necesita carga dinamica no auditable para cifrar.
                # Las capas de catalogo/UI si cargan recursos por inventario.
                errors.append(f"{path}:{node.lineno} IMPORT_DINAMICO_NO_AUDITABLE: {full}")
    return sorted(set(errors))


def find_python_functions(path: Path) -> set[str]:
    t = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {n.name for n in t.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def find_js_functions(source: str) -> set[str]:
    return set(re.findall(r"\b(?:async\s+)?function\s+(ui3[A-Za-z0-9_]+)\s*\(", source))


def unregistered_public(public: set[str], catalog: set[str]) -> list[str]:
    return sorted(public - catalog)


def extra_in_catalog(public: set[str], catalog: set[str]) -> list[str]:
    return sorted(catalog - public)


def get_call_names(source: str) -> set[str]:
    return {_expr_name(n.func) for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call)}
