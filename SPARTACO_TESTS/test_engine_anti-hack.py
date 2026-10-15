"""Pieza Engine sola — no es el rompecabezas Spartaco completo.

Alcance (binario pass/fail, sin salidas blandas):
  Estos tests ejercen solo `core.engine.Engine.evaluar_universal` con módulos
  CONTENEDOR sintéticos en tmp. No atraviesan protección, credencial,
  manifiesto firmado, centinela, launcher ni el resto de defensas del repo.

  Por tanto NO demuestran bypass del sistema Spartaco. Solo fijan el
  comportamiento de ESTA pieza en aislamiento.

  AntiHackValidation es facilidad interna: aquí se usa como contraste de
  API directa, no como requisito de que `evaluar_universal` la invoque.
"""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(scope="module")
def engine_mod():
    return importlib.import_module("core.engine")


def _write_module(root: Path, engine_mod, *, name: str, rol: str, id_: str, body: str) -> Path:
    mod_dir = root / name
    mod_dir.mkdir(parents=True, exist_ok=True)
    perms = list(engine_mod.PERMISOS_AUTORIZA_ENGINE)
    flags = list(engine_mod.BANDERAS_REPORTING)
    estados = list(engine_mod.ESTADOS_CANONICOS)
    (mod_dir / "__init__.py").write_text(
        body
        + f"""

CONTENEDOR = {{
    "esquema": {engine_mod.ESQUEMA_CONTRATO_REQUERIDO!r},
    "version_contrato": {engine_mod.VERSION_CONTRATO_REQUERIDA!r},
    "version_modulo": "0.0.1-attack",
    "id": {id_!r},
    "nombre": {name!r},
    "rol": {rol!r},
    "descripcion": "fixture aislado de pieza Engine",
    "funcion": "echo/cyclic para borde evaluar_universal",
    "no_hace": ["no simula cadena Spartaco completa"],
    "autoridad": ["solo hechos de prueba"],
    "conocimiento_exportable": ["hechos"],
    "requiere": [],
    "autoriza_engine": {{k: True for k in {perms!r}}},
    "consultas_soportadas": ["evaluar_universal"],
    "capacidades": {{
        "evaluar_universal": evaluar_universal,
        "reporte": reporte,
    }},
    "capacidades_meta": {{
        "evaluar_universal": {{
            "descripcion": "a",
            "entrada": "hechos",
            "validar_esquema": "n/a",
            "salida": "dict",
            "acceso_archivos": [],
        }},
        "reporte": {{
            "descripcion": "r",
            "entrada": "none",
            "validar_esquema": "n/a",
            "salida": "dict",
            "acceso_archivos": [],
        }},
    }},
    "reporting": {{k: True for k in {flags!r}}},
    "estados_validos": {estados!r},
    "invariantes": ["aislamiento de pieza"],
    "estabilidad": "experimental",
    "acceso": "test",
    "compatible_desde": "1.0",
    "acceso_archivos": [],
    "api_engine": {engine_mod.API_ENGINE_ACTUAL!r},
    "validar_esquema": ["self"],
}}
""",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def attack_echo_root(tmp_path, engine_mod):
    body = '''
from __future__ import annotations
from typing import Any, Dict, Optional

def evaluar_universal(hechos: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"hechos": dict(hechos or {}), "ejecutadas": ["echo"]}

def reporte():
    return {"ok": True}
'''
    return _write_module(
        tmp_path / "modules", engine_mod, name="echo", rol="CT", id_="id.echo", body=body
    )


@pytest.fixture
def attack_cyclic_publisher_root(tmp_path, engine_mod):
    body = '''
from __future__ import annotations
from typing import Any, Dict, Optional

def evaluar_universal(hechos: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cyclic = {}
    cyclic["self"] = cyclic
    out = dict(hechos or {})
    if "bomb" not in out:
        out["bomb"] = cyclic
    return {"hechos": out, "ejecutadas": ["cyclic"]}

def reporte():
    return {"ok": True}
'''
    return _write_module(
        tmp_path / "modules", engine_mod, name="cyclic", rol="CT", id_="id.cyclic", body=body
    )


def test_pieza_engine_acepta_hechos_lista_de_pares(engine_mod, attack_echo_root):
    """Verdadero/falso: en aislamiento, list-of-pairs entra a evaluar_universal."""
    with pytest.raises(engine_mod.StructuralIntegrityError):
        engine_mod.AntiHackValidation.validate_hechos([("a", 1)])

    eng = engine_mod.Engine(attack_echo_root, strict=True)
    exp = eng.evaluar_universal(hechos=[("a", 1)], max_pasadas=1)  # type: ignore[arg-type]

    assert exp["operacion"] == "evaluar_universal"
    assert exp["hechos"] == {"a": 1}
    assert exp["origen"] == {"a": "PETICION"}
    assert exp["estado"] == "PARCIAL"
    assert exp["punto_fijo"] is False


def test_pieza_engine_acepta_hechos_ciclicos_sin_CircularityDetectedError(
    engine_mod, attack_echo_root
):
    """Verdadero/falso: ciclo en entrada no dispara CircularityDetectedError en este borde."""
    cyclic: dict[str, Any] = {}
    cyclic["self"] = cyclic

    with pytest.raises(engine_mod.CircularityDetectedError):
        engine_mod.AntiHackValidation.validate_hechos(cyclic)

    eng = engine_mod.Engine(attack_echo_root, strict=True)
    exp = eng.evaluar_universal(hechos=cyclic, max_pasadas=1)

    assert exp["operacion"] == "evaluar_universal"
    assert "self" in exp["hechos"]
    # dict(hechos) copia superficial: el valor "self" sigue siendo el ciclo original
    nodo = exp["hechos"]["self"]
    assert isinstance(nodo, dict)
    assert nodo["self"] is nodo
    assert exp["estado"] == "PARCIAL"


def test_pieza_engine_absorbe_bomb_ciclico_publicado_por_modulo(
    engine_mod, attack_cyclic_publisher_root
):
    """Verdadero/falso: módulo sintético puede publicar bomb cíclico y la pieza lo guarda."""
    eng = engine_mod.Engine(attack_cyclic_publisher_root, strict=True)
    exp = eng.evaluar_universal(hechos={}, max_pasadas=2)

    assert "bomb" in exp["hechos"]
    bomb = exp["hechos"]["bomb"]
    assert isinstance(bomb, dict)
    assert bomb["self"] is bomb
    assert exp["estado"] == "PARCIAL"


def test_pieza_engine_transporta_manifiesto_invalido_dentro_de_hechos(
    engine_mod, attack_echo_root
):
    """Verdadero/falso: manifiesto inválido como valor de hecho se transporta en esta pieza."""
    payload = {
        "manifiesto": {"cuerpo": {"x": 1}, "firma": "x", "extra": "inyectado"},
    }
    with pytest.raises(engine_mod.StructuralIntegrityError):
        engine_mod.AntiHackValidation.validate_manifiesto(payload["manifiesto"])

    eng = engine_mod.Engine(attack_echo_root, strict=True)
    exp = eng.evaluar_universal(hechos=payload, max_pasadas=1)

    assert exp["hechos"]["manifiesto"]["extra"] == "inyectado"
    assert exp["estado"] == "PARCIAL"
    assert exp["punto_fijo"] is False


def test_antihack_interno_rechaza_pub_bytes_y_artefacto_vacios(engine_mod):
    """Verdadero/falso: AntiHack directo corta basura (contraste de facilidad interna)."""
    AH = engine_mod.AntiHackValidation
    with pytest.raises(engine_mod.StructuralIntegrityError):
        AH.validate_pub_bytes(b"corta")
    AH.validate_pub_bytes(b"\x00" * 32)
    with pytest.raises(engine_mod.StructuralIntegrityError):
        AH.validate_artefacto(b"")
    AH.validate_artefacto(b"data")


def test_alcance_no_es_cadena_spartaco_completa(engine_mod, attack_echo_root):
    """Verdadero/falso: este harness no carga protección/credencial/centinela del repo."""
    eng = engine_mod.Engine(attack_echo_root, strict=True)
    roles = set(eng.registro.por_rol.keys())
    nombres = set(eng.registro.contenedores.keys())

    assert roles == {"CT"}
    assert nombres == {"echo"}
    assert "spartaco_seguridad" not in nombres
    assert "constante" not in nombres
    assert "interfaz" not in nombres
