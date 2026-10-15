"""Adversarial calibration: if the auditor lets a mutant slip through, 
this test fails.
Mutants in AST/synthetic data. No production code is written.
"""
from __future__ import annotations
import ast
import importlib.util
import sys
from pathlib import Path

import pytest

RUTA = Path(__file__).resolve().parent / '_spartaco_dvc_motor.py'
spec = importlib.util.spec_from_file_location('_dvc_motor_cal', RUTA)
assert spec and spec.loader
M = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = M
spec.loader.exec_module(M)


@pytest.mark.parametrize('importacion', [
    'import cryptography',
    'from cryptography.hazmat.primitives.ciphers.aead import AESGCM',
    'import Crypto.Cipher',
    'from Crypto.Cipher import AES',
    'import nacl.secret',
    'import Cryptodome',
    'from pyaes import AESModeOfOperationCTR',
    'from fernet import Fernet',
    'x=__import__("cryptography.hazmat")',
    'x=eval("cryptography")',
])
def test_C01_mutantes_crypto_en_user(importacion):
    assert M.imports_ilegitimos(ast.parse(importacion)), 'MUTANTE_CRYPTO_NO_DETECTADO'


@pytest.mark.parametrize('mutante', [
    '''class CredencialUser:
 @staticmethod
 def cerrar(*a):
  return {'ok': True}
 @staticmethod
 def abrir(*a):
  return {'ok': True}
def _cerrar_puerta(*a): return CredencialUser.cerrar(*a)
def entrar_con_paquetes(*a): return CredencialUser.abrir(*a)
''',
    '''class CredencialUser:
 def cerrar(*a):
  CREDENCIAL.proteger(*a)
  return {'ok': True}
 def abrir(*a):
  CREDENCIAL.abrir_documento(*a)
  return {'ok': True}
def _cerrar_puerta(*a): return CredencialUser.cerrar(*a)
def entrar_con_paquetes(*a): return CredencialUser.abrir(*a)
''',
    '''class CredencialUser:
 def cerrar(*a): return CREDENCIAL.proteger(*a)
 def abrir(*a): return CREDENCIAL.abrir_documento(*a)
def _cerrar_puerta(*a): return {'ok': True}
def entrar_con_paquetes(*a): return {'ok': True}
''',
])
def test_C02_mutantes_puerta_falsa(mutante):
    assert M.detectar_pasarela(ast.parse(mutante)), 'MUTANTE_DELEGACION_NO_DETECTADO'


@pytest.mark.parametrize('programa', [
    'def autorizar(): return True\ndef autorizar(): return True',
    'class UserRepository: pass\nclass UserRepository: pass',
    'def entrar(): pass\ndef entrar(): pass',
])
def test_C03_sustituciones_silenciosas(programa):
    assert M.duplicados_publicos(ast.parse(programa)), 'MUTANTE_DUPLICADO_NO_DETECTADO'


@pytest.mark.parametrize('fragmento', [
    'dato("✔", "Test", "PASS")',
    "dato('ok', 'CI', 'OK')",
    'dato("CI", "Estado", "COMPLETE")',
    'status = "PASS"',
    "estado: 'OK'",
])
def test_C04_literal_ci_sin_medicion(fragmento):
    assert M.fuente_literal_pass(fragmento), 'MUTANTE_CI_LITERAL_NO_DETECTADO'


def test_C05_pass_sin_testigo_imposible():
    with pytest.raises(ValueError, match='PROBADO exige'):
        M.Evidencia('D1', 'mentira', M.PROBADO, 'todo bien')
    assert M.fallos([]), 'CERO_EVIDENCIAS_NO_ES_PASS'
    assert M.fallos([M.no_medible('D6', 'sin prueba', 'no corrio')]), 'NO_DEMOSTRABLE_NO_BLOQUEA'
    assert M.fallos([M.ev('D6', 'falsificado', False, 'resultado malo', '')]), 'CONTRADICCION_NO_BLOQUEA'


def test_C06_catalogo_mutado_no_iguala_backend():
    inv = {'recursos': {'USER': {'capacidades_recurso': ['alta','entrar_con_paquetes']}}}
    mutaciones = (
        {'USER.alta': object(), 'USER.actualizar_vinculacion': object()},
        {'USER.alta': object()},
        {'USER.alta': object(), 'USER.entrar_con_paquetes': object(), 'FANTASMA.entrar': object()},
    )
    for m in mutaciones:
        filas = M.comparar_catalogo(inv, m)
        assert M.fallos(filas), f'CATALOGO_MUTANTE_APROBADO: {m.keys()}'
    valido = M.comparar_catalogo(inv, {'USER.alta': object(), 'USER.entrar_con_paquetes': object()})
    assert not M.fallos(valido)


def test_C07_controles_positivos_evitan_falsos_bloqueos():
    arbol = ast.parse('import hashlib\nimport json\nfrom modules.spartaco_seguridad import credencial\n')
    assert not M.imports_ilegitimos(arbol), 'ALGORITMOS_DE_IDENTIDAD/ORQUESTACIÓN_LEGÍTIMOS_BLOQUEADOS'
    assert not M.fuente_literal_pass('if salida.returncode == 0:\n    print("PASS medido")\n')


def test_C08_control_autoridad_directa_valida():
    codigo = '''class CredencialUser:
 @staticmethod
 def cerrar(x):
  return CREDENCIAL.proteger(x)
 @staticmethod
 def abrir(x):
  return CREDENCIAL.abrir_documento(x)
def _cerrar_puerta(x): return CredencialUser.cerrar(x)
def entrar_con_paquetes(x): return CredencialUser.abrir(x)
'''
    assert not M.detectar_pasarela(ast.parse(codigo))


def test_C09_mutante_capa_declara_stdlib_y_importa_terceros():
    assert M.imports_ajenos_stdlib(ast.parse('import pandas'))
    assert M.imports_ajenos_stdlib(ast.parse('from cryptography.hazmat import hashes'))
    assert not M.imports_ajenos_stdlib(ast.parse('import pathlib\nfrom dataclasses import dataclass'))
