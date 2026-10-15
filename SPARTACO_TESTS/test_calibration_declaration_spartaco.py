# ===========================================================================
# SPARTACO-SECURITY — tests/test_calibracion_auditoria_dvc.py
# ===========================================================================
#
# ADVERSARIAL CALIBRATION: IF THE AUDITOR LETS A MUTANT SLIP THROUGH,
# THIS TEST FAILS.
#
# Mutants live in AST and synthetic data. No production code is written.
#
# WHAT THIS FILE DOES
# ---------------------------------------------------------------------------
# It calibrates the DVC audit motor that other files in the suite use.
# The motor is loaded by explicit path (importlib.util.spec_from_file_
# location) so it does not depend on PATH or sys.path.
#
# The motor exposes:
#
#   imports_ilegitimos        illegitimate cryptography imports
#   detectar_pasarela         false gateway / false delegation
#   duplicados_publicos       silently shadowed public definitions
#   fuente_literal_pass       literals of success embedded as data
#   comparar_catalogo         catalog vs backend divergence
#   imports_ajenos_stdlib     imports outside the standard library
#   Evidencia / PROBADO       evidence model
#   no_medible / ev / fallos  evidence helpers
#
# THE NINE CALIBRATION TESTS
# ---------------------------------------------------------------------------
#   C01  Ten ways to import unauthorized cryptography, all must be
#        detected:
#
#          import cryptography
#          from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#          import Crypto.Cipher
#          from Crypto.Cipher import AES
#          import nacl.secret
#          import Cryptodome
#          from pyaes import AESModeOfOperationCTR
#          from fernet import Fernet
#          x = __import__("cryptography.hazmat")
#          x = eval("cryptography")
#
#        Detection is not limited to the static import form; the
#        dynamic variants must be caught too.
#
#   C02  Three false-delegation mutants, all must be detected:
#
#          CredencialUser.cerrar/abrir return {'ok': True} with no call
#          CredencialUser.cerrar/abrir call CREDENCIAL but then return
#          {'ok': True} unconditionally (result discarded)
#          CredencialUser delegates correctly but _cerrar_puerta and
#          entrar_con_paquetes return {'ok': True} without delegating
#
#        These three cover the three failure modes of delegation:
#        not delegating, delegating and ignoring the result, and
#        delegating only at one level.
#
#   C03  Silently shadowed public definitions:
#
#          def autorizar twice
#          class UserRepository twice
#          def entrar twice
#
#        Python overwrites the first definition silently, which is one
#        of the simplest and most effective injection vectors. The
#        motor must detect the duplicates in the AST.
#
#   C04  Literals of CI success embedded as data:
#
#          dato("✔", "Test", "PASS")
#          dato('ok', 'CI', 'OK')
#          dato("CI", "Estado", "COMPLETE")
#          status = "PASS"
#          estado: 'OK'
#
#        The motor must distinguish these from measured results (see
#        C07).
#
#   C05  Evidence model invariants:
#
#          Evidencia('D1', 'lie', PROBADO, 'all good') must raise
#          ValueError matching 'PROBADO exige'
#          fallos([]) is falsy: zero evidence is not PASS
#          fallos([no_medible(...)]) is truthy: not measurable does
#          not block
#          fallos([ev(..., False, ...)]) is truthy: contradiction
#          blocks
#
#        The four cases fix the semantics of the evidence model.
#
#   C06  Catalog vs backend divergence:
#
#          three mutants that must fail (missing entry, ghost
#          resource, extra catalog entry)
#          one valid catalog that must not fail
#
#        Both directions of the bijection are verified: capabilities
#        missing from the catalog and entries with no backend.
#
#   C07  Positive controls: legitimate identity and orchestration
#        algorithms must not be blocked, and a measured result
#        printed conditionally is not a literal-of-CI. The motor must
#        distinguish data from measured evidence.
#
#   C08  Positive control of gateway detection: a genuinely
#        delegating adapter is accepted.
#
#   C09  Imports outside the standard library:
#
#          import pandas                    -> detected
#          from cryptography.hazmat import hashes -> detected
#          import pathlib / dataclasses     -> not detected
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It does not write production code.
#   - It does not modify the modules under audit.
#   - It does not certify the whole system: it certifies that the DVC
#     audit motor detects what it must detect and does not detect what
#     it must not detect.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# Other files in the suite (the unified hard audit, the D1-D7 declaration
# vs. conduct) use this motor to detect parallel cryptography, false
# delegation, shadowed definitions, and catalog divergence. Those uses
# assume the motor works. This file verifies precisely that. It is the
# same symmetric-calibration doctrine the metrological kernel and the
# UHCR auditor apply to their own instruments, applied here to the DVC
# audit motor. Without this file, the rest of the suite could be
# approving malicious code without anyone noticing.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# An instrument that cannot detect a known mutant cannot be trusted to
# detect an unknown one. An instrument that blocks legitimate code
# produces false alarms. This file calibrates the motor in both
# directions: every mutant must be detected, every legitimate case must
# be accepted. No production code is written to make the calibration
# pass. The mutants live in AST and synthetic data.
#
# ===========================================================================
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
