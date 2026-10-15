# ===============================================================
# VPSI-TRUTH — test_d6_lector_calibracion.py
# ===============================================================
#
# D6 reader calibration: it does not invent APIs that USER does
# not declare.
#
# THESIS
# ------
# This file audits a single internal component of the D6 probe:
#     _spartaco_dvc_probe._cuentas_desde_indice(repositorio, alias)
#
# The reader must derive accounts exclusively from the API surface
# that the real repository declares (indice, cargar_perfil). It
# must NOT rely on helpers USER does not expose (buscar_aliases,
# buscar_fingerprint, etc.).
#
# If the reader depended on an invented helper, D6 would pass
# against a mock but fail in production with AttributeError — or,
# worse, produce a false PASS against a mock carrying the fake
# helper. This file prevents both.
#
# SCOPE
# -----
#   - Simulated repository exposing ONLY indice() and cargar_perfil().
#   - Valid state: three users, two sharing alias "repetible",
#     one with alias "distinto". Coherent fingerprints and profiles.
#
#   T1  Reader works with the declared surface only
#         - The simulated repo has no buscar_aliases attribute.
#         - _cuentas_desde_indice(repo, 'REPETIBLE') returns exactly
#           {id_a: fpr_a, id_b: fpr_b}.
#         - The returned index contains all users, not only matches.
#         - Alias matching is case-insensitive.
#
#   T2  Reader rejects contradictory state (parametrized ×4)
#         - huella_indice      : fingerprint in index differs from profile.
#         - huella_perfil      : profile fingerprint is empty.
#         - perfil_ausente     : user present in index without loadable profile.
#         - identidad_cruzada  : profile user_id differs from index key.
#         Each must raise AssertionError matching /D6_/. The reader
#         must NOT fabricate accounts from corrupt state.
#
#   T3  Reader does not invent nonexistent accounts
#         - Unknown alias returns empty dict, not an error.
#         - Distinguishes "no match" (legitimate) from "state is
#           broken" (must abort with D6_ witness).
#
# CONTRACT
# --------
#   - Contradictory state -> AssertionError whose message contains
#     a D6_* witness tag. Never a silent value.
#   - Missing match -> empty dict, no exception.
#   - Reader never calls helpers absent from the real repository
#     surface. The subject is not used as its own oracle.
#
# CONSTRAINTS
# -----------
#   - Does NOT attack credencial.py.
#   - Does NOT run the full D6 probe.
#   - Does NOT verify the real system: uses a simulated repository
#     calibrated to the real declared surface.
#
# ROLE IN THE SUITE
# -----------------
#   test_credencial_aniquilador.py .......... attacks credencial.py
#   test_credencial_redteam.py ............... 35 independent attacks
#   test_credencial_redteam_continuacion.py .. 14 additional attacks
#   test_D1_D7_... ........................... audits the package
#                                              as a declaration
#   test_d6_lector_calibracion.py ............ audits the auditor:
#                                              the D6 reader is
#                                              calibrated against
#                                              the surface USER
#                                              actually declares.
#
# PRINCIPLE
# ---------
#   The witness cannot invent facts. The auditor is also audited,
#   and may only use the API the subject declares it has.
# ===============================================================
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

RUTA = Path(__file__).resolve().with_name('_spartaco_dvc_probe.py')
SPEC = importlib.util.spec_from_file_location('_dvc_probe_calibracion_autolectura', RUTA)
assert SPEC is not None and SPEC.loader is not None, 'SONDA_NO_CARGABLE'
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def _repositorio_simulado(filas, perfiles):
    """Superficie mínima que existe realmente: indice y cargar_perfil.

    No define buscar_aliases, buscar_fingerprint ni otros auxiliares.
    """
    class Repositorio:
        def __init__(self, uid=''):
            self.uid = uid

        @staticmethod
        def indice():
            return {'ok': True, 'usuarios': filas}

        def cargar_perfil(self):
            if self.uid not in perfiles:
                return {'ok': False, 'concepto': 'AUSENTE'}
            return {'ok': True, 'perfil': perfiles[self.uid]}
    return Repositorio


def _estado_valido():
    filas = {
        'id_a': {'alias': 'repetible', 'fingerprint': 'fpr_a'},
        'id_b': {'alias': 'repetible', 'fingerprint': 'fpr_b'},
        'id_c': {'alias': 'distinto', 'fingerprint': 'fpr_c'},
    }
    perfiles = {
        uid: {'user_id': uid, 'alias': fila['alias'], 'fingerprint': fila['fingerprint']}
        for uid, fila in filas.items()
    }
    return filas, perfiles


def test_lector_d6_no_necesita_helpers_de_alias():
    filas, perfiles = _estado_valido()
    repositorio = _repositorio_simulado(filas, perfiles)
    assert not hasattr(repositorio, 'buscar_aliases')
    cuentas, indice = P._cuentas_desde_indice(repositorio, 'REPETIBLE')
    assert cuentas == {'id_a': 'fpr_a', 'id_b': 'fpr_b'}
    assert set(indice) == set(filas)


@pytest.mark.parametrize('mutacion', ['huella_indice', 'huella_perfil', 'perfil_ausente', 'identidad_cruzada'])
def test_lector_d6_rechaza_indice_contradictorio(mutacion):
    filas, perfiles = _estado_valido()
    if mutacion == 'huella_indice':
        filas['id_a']['fingerprint'] = 'otra-huella'
    elif mutacion == 'huella_perfil':
        perfiles['id_a']['fingerprint'] = ''
    elif mutacion == 'perfil_ausente':
        del perfiles['id_a']
    elif mutacion == 'identidad_cruzada':
        perfiles['id_a']['user_id'] = 'id_b'
    with pytest.raises(AssertionError, match=r'D6_'):
        P._cuentas_desde_indice(_repositorio_simulado(filas, perfiles), 'repetible')


def test_lector_d6_no_inventa_cuentas_inexistentes():
    filas, perfiles = _estado_valido()
    cuentas, _ = P._cuentas_desde_indice(_repositorio_simulado(filas, perfiles), 'alias-inexistente')
    assert cuentas == {}
