"""Calibración del lector D6: no inventa APIs que USER no declare."""
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
