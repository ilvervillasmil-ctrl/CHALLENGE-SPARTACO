"""Prueba de integración real contra el dispatcher, en HOME aislado.

No hay mocks de éxito de autoridades. Únicamente se observan llamadas
reales y se introduce un rechazo forzado para falsificar la ruta de alta.
Este archivo NO se autodescubre por pytest; lo ejecuta el test principal
como subproceso limpio para no compartir sesiones, keysets ni usuarios.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

from modules.interfaz.paquetes.spartaco_ui import Spartaco_UI as web
from modules.spartaco_seguridad import user as USER
from modules.spartaco_seguridad import generador_claves as GK


def guard(cond, why):
    if not cond:
        raise AssertionError(why)


def text(x):
    return {'tipo': 'texto', 'valor': str(x)}


def archivo(b):
    return {'tipo': 'bytes_b64', 'valor': base64.b64encode(b).decode('ascii'), 'nombre': 'documento.png'}


def run(action, args):
    return web.ejecutar_accion_usuario({'accion_id': action, 'inputs': args})


def registration(alias, dev='iphone-ci'):
    return run('USER.alta', {'nombre': text('Auditoria'), 'apellido': text('Aislada'),
                             'alias': text(alias), 'dispositivo_id': text(dev)})


def login(alias, priv, kit, dev='iphone-ci'):
    return run('USER.entrar_con_paquetes', {
        'alias': text(alias), 'dispositivo_id': text(dev),
        'paquete_priv': archivo(priv), 'paquete_kit': archivo(kit),
    })


def decode_packet(result, name):
    obj = result.get(name)
    guard(isinstance(obj, dict), f'{name}: SIN_ARCHIVO_CERRADO')
    guard(not any(k in obj for k in ('manifiesto','kit','plaintext','privada','secreto')),
          f'{name}: MANIFIESTO_O_SECRETO_EN_RESPUESTA_SEPARADA')
    b64 = obj.get('b64')
    guard(isinstance(b64, str) and bool(b64), f'{name}: SIN_BASE64')
    raw = base64.b64decode(b64, validate=True)
    guard(raw.startswith(b'\x89PNG\r\n\x1a\n'), f'{name}: PNG_INVALIDO')
    # El manifiesto EXTERIOR puede ser metadato autenticado de arranque.
    # La confidencialidad del manifiesto INTERIOR se comprueba con el spy
    # de cierres, no buscando la palabra 'manifiesto' en el PNG.
    guard(len(raw) < 6_000_000, f'{name}: TAMAÑO_EXCESIVO')
    return raw


def tamper_png_payload_with_valid_crc(data):
    """Alteración en spRt con CRC recalculado: el rechazo debe ser de
    autenticidad de la carga, no meramente del CRC de la imagen.
    """
    import struct
    import zlib
    b = bytearray(data)
    pos = 8
    while pos + 12 <= len(b):
        n = struct.unpack('>I', b[pos:pos+4])[0]
        if pos + n + 12 > len(b):
            break
        typ = bytes(b[pos+4:pos+8])
        if typ == b'spRt' and n > 8:
            byte_index = pos + 8 + max(4, n//2)
            b[byte_index] ^= 1
            new_crc = zlib.crc32(bytes(b[pos+4:pos+8+n])) & 0xffffffff
            b[pos+8+n:pos+12+n] = struct.pack('>I', new_crc)
            return bytes(b)
        pos += n + 12
    raise AssertionError('NO_HAY_CARGA_spRt_AUDITABLE: adaptar test al nuevo formato autenticado')


def main():
    root = Path.home()
    guard('SPARTACO_AUDIT_ISOLATED' in os.environ, 'HOME_NO_AISLADO')
    guard(root.resolve() == Path(os.environ['SPARTACO_AUDIT_ISOLATED']).resolve(), 'HOME_NO_AISLADO')
    status = GK.configurar_almacen(str(root / 'keys_audit.json'))
    guard(status.get('ok') is True, 'ALMACEN_IKM_NO_AISLADO')

    # Must spy on real authority, not emulate a successful authority.
    spies = {'cerrar': 0, 'abrir': 0}
    cierre_evidencias = []
    real_cerrar = USER.CredencialUser.cerrar
    real_abrir = USER.CredencialUser.abrir

    def cerrar(*args, **kwargs):
        spies['cerrar'] += 1
        out = real_cerrar(*args, **kwargs)
        if out.get('ok'):
            cierre_evidencias.append((bytes(args[0]), out.get('manifiesto')))
        return out
    def abrir(*args, **kwargs):
        spies['abrir'] += 1
        return real_abrir(*args, **kwargs)
    USER.CredencialUser.cerrar = staticmethod(cerrar)
    USER.CredencialUser.abrir = staticmethod(abrir)

    a = registration('auditor-uno')
    guard(a.get('ok') is True, f'ALTA_RECHAZADA: {a.get("concepto") or a.get("error")}')
    guard(a.get('kit_ok') is True, 'ALTA_OK_CON_KIT_INCOMPLETO')
    guard('kit' not in a, 'FILTRACION_KIT_EN_CLARO')
    guard('ruta_priv' not in a, 'FILTRACION_RUTA_PRIVADA')
    guard('ruta_priv' not in a.get('archivos', {}), 'FILTRACION_OUTPUT_PATH_PRIVADA')
    guard('ruta_pub' in a.get('archivos', {}), 'FALTA_PUBLICA')
    guard(spies['cerrar'] >= 4, 'DOBLE_CIERRE_DE_MANIFIESTOS_NO_DEMOSTRADO: API CREDENCIAL ACTUAL')
    priv, kit = decode_packet(a, 'paquete_priv'), decode_packet(a, 'paquete_kit')
    # Se exige la confidencialidad de los dos primeros documentos internos.
    # En el API actual CREDENCIAL.proteger devuelve (blob, manifiesto), por
    # ello se hacen dos llamadas por paquete: dentro y fuera.
    for inicio, png, nombre in ((0, priv, 'PRIV'), (2, kit, 'KIT')):
        guard(inicio+1 < len(cierre_evidencias), f'{nombre}: FALTA_ENVOLTURA')
        contenido_interno, man_interno = cierre_evidencias[inicio]
        guard(contenido_interno not in png, f'{nombre}: TEXTO_ORIGINAL_VISIBLE')
        guard(isinstance(man_interno, dict), f'{nombre}: MANIFIESTO_INTERIOR_AUSENTE')
        manifiesto_serializado = json.dumps(man_interno, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        guard(manifiesto_serializado not in png, f'{nombre}: MANIFIESTO_INTERIOR_VISIBLE')
    guard(priv != kit, 'PAQUETES_IDENTICOS')
    guard('session_id' in a, 'NO_SESION_INICIAL')
    guard(run('USER.salir', {'session_id': text(a['session_id'])}).get('ok') is True, 'NO_SALIO_DE_ALTA')

    opened = login('auditor-uno', priv, kit)
    guard(opened.get('ok') is True and opened.get('session_id'),
          f'ENTRADA_RECHAZADA: {opened.get("concepto") or opened.get("error")}')
    guard(spies['abrir'] >= 2, 'NO_USA_CREDENCIAL_PARA_ABRIR_PRIV_Y_KIT')
    guard(run('USER.salir', {'session_id': text(opened['session_id'])}).get('ok') is True, 'SESION_NO_CERRABLE')

    broken = tamper_png_payload_with_valid_crc(priv)
    bad = login('auditor-uno', broken, kit)
    guard(bad.get('ok') is False and not bad.get('session_id'), 'FAIL_OPEN_CIPHERTEXT_ALTERADO_CON_CRC_VALIDO')
    wrong = login('auditor-uno', priv, kit, dev='aparato-desconocido')
    guard(wrong.get('ok') is False and not wrong.get('session_id'), 'FAIL_OPEN_DISPOSITIVO_NO_VINCULADO')

    for label, malformed in (
        ('TRUNCADO', priv[:32]),
        ('NO_PNG', b'credencial-falsa'),
        ('DATOS_POST_IEND', priv + b'INYECCION'),
        ('TAMANO_EXCESIVO', b'X' * 6_000_001),
    ):
        ans = login('auditor-uno', malformed, kit)
        guard(ans.get('ok') is False and not ans.get('session_id'), f'FAIL_OPEN_{label}')

    b = registration('auditor-dos')
    guard(b.get('ok') is True, 'SEGUNDA_CUENTA_NO_CREADA')
    second_kit = decode_packet(b, 'paquete_kit')
    guard(run('USER.salir', {'session_id': text(b['session_id'])}).get('ok') is True, 'SEGUNDA_SESION_INICIAL')
    crossed = login('auditor-uno', priv, second_kit)
    guard(crossed.get('ok') is False and not crossed.get('session_id'), 'FAIL_OPEN_KIT_CRUZADO')

    # Rejecting the authority must make USER fail closed and clean staging.
    count_before = spies['cerrar']
    USER.CredencialUser.cerrar = staticmethod(lambda *a, **k: {'ok': False, 'concepto': 'RECHAZO_AUTORIDAD_AUDITOR'})
    rejected = registration('auditor-tercero')
    guard(rejected.get('ok') is False and not rejected.get('session_id'), 'FAIL_OPEN_CREDENCIAL_RECHAZA_CIERRE')
    guard(USER.UserRepository.candidatos_alias('auditor-tercero') == [], 'CUENTA_PERSISTIDA_TRAS_RECHAZO')
    guard(spies['cerrar'] == count_before, 'INSTRUMENTACION_FALLA_EN_FASE_NEGATIVA')

    def negar_cuarto(*args, **kwargs):
        negar_cuarto.calls += 1
        if negar_cuarto.calls == 4:
            return {'ok': False, 'concepto': 'RECHAZO_CUARTO_CIERRE'}
        return real_cerrar(*args, **kwargs)
    negar_cuarto.calls = 0
    USER.CredencialUser.cerrar = staticmethod(negar_cuarto)
    partial = registration('auditor-cuarto')
    guard(negar_cuarto.calls >= 4, 'NO_LLEGO_AL_CUARTO_CIERRE')
    guard(partial.get('ok') is False and not partial.get('session_id'), 'FAIL_OPEN_CUARTO_CIERRE_DENEGADO')
    guard(USER.UserRepository.candidatos_alias('auditor-cuarto') == [], 'CUENTA_PERSISTIDA_TRAS_CIERRE_EXTERIOR_DENEGADO')

    # Restore and attack the opening authority; login may never pass.
    USER.CredencialUser.cerrar = staticmethod(cerrar)
    USER.CredencialUser.abrir = staticmethod(lambda *a, **k: {'ok': False, 'concepto': 'RECHAZO_AUTORIDAD_AUDITOR'})
    denied = login('auditor-uno', priv, kit)
    guard(denied.get('ok') is False and not denied.get('session_id'), 'FAIL_OPEN_CREDENCIAL_RECHAZA_APERTURA')
    USER.CredencialUser.abrir = staticmethod(abrir)

    # Falsificaciones de autoridad en la autenticación original.
    for cls, method, name in (
        (USER.ProteccionUser, 'probar_privada', 'PROTECCION'),
        (USER.VinculacionUser, 'probar', 'VINCULACION'),
        (USER.AccesoUser, 'autorizar', 'ACCESO'),
    ):
        original = getattr(cls, method)
        setattr(cls, method, staticmethod(lambda *a, **k: {'ok': False, 'estado': 'DENEGADO', 'concepto': 'AUDIT_RECHAZADO'}))
        try:
            attempt = login('auditor-uno', priv, kit)
            guard(attempt.get('ok') is False and not attempt.get('session_id'),
                  f'FAIL_OPEN_AUTORIDAD_{name}')
        finally:
            setattr(cls, method, staticmethod(original))

    print('ESPARTACO_E2E=PASS')
    print('CREDENCIAL_CIERRES_OBSERVADOS=', spies['cerrar'])
    print('CREDENCIAL_APERTURAS_OBSERVADAS=', spies['abrir'])
    print('FALSIFICACIONES=CRC_VALIDO_PAYLOAD_ALTERADO;DISPOSITIVO_AJENO;KIT_CRUZADO;CIERRE_DENEGADO;CUARTO_CIERRE_DENEGADO;APERTURA_DENEGADA;PROTECCION_DENEGADA;VINCULACION_DENEGADA;ACCESO_DENEGADO')


if __name__ == '__main__':
    main()
