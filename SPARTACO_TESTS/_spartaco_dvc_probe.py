"""Sonda de ejecución REAL en proceso hijo. Nunca ejecutar con HOME de usuario."""
from __future__ import annotations

import base64
import json
import os
import struct
import sys
import zlib
from pathlib import Path


EVIDENCIAS = []


def exigir(hecho, nombre):
    if not hecho:
        raise AssertionError(nombre)
    EVIDENCIAS.append(nombre)
    print('EVIDENCIA', nombre)


def _cuentas_desde_indice(repositorio, alias):
    """Lee la persistencia declarada, no presupone buscar_aliases().

    La prueba deriva identidades de alta(), filas de indice() y perfiles
    de cargar_perfil(): tres observaciones independientes de un alias.
    No marca PROBADO un indice vacio, ambiguo o desincronizado.
    """
    indice = repositorio.indice()
    if (not isinstance(indice, dict) or indice.get('ok') is not True
            or not isinstance(indice.get('usuarios'), dict)):
        raise AssertionError('D6_INDICE_NO_RESUELTO')
    usuarios = indice['usuarios']
    encontrados = {}
    for uid, fila in usuarios.items():
        if not isinstance(uid, str) or not isinstance(fila, dict):
            raise AssertionError('D6_INDICE_FILA_INVALIDA')
        if str(fila.get('alias', '')).casefold() != alias.casefold():
            continue
        perfil_observado = repositorio(uid).cargar_perfil()
        if (not isinstance(perfil_observado, dict)
                or perfil_observado.get('ok') is not True
                or not isinstance(perfil_observado.get('perfil'), dict)):
            raise AssertionError('D6_PERFIL_NO_RESUELTO')
        perfil = perfil_observado['perfil']
        if (perfil.get('user_id') != uid
                or str(perfil.get('alias', '')).casefold() != alias.casefold()
                or not isinstance(perfil.get('fingerprint'), str)
                or not perfil['fingerprint']):
            raise AssertionError('D6_INDICE_PERFIL_DIVERGENTES')
        huella_indice = fila.get('fingerprint')
        if huella_indice is not None and huella_indice != perfil['fingerprint']:
            raise AssertionError('D6_HUELLA_NO_COINCIDE')
        encontrados[uid] = perfil['fingerprint']
    return encontrados, usuarios


def decodificar(paquete):
    assert isinstance(paquete, dict) and paquete.get('ok') is True
    assert 'manifiesto' not in paquete and 'plaintext' not in paquete
    return base64.b64decode(paquete['b64'], validate=True)


def mutar_ciphertext_con_crc_valido(png):
    """Conserva PNG, CRC, JSON y B64; altera el blob que procesa CREDENCIAL."""
    salida = bytearray(png[:8]); pos = 8; mutado = False
    while pos + 12 <= len(png):
        n = struct.unpack('>I', png[pos:pos + 4])[0]
        tipo = png[pos + 4:pos + 8]
        cuerpo = png[pos + 8:pos + 8 + n]
        if tipo == b'spRt':
            meta = json.loads(cuerpo[4:].decode('utf-8'))
            cifrado = bytearray(base64.b64decode(meta['blob'], validate=True))
            assert len(cifrado) >= 16
            cifrado[len(cifrado) // 2] ^= 1
            meta['blob'] = base64.b64encode(cifrado).decode('ascii')
            cuerpo = cuerpo[:4] + json.dumps(meta, sort_keys=True, separators=(',', ':')).encode()
            mutado = True
        salida += (struct.pack('>I', len(cuerpo)) + tipo + cuerpo
                   + struct.pack('>I', zlib.crc32(tipo + cuerpo) & 0xffffffff))
        pos += n + 12
        if tipo == b'IEND':
            break
    assert mutado and pos == len(png)
    return bytes(salida)


def main():
    # -I ignora PYTHONPATH; se inyecta SOLO el root conocido por ruta del test.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import modules.spartaco_seguridad.user as U
    from modules.spartaco_seguridad import generador_claves as GK

    home = Path.home().resolve()
    exigir(os.environ.get('ESPARTACO_DVC_HOME') == str(home), 'D6_HOME_EXCLUSIVO')
    exigir(GK.configurar_almacen(str(home / 'ikm.json')).get('ok') is True,
           'D6_IKM_ALMACEN_AISLADO')

    # Las autoridades siguen siendo las auténticas, solo se contabilizan llamadas.
    cierre_real, apertura_real = U.CredencialUser.cerrar, U.CredencialUser.abrir
    contadores = {'cerrar': 0, 'abrir': 0}
    cierres = []

    def cierre_observado(*a, **kw):
        contadores['cerrar'] += 1
        resultado = cierre_real(*a, **kw)
        if resultado.get('ok'):
            cierres.append({'plano': bytes(a[0]), 'manifiesto': resultado.get('manifiesto')})
        return resultado

    def apertura_observada(*a, **kw):
        contadores['abrir'] += 1
        return apertura_real(*a, **kw)

    U.CredencialUser.cerrar = staticmethod(cierre_observado)
    U.CredencialUser.abrir = staticmethod(apertura_observada)

    def alta(nombre):
        priv, pub = home / f'{nombre}.priv', home / f'{nombre}.pub'
        respuesta = U.alta(nombre='Auditoria', apellido='DVC', alias='alias-comun',
                           ruta_priv=str(priv), ruta_pub=str(pub), dispositivo_id='dispositivo-autorizado')
        return respuesta, priv, pub

    a, ruta_priv_a, publica_a = alta('identidad_a')
    exigir(a.get('ok') is True and a.get('kit_ok') is True, 'D6_ALTA_REAL_COMPLETA')
    exigir(not ruta_priv_a.exists() and publica_a.exists(), 'D6_PRIVADA_NO_PERSISTE')
    exigir('ruta_priv' not in a and 'kit' not in a, 'D6_RESPUESTA_SIN_PRIVADA_NI_KIT')
    priv_a = decodificar(a['paquete_priv']); kit_a = decodificar(a['paquete_kit'])
    exigir(priv_a.startswith(b'\x89PNG\r\n\x1a\n') and kit_a.startswith(b'\x89PNG\r\n\x1a\n'),
           'D6_PNG_DOS_ARCHIVOS')
    exigir(contadores['cerrar'] == 4, 'D6_DOS_CIERRES_POR_CADA_PNG')
    for indice, png, etiqueta in ((0, priv_a, 'PRIV'), (2, kit_a, 'KIT')):
        original = cierres[indice]['plano']
        man = cierres[indice]['manifiesto']
        exigir(isinstance(man, dict) and original not in png, f'D6_{etiqueta}_CUERPO_OCULTO')
        serial = json.dumps(man, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        exigir(serial not in png, f'D6_{etiqueta}_MANIFIESTO_INTERIOR_OCULTO')
    U.salir(session_id=a['session_id'])

    b, ruta_priv_b, publica_b = alta('identidad_b')
    exigir(b.get('ok') and b['user_id'] != a['user_id'] and
           b['fingerprint'] != a['fingerprint'] and not ruta_priv_b.exists(),
           'D6_ALIAS_REPETIDO_IDENTIDADES_DISTINTAS')
    priv_b = decodificar(b['paquete_priv']); kit_b = decodificar(b['paquete_kit'])
    U.salir(session_id=b['session_id'])
    # Identificar los usuarios desde lo que USER realmente persistio.
    # No depende de una API auxiliar opcional como buscar_aliases().
    cuentas, usuarios_antes = _cuentas_desde_indice(U.UserRepository, a['alias'])
    identidades_esperadas = {a['user_id']: a['fingerprint'],
                            b['user_id']: b['fingerprint']}
    exigir(cuentas == identidades_esperadas and len(usuarios_antes) == len(identidades_esperadas),
           'D6_INDICE_MULTIALIAS_CON_HUELLAS')
    foto_indice = json.dumps(usuarios_antes, sort_keys=True, ensure_ascii=False)
    rechazos_observados = 0

    def entrar(p, k, aparato='dispositivo-autorizado'):
        return U.entrar_con_paquetes(alias='alias-comun', paquete_priv=p,
                                    paquete_kit=k, dispositivo_id=aparato)

    for nombre, p, k, uid in (('A', priv_a, kit_a, a['user_id']), ('B', priv_b, kit_b, b['user_id'])):
        r = entrar(p, k)
        exigir(r.get('ok') is True and r.get('user_id') == uid and r.get('session_id'),
               f'D6_ENTRA_IDENTIDAD_{nombre}_AUTORIDADES_REALES')
        U.salir(session_id=r['session_id'])
    exigir(contadores['abrir'] >= 8, 'D6_CREDENCIAL_ABRE_SOBRES_REALES')

    ataques = [
        ('PRIV_KIT_CRUZADO', priv_a, kit_b, 'dispositivo-autorizado'),
        ('PRIV_KIT_CRUZADO_INVERSO', priv_b, kit_a, 'dispositivo-autorizado'),
        ('DISPOSITIVO_AJENO', priv_a, kit_a, 'otro-dispositivo'),
        ('CIPHERTEXT_ALTERADO_CRC_VALIDO', mutar_ciphertext_con_crc_valido(priv_a), kit_a, 'dispositivo-autorizado'),
        ('KIT_ALTERADO_CRC_VALIDO', priv_a, mutar_ciphertext_con_crc_valido(kit_a), 'dispositivo-autorizado'),
        ('PNG_TRUNCADO', priv_a[:27], kit_a, 'dispositivo-autorizado'),
        ('PNG_CON_TRAILING', priv_a + b'NO_AUTORIZADO', kit_a, 'dispositivo-autorizado'),
    ]
    for nombre, p, k, aparato in ataques:
        r = entrar(p, k, aparato)
        denegado = r.get('ok') is False and not r.get('session_id')
        exigir(denegado, f'D6_FAIL_CLOSED_{nombre}')
        rechazos_observados += int(denegado)

    for nombre, cls, method in (
        ('CREDENCIAL_ABRIR', U.CredencialUser, 'abrir'),
        ('PROTECCION', U.ProteccionUser, 'probar_privada'),
        ('VINCULACION', U.VinculacionUser, 'probar'),
        ('ACCESO', U.AccesoUser, 'autorizar'),
    ):
        original = getattr(cls, method)
        setattr(cls, method, staticmethod(lambda *args, **kwargs: {'ok': False, 'estado': 'DENEGADO'}))
        try:
            r = entrar(priv_a, kit_a)
            denegado = r.get('ok') is False and not r.get('session_id')
            exigir(denegado, f'D6_RECHAZO_AUTORIDAD_{nombre}')
            rechazos_observados += int(denegado)
        finally:
            setattr(cls, method, staticmethod(original))

    # Cierre fallido en la 4a llamada: la cuenta no debe sobrevivir parcialmente.
    original = U.CredencialUser.cerrar
    def cerrar_y_negar(*args, **kwargs):
        cerrar_y_negar.cuenta += 1
        if cerrar_y_negar.cuenta == 4:
            return {'ok': False, 'concepto': 'DENEGADO_POR_AUTORIDAD'}
        return cierre_real(*args, **kwargs)
    cerrar_y_negar.cuenta = 0
    U.CredencialUser.cerrar = staticmethod(cerrar_y_negar)
    try:
        fallo, priv_f, pub_f = alta('alta_rechazada')
        exigir(cerrar_y_negar.cuenta == 4 and fallo.get('ok') is False and
               not fallo.get('session_id') and not priv_f.exists() and not pub_f.exists(),
               'D6_CUARTO_CIERRE_DENEGADO_REVIERTE_ENTREGA')
        cuentas_despues, usuarios_despues = _cuentas_desde_indice(U.UserRepository, a['alias'])
        exigir(cuentas_despues == identidades_esperadas and
               json.dumps(usuarios_despues, sort_keys=True, ensure_ascii=False) == foto_indice,
               'D6_CIERRE_DENEGADO_NO_REGISTRA_USUARIO')
        rechazos_observados += int(fallo.get('ok') is False and not fallo.get('session_id'))
    finally:
        U.CredencialUser.cerrar = staticmethod(original)

    # El almacén IKM debe impedir cruce de dominios y segunda revelación.
    r = GK.generar_clave(dominio=GK.DOMINIO_AUTH, tipo=GK.TIPO_PERMANENTE, descripcion='DVC-en-aislamiento')
    exigir(r.get('ok') is True and r.get('ref_id', '').startswith('IKM-'), 'D6_REF_IKM_OPACA')
    ref = r['ref_id']
    try:
        secreto = GK.resolver_clave(ref_id=ref, dominio=GK.DOMINIO_AUTH)
        exigir(secreto.get('ok') is True and len(secreto.get('secreto', b'')) == 32,
               'D6_IKM_EXACTO_32_BYTES')
        errado = GK.resolver_clave(ref_id=ref, dominio=GK.DOMINIO_DEF)
        exigir(errado.get('ok') is False and 'secreto' not in errado, 'D6_DOMINIO_INCORRECTO_DENEGADO')
        listado = GK.listar_referencias()
        exigir(listado.get('ok') is True and 'secreto' not in json.dumps(listado, default=str),
               'D6_LISTADO_NO_REVELA_IKM')
        una = GK.revelar_una_vez(ref_id=ref)
        dos = GK.revelar_una_vez(ref_id=ref)
        exigir(una.get('ok') is True and dos.get('ok') is False, 'D6_REVELACION_UNICA')
    finally:
        GK.eliminar_clave(ref_id=ref)
    exigir(GK.resolver_clave(ref_id=ref, dominio=GK.DOMINIO_AUTH).get('ok') is False,
           'D6_ELIMINADA_NO_SE_RESUELVE')
    print('SONDA_FINAL', json.dumps({
        'contadores': contadores,
        'alta_ok': sum(r.get('ok') is True for r in (a, b)),
        'rechazos': rechazos_observados,
        'evidencias': len(EVIDENCIAS),
    }, sort_keys=True))


if __name__ == '__main__':
    main()
