"""D1–D7 SPARTACO: declaración contra conducta; el PASS necesita testigo.

Añadir SOLO a tests/. Ni usuario ni CI se modifica. Subprocesos aislados.
"""
from __future__ import annotations

import importlib
import json
import importlib.util
import inspect
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location('_dvc_motor_spartaco', TESTS / '_spartaco_dvc_motor.py')
assert spec and spec.loader, 'MOTOR_AUDITOR_AUSENTE'
M = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = M
spec.loader.exec_module(M)

PKG = 'modules.spartaco_seguridad'
UI_PKG = 'modules.interfaz.paquetes.spartaco_ui'


def _mod(name):
    return importlib.import_module(name)


def _inventario():
    sc = _mod(PKG)
    r = sc.inventario()
    assert r.get('coherente') is True and len(r.get('recursos', {})) >= 12, f'Inventario no coherente: {r}'
    return r


def test_D1_inventario_y_declaraciones_contra_runtime():
    """Cada capacidad pública/interna declarada es callable y única en su recurso."""
    inv = _inventario()
    filas = []
    for rid, meta in sorted(inv['recursos'].items()):
        ruta = meta.get('ruta') or ''
        nombre = Path(ruta).stem if ruta else meta.get('nombre')
        if not nombre:
            filas.append(M.no_medible('D1', rid, 'no hay módulo declarado en inventario'))
            continue
        try:
            mod = _mod(f'{PKG}.{nombre}')
        except Exception as exc:
            filas.append(M.no_medible('D1', rid, f'no importable: {type(exc).__name__}'))
            continue
        seg = getattr(mod, 'SEGURIDAD', None)
        if not isinstance(seg, dict):
            filas.append(M.no_medible('D1', rid, 'SEGURIDAD no es un contrato dict'))
            continue
        filas.extend(M.declaraciones_resueltas(mod, seg, titulo=rid))
        filas.append(M.ev('D1', f'{rid}.id', seg.get('id') == rid,
                          f'declarado={seg.get("id")!r} vs inventario={rid!r}',
                          'SEGURIDAD.id contra SC.inventario()'))
        declaradas = set(seg.get('capacidades_recurso') or ())
        inventariadas = set(meta.get('capacidades_recurso') or ())
        filas.append(M.ev('D1', f'{rid}.inventario', declaradas == inventariadas,
                          f'diferencias: {sorted(declaradas ^ inventariadas)[:20]}',
                          'SEGURIDAD.capacidades_recurso contra inventario de SC'))
        ruta_src = ROOT / 'modules/spartaco_seguridad' / str(ruta)
        if not ruta or not ruta_src.is_file():
            filas.append(M.no_medible('D1', f'{rid}.fuente', 'ruta de fuente no verificable'))
        else:
            arbol = M.fuente(ruta_src)
            filas.append(M.ev('D1', f'{rid}.duplicación', not M.duplicados_publicos(arbol),
                              str(M.duplicados_publicos(arbol)[:10]),
                              f'AST real de {ruta}'))
    M.reportar_y_exigir(filas, 'D1')


def test_D2_invalidos_se_rechazan_sin_crear_sesion():
    """No confundir excepción accidental ni 'ok=True' con rechazo contractual."""
    U = _mod(f'{PKG}.user')
    muestras = (
        ('contenedor truncado', lambda: U._leer_contenedor(b'\x89PNG\r\n\x1a\n', 'PRIV')),
        ('contenedor ajeno', lambda: U._leer_contenedor(b'estafa', 'KIT')),
        ('sesion inexistente', lambda: U.sesion(session_id='SES-INEXISTENTE-DVC')),
        ('clave de login ausente', lambda: U.entrar(alias='falso', ruta_priv='', dispositivo_id='test')),
        ('paquetes vacios', lambda: U.entrar_con_paquetes(alias='test', paquete_priv=b'', paquete_kit=b'', dispositivo_id='test')),
    )
    filas = []
    for nombre, operacion in muestras:
        try:
            r = operacion()
        except Exception as exc:
            filas.append(M.ev('D2', nombre, False, f'excepción fuera de contrato: {type(exc).__name__}', ''))
            continue
        conforme = isinstance(r, dict) and r.get('ok') is False and not r.get('session_id')
        filas.append(M.ev('D2', nombre, conforme, f'rechaza={conforme}; no hay sesión',
                          f'llamada runtime USER: {nombre}'))
    M.reportar_y_exigir(filas, 'D2')


def test_D3_mapas_de_dependencias_resuelven_autoridades_reales():
    """La ruta de dependencia declarada debe existir y ser callable."""
    U = _mod(f'{PKG}.user')
    filas = M.mapas_usuario(U, PKG, ROOT)
    M.reportar_y_exigir(filas, 'D3')


def test_D4_catalogo_y_firmas_coinciden_con_inventario():
    """El inventario NO legitima acciones fantasmas ni campos inventados."""
    inv = _inventario()
    C = _mod(f'{UI_PKG}.capa_universal')
    filas = M.comparar_catalogo(inv, getattr(C, 'ACCIONES_MAP', None))
    campos = getattr(C, 'CAMPOS', {})
    if not isinstance(campos, dict):
        filas.append(M.no_medible('D4', 'CAMPOS', 'sin declaración de transportes'))
    else:
        resultados = []
        for accion, definiciones in campos.items():
            rec, dot, cap = accion.partition('.')
            if not dot or rec not in inv['recursos']:
                resultados.append((accion, 'recurso inexistente'))
                continue
            fila = inv['recursos'][rec]
            nom = Path(str(fila.get('ruta') or '')).stem
            try:
                funcion = getattr(_mod(f'{PKG}.{nom}'), cap)
                params = set(inspect.signature(funcion).parameters)
            except (AttributeError, TypeError, ValueError):
                resultados.append((accion, 'firma no resoluble'))
                continue
            for campo in definiciones:
                if campo not in params:
                    resultados.append((accion, campo))
        filas.append(M.ev('D4', 'CAMPOS vs firma', not resultados,
                          f'campos ajenos a firmas: {resultados[:20]} (total={len(resultados)})',
                          'inspect.signature de cada función real vs capa_universal.CAMPOS'))
    M.reportar_y_exigir(filas, 'D4')


def test_D5_user_no_implementa_crypto_y_delega_en_credencial():
    """La frontera de autoridad se prueba por AST, no por el comentario 'no cifra'."""
    rutas = {
        'USER': ROOT / 'modules/spartaco_seguridad/user.py',
        'CAPA_UNIVERSAL': ROOT / 'modules/interfaz/paquetes/spartaco_ui/capa_universal.py',
        'SPARTACO_UI': ROOT / 'modules/interfaz/paquetes/spartaco_ui/Spartaco_UI.py',
        'INTERFAZ_3': ROOT / 'modules/interfaz/paquetes/spartaco_ui/interfaz_3.py',
    }
    filas = []
    for nombre, ruta in rutas.items():
        if not ruta.is_file():
            filas.append(M.no_medible('D5', nombre, f'archivo ausente {ruta}'))
            continue
        arbol = M.fuente(ruta)
        ilegales = M.imports_ilegitimos(arbol)
        filas.append(M.ev('D5', f'{nombre}.cripto', not ilegales, f'motores extra {ilegales}',
                          f'AST de {ruta.relative_to(ROOT)}'))
        if nombre == 'CAPA_UNIVERSAL':
            externos = M.imports_ajenos_stdlib(arbol)
            filas.append(M.ev('D5', 'CAPA_UNIVERSAL.solo_stdlib', not externos,
                              f'importaciones fuera de stdlib: {externos}',
                              'AST imports contra sys.stdlib_module_names'))
        if nombre in ('SPARTACO_UI', 'INTERFAZ_3'):
            fuente_capa = ruta.read_text(encoding='utf-8')
            patrones = [r'\bcrypto\.subtle\.(?:decrypt|deriveKey|importKey)',
                        r'\bnew\s+AESGCM\s*\(', r'\bfernet\.decrypt\s*\(']
            crypto_ui = [p for p in patrones if re.search(p, fuente_capa, flags=re.IGNORECASE)]
            filas.append(M.ev('D5', f'{nombre}.sin_descifrado_ui', not crypto_ui,
                              f'patrones de descifrado en cara/dispatcher: {crypto_ui}',
                              'búsqueda literal de llamadas crypto UI (alcance limitado)'))
        if nombre == 'USER':
            fallas = M.detectar_pasarela(arbol)
            filas.append(M.ev('D5', 'delegación CREDENCIAL', not fallas,
                              f'rutas sin delegar: {fallas}',
                              'AST de CredencialUser.cerrar/abrir, _cerrar_puerta y entrar_con_paquetes'))
    M.reportar_y_exigir(filas, 'D5')


def test_D6_autoridades_reales_2_cuentas_falsificaciones_y_rollback():
    """Sonda de extremo a extremo: proceso/hogar/almacén IKM aislados."""
    sonda = TESTS / '_spartaco_dvc_probe.py'
    assert sonda.is_file(), 'NO DEMOSTRABLE: sonda ausente'
    with tempfile.TemporaryDirectory(prefix='espartaco_dvc_', dir=None) as tmp:
        home = Path(tmp).resolve()
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home),
                   ESPARTACO_DVC_HOME=str(home), PYTHONDONTWRITEBYTECODE='1')
        env['PYTHONPATH'] = str(ROOT) + os.pathsep + env.get('PYTHONPATH', '')
        p = subprocess.run([sys.executable, '-I', str(sonda)], cwd=ROOT, env=env,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150)
        # -I ignora PYTHONPATH: usar inserción explícita en la sonda, no contaminar el host.
        assert p.returncode == 0, f'D6 SONDA FALLÓ (exit={p.returncode}):\n{p.stdout[-5000:]}\n{p.stderr[-3000:]}'
        pruebas = re.findall(r'^EVIDENCIA (D6_[A-Z0-9_]+)$', p.stdout, flags=re.MULTILINE)
        assert pruebas, 'D6 SIN_EVIDENCIAS_OBSERVABLES'
        assert len(pruebas) == len(set(pruebas)), 'D6 EVIDENCIAS_DUPLICADAS'
        cierres = re.findall(r'^SONDA_FINAL (.+)$', p.stdout, flags=re.MULTILINE)
        assert len(cierres) == 1, f'D6 SONDA_FINAL_INCONSISTENTE: {len(cierres)}'
        resultado = json.loads(cierres[0])
        assert resultado['evidencias'] == len(pruebas), 'D6 CONTABILIDAD_EVIDENCIAS_DIVERGE'
        assert resultado['alta_ok'] == 2, 'D6 NO_HUBO_DOS_ALTAS_VERIFICADAS'
        assert resultado['rechazos'] > 0, 'D6 SIN_FALSIFICACIONES_RECHAZADAS'
        assert resultado['contadores']['cerrar'] > 0 and resultado['contadores']['abrir'] > 0, \
            'D6 CREDENCIAL_NO_EJECUTADA'
        print('\n' + p.stdout)


def test_D7_publicacion_ci_no_fabrica_resultados():
    """Distingue un PASS medido de un PASS incrustado en el workflow."""
    carpeta = ROOT / '.github/workflows'
    filas = []
    if not carpeta.is_dir():
        filas.append(M.no_medible('D7', 'workflow', 'no existe .github/workflows'))
    else:
        archs = sorted(carpeta.glob('*.yml')) + sorted(carpeta.glob('*.yaml'))
        if not archs:
            filas.append(M.no_medible('D7', 'workflow', 'sin workflow'))
        for f in archs:
            golpes = M.fuente_literal_pass(f.read_text(encoding='utf-8'))
            filas.append(M.ev('D7', f.name, not golpes,
                              f'PASS/OK literales como datos: {golpes[:15]}',
                              f'inspección textual workflow {f.relative_to(ROOT)}'))
    # No basta que el workflow no publique un literal: debe invocar pytest
    # y producir evidencia JUnit para sus contadores.
    principal = carpeta / 'ci.yml'
    if principal.is_file():
        texto = principal.read_text(encoding='utf-8')
        sin_comentarios = '\n'.join(l for l in texto.splitlines() if not l.lstrip().startswith('#'))
        medicion = bool(re.search(r'(?m)^\s*(?:python\s+-m\s+)?pytest\s+tests(?:/|\b)', sin_comentarios))
        junit = '--junit-xml' in sin_comentarios
        ignorar_fallos = bool(re.search(r'(?m)^\s*continue-on-error\s*:\s*true\s*$', sin_comentarios))
        filas.append(M.ev('D7', 'pytest/JUnit observables en workflow',
                          medicion and junit and not ignorar_fallos,
                          f'pytest={medicion}; JUnit={junit}; ignore-failure={ignorar_fallos}',
                          'inspección del step CI (configuración; NO resultado de Actions)'))
    else:
        filas.append(M.no_medible('D7', 'ci.yml', 'no se encuentra workflow principal'))
    M.reportar_y_exigir(filas, 'D7')
