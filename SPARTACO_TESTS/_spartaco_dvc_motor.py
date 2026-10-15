"""Motor puro DVC: nunca declara PROBADO por una mera promesa textual."""
from __future__ import annotations

import ast
import importlib
import inspect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROBADO = 'PROBADO'
CONTRADICCION = 'CONTRADICCIÓN'
NO_DEMOSTRABLE = 'NO DEMOSTRABLE'
NIVELES = {PROBADO, CONTRADICCION, NO_DEMOSTRABLE}

# No se persisten IKM, claves, cuerpo de paquetes ni plaintext en reportes.
@dataclass(frozen=True)
class Evidencia:
    eje: str
    asunto: str
    estado: str
    detalle: str
    prueba: str = ''

    def __post_init__(self):
        if self.estado not in NIVELES:
            raise ValueError('estado de evidencia desconocido')
        if self.estado == PROBADO and not self.prueba:
            raise ValueError('PROBADO exige referencia a una medición o test reproducible')

    def serializar(self):
        return {k: getattr(self, k) for k in ('eje', 'asunto', 'estado', 'detalle', 'prueba')}


def ev(eje, asunto, condicion, detalle, prueba):
    return Evidencia(eje, asunto, PROBADO if condicion else CONTRADICCION,
                    detalle, prueba if condicion else '')


def no_medible(eje, asunto, detalle):
    return Evidencia(eje, asunto, NO_DEMOSTRABLE, detalle)


def fallos(filas, *, estricto=True):
    if not filas:
        return ['SIN_EVIDENCIAS: cero pruebas no equivale a PASS']
    salida = []
    for e in filas:
        if e.estado == CONTRADICCION or (estricto and e.estado == NO_DEMOSTRABLE):
            salida.append(f'[{e.eje}][{e.asunto}] {e.estado}: {e.detalle}')
    return salida


def fuente(ruta: Path):
    return ast.parse(ruta.read_text(encoding='utf-8-sig'), filename=str(ruta))


def imports_ilegitimos(arbol: ast.AST, paquete='user'):
    """Marca criptografía nueva en capa USER/UI; hashlib para huellas permitido."""
    prohibidos = ('cryptography', 'Crypto', 'Cryptodome', 'nacl', 'pycryptodome',
                  'pyaes', 'fernet', 'argon2', 'passlib')
    golpes = []
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.Import):
            for n in nodo.names:
                if n.name.split('.')[0] in prohibidos:
                    golpes.append(f'L{nodo.lineno}: import {n.name}')
        elif isinstance(nodo, ast.ImportFrom):
            if (nodo.module or '').split('.')[0] in prohibidos:
                golpes.append(f'L{nodo.lineno}: from {nodo.module}')
        elif isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name) and nodo.func.id in ('__import__', 'eval', 'exec'):
            if any(isinstance(arg, ast.Constant) and isinstance(arg.value, str) and
                   any(p in arg.value for p in prohibidos) for arg in nodo.args):
                golpes.append(f'L{nodo.lineno}: carga dinámica de motor criptográfico')
    return golpes



def imports_ajenos_stdlib(arbol: ast.AST):
    """Declaración verificable: capa semántica usa solamente stdlib."""
    import sys
    hits = []
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.Import):
            nombres = [a.name for a in nodo.names]
        elif isinstance(nodo, ast.ImportFrom):
            if nodo.level:
                hits.append(f'L{nodo.lineno}: import relativo')
                continue
            nombres = [nodo.module or '']
        else:
            continue
        for nombre in nombres:
            raiz = nombre.split('.')[0]
            if raiz not in sys.stdlib_module_names and raiz != '__future__':
                hits.append(f'L{nodo.lineno}: {nombre}')
    return hits


def llamadas(arbol, nombre):
    """Objetivos de llamada dentro de la función declarada, no en todo el archivo."""
    fns = [n for n in ast.walk(arbol) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == nombre]
    if len(fns) != 1:
        return None
    out = set()
    for node in ast.walk(fns[0]):
        if isinstance(node, ast.Call):
            try:
                out.add(ast.unparse(node.func))
            except Exception:
                pass
    return out


def detectar_pasarela(arbol):
    """Delegación verificable en AST, jamás confundida con prueba de cifrado."""
    hallazgos = []
    reglas = {
        'cerrar': ('CREDENCIAL.proteger',),
        'abrir': ('CREDENCIAL.abrir_documento',),
    }
    clases = [n for n in arbol.body if isinstance(n, ast.ClassDef) and n.name == 'CredencialUser']
    if len(clases) != 1:
        return ['CredencialUser no definido una sola vez']
    for accion, obligatorias in reglas.items():
        funciones = [n for n in clases[0].body if isinstance(n, ast.FunctionDef) and n.name == accion]
        if len(funciones) != 1:
            hallazgos.append(f'CredencialUser.{accion} ausente/duplicado')
            continue
        objetivos = {ast.unparse(n.func) for n in ast.walk(funciones[0]) if isinstance(n, ast.Call)}
        if not all(p in objetivos for p in obligatorias):
            hallazgos.append(f'CredencialUser.{accion}: no delega a {obligatorias}')
        # Una llamada decorativa seguida de OK literal NO es delegación.
        retornos = [n.value for n in ast.walk(funciones[0]) if isinstance(n, ast.Return)]
        if not any(isinstance(v, ast.Call) and ast.unparse(v.func) in obligatorias for v in retornos):
            hallazgos.append(f'CredencialUser.{accion}: falta retorno DIRECTO de autoridad')
    c = llamadas(arbol, '_cerrar_puerta')
    if c is None or 'CredencialUser.cerrar' not in c:
        hallazgos.append('_cerrar_puerta no invoca CredencialUser.cerrar')
    e = llamadas(arbol, 'entrar_con_paquetes')
    # abrir_uno es un closure; comprobar que existe dentro de esa función.
    if e is None or 'CredencialUser.abrir' not in e:
        hallazgos.append('entrar_con_paquetes no invoca CredencialUser.abrir')
    return hallazgos


def duplicados_publicos(arbol):
    encontrados = {}
    duplicados = []
    for nodo in arbol.body:
        if isinstance(nodo, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if nodo.name in encontrados:
                duplicados.append(f'{nodo.name}: líneas {encontrados[nodo.name]} y {nodo.lineno}')
            encontrados[nodo.name] = nodo.lineno
    return duplicados


def declaraciones_resueltas(mod, declarado, *, eje='D1', titulo='recurso'):
    pub = declarado.get('capacidades_recurso')
    if not isinstance(pub, (list, tuple)) or not pub:
        return [no_medible(eje, titulo, 'no hay lista de capacidades_recurso')]
    internas = declarado.get('capacidades_internas', [])
    if not isinstance(internas, (list, tuple)):
        internas = []
    todas = list(pub) + list(internas)
    problemas, alias = [], []
    if len(todas) != len(set(todas)):
        problemas.append('duplicados públicos/internos')
    objetos = {}
    for cap in todas:
        f = getattr(mod, cap, None) if isinstance(cap, str) else None
        if not callable(f):
            problemas.append(f'{cap}: no callable')
        elif id(f) in objetos:
            alias.append(f'{cap} comparte objeto con {objetos[id(f)]}')
        else:
            objetos[id(f)] = cap
    detalle = f'{len(pub)} públicas, {len(internas)} internas; problemas={problemas[:16]}; alias={alias[:16]}'
    if problemas:
        return [Evidencia(eje, titulo, CONTRADICCION, detalle)]
    if alias:
        return [no_medible(eje, titulo, detalle + '; los alias requieren contrato de equivalencia')]
    return [Evidencia(eje, titulo, PROBADO, detalle,
                      f'importlib({mod.__name__}): introspección callable/identidad')]


def mapas_usuario(mod, paquete, raiz):
    filas = []
    mapa = getattr(mod, 'MAPA_SPARTACO', None)
    if not isinstance(mapa, dict):
        return [no_medible('D3', 'MAPA_SPARTACO', 'USER no publica mapa')]
    alias_mod = {'MANIFIESTO_DOCUMENTOS': 'manifiesto', 'ML_PROTECCION': 'ml_proteccion',
                 'GENERADOR_CLAVES': 'generador_claves', 'OMEGA_PERIMETER': 'perimeter'}
    for autoridad, fila in sorted(mapa.items()):
        capacidades = fila.get('capacidades_base', [])
        if not capacidades:
            continue   # un recurso de infraestructura sin mapeo no es promesa de ruta USER
        nombre = alias_mod.get(autoridad, autoridad.lower())
        try:
            m = importlib.import_module(f'{paquete}.{nombre}')
        except Exception as exc:
            filas.append(no_medible('D3', autoridad, f'módulo no importable: {type(exc).__name__}'))
            continue
        problemas = [n for n in capacidades if not callable(getattr(m, n, None))]
        filas.append(ev('D3', autoridad, not problemas,
                        f'{len(capacidades)} capacidades base, ausentes: {problemas}',
                        f'importlib({m.__name__}) + callable por capacidad'))
    return filas


def fuente_literal_pass(texto: str):
    """Detecta estado positivo escrito, no calculado, dentro de la publicación CI."""
    patron = re.compile(r'(?:dato\s*\([^\n]*?[\'\"](?:PASS|OK|COMPLETE)[\'\"]|'
                        r'(?:(?:estado|status|veredicto)\s*[:=]\s*[\'\"](?:PASS|OK|COMPLETE)[\'\"]))',
                        re.IGNORECASE)
    return [(texto.count('\n', 0, m.start()) + 1, m.group(0)[:130]) for m in patron.finditer(texto)]


def comparar_catalogo(inventario, acciones, campos=None):
    filas = []
    recursos = inventario.get('recursos') if isinstance(inventario, dict) else None
    if not isinstance(recursos, dict) or not recursos:
        return [no_medible('D4', 'inventario', 'sin recursos del runtime')]
    existentes = {f'{rid}.{cap}' for rid, fila in recursos.items() if isinstance(fila, dict)
                  for cap in fila.get('capacidades_recurso', [])}
    if not isinstance(acciones, dict):
        return [no_medible('D4', 'catálogo', 'ACCIONES_MAP ausente')]
    publicadas = set(acciones)
    faltantes = sorted(existentes - publicadas)
    fantasmas = sorted(publicadas - existentes)
    filas.append(ev('D4', 'cobertura exacta', not faltantes and not fantasmas,
                    f'reales={len(existentes)}, catálogo={len(publicadas)}, faltantes={faltantes[:20]}, fantasmas={fantasmas[:20]}',
                    'inventario() vivo comparado con ACCIONES_MAP vivo'))
    return filas


def reporte(filas):
    conteo = {n: sum(e.estado == n for e in filas) for n in (PROBADO, CONTRADICCION, NO_DEMOSTRABLE)}
    return {'esquema': 1, 'total': len(filas), 'resumen': conteo,
            'aprobado_estricto': bool(filas) and not fallos(filas),
            'evidencias': [f.serializar() for f in filas]}


def reportar_y_exigir(filas, etiqueta):
    salida = reporte(filas)
    print('\nDECLARACIÓN VS CONDUCTA /', etiqueta)
    for e in filas:
        print(f'  [{e.estado}] {e.eje} {e.asunto}: {e.detalle}')
    print('RESUMEN', salida['resumen'])
    errores = fallos(filas)
    assert not errores, '\n'.join(errores)
