"""Auditor estático defensivo ESPARTACO: Unicode/Trojan Source y límites de autoridad.

No importa ni ejecuta módulos del proyecto. Solo lee archivos de texto. Stdlib.
Uso: python tests/espartaco_anti_sabotaje.py [--root .] [--json ruta]
Salida: 0 sin hallazgos bloqueantes, 1 si los hay, 2 error de auditoría.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys
import tokenize
import unicodedata as ud

CODE_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.json', '.yml', '.yaml', '.toml', '.sh', '.bash', '.c', '.h', '.bat', '.ps1'}
SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', '.pytest_cache', '__pycache__', '.mypy_cache', '.ruff_cache', 'dist', 'build'}
# El carácter de párrafo, bidi y los controles invisibles alteran las revisiones visuales.
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
INVISIBLE = {0x00AD, 0x034F, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF}
SEPARATORS = {0x2028, 0x2029}
SECURITY_NAME = re.compile(r'(?:auth|autoriz|permit|access|acceso|verific|session|sesion|login|entrar|perimet|protecc|firma|credencial|token|desbloqueo)', re.I)
# Capas no propietarias del cifrado, según el contrato declarado por el usuario.
ORCHESTRATOR_NAMES = {'user.py', 'Spartaco_UI.py', 'interfaz_3.py', 'interfaz_2.py', 'interfaz_4.py', 'capa_universal.py', 'vista_user.py'}
CRYPTO_IMPORT_ROOTS = {'cryptography', 'Crypto', 'Cryptodome', 'nacl', 'PyNaCl', 'fernet'}
CRYPTO_PRIMITIVES = {'AESGCM', 'ChaCha20Poly1305', 'Fernet', 'PBKDF2HMAC', 'Scrypt', 'Cipher', 'SecretBox'}
JAVASCRIPT_ESCAPE = re.compile(r'\\u(?:\{[0-9a-fA-F]{1,6}\}|[0-9a-fA-F]{4})')
ESCAPED_CODEPOINT = re.compile(r'\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|u\{([0-9a-fA-F]{1,6})\})')


@dataclass(frozen=True)
class Hallazgo:
    severidad: str
    codigo: str
    archivo: str
    linea: int
    columna: int
    detalle: str


def _issue(out, sev, code, path, line, col, detail):
    out.append(Hallazgo(sev, code, str(path).replace('\\', '/'), int(line), int(col), detail))


def _noncharacter(cp):
    return 0xFDD0 <= cp <= 0xFDEF or cp & 0xFFFE == 0xFFFE and cp <= 0x10FFFF


def _script(ch):
    if ch.isascii():
        return 'ASCII'
    if not ch.isalpha():
        return None
    name = ud.name(ch, '')
    for script in ('LATIN', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'HEBREW', 'ARABIC', 'CJK', 'HIRAGANA', 'KATAKANA', 'HANGUL'):
        if script in name:
            return script
    return 'OTHER'


def scan_unicode(relative, raw):
    findings = []
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        _issue(findings, 'BLOQUEO', 'ENCODING_INVALIDO', relative, 1, exc.start + 1, f'UTF-8 inválido: posición byte {exc.start}')
        return findings, None
    if raw.startswith(b'\xef\xbb\xbf'):
        _issue(findings, 'BLOQUEO', 'UTF8_BOM', relative, 1, 1, 'BOM UTF-8 en código fuente: revisar si está autorizado')
    for i, line in enumerate(text.splitlines(keepends=True), 1):
        for col, ch in enumerate(line, 1):
            cp = ord(ch)
            if cp in BIDI:
                _issue(findings, 'BLOQUEO', 'UNICODE_BIDI', relative, i, col, f'Control bidireccional U+{cp:04X} ({ud.name(ch, "?")})')
            elif cp in INVISIBLE:
                # U+00AD suele aparecer en comentarios/docstrings antiguos; reportar
                # sin declararlo sabotaje automático. El modo estricto puede bloquearlo.
                sev = 'REVISION' if cp == 0x00AD else 'BLOQUEO'
                _issue(findings, sev, 'UNICODE_INVISIBLE', relative, i, col, f'Formato invisible U+{cp:04X} ({ud.name(ch, "?")})')
            elif cp in SEPARATORS:
                _issue(findings, 'BLOQUEO', 'UNICODE_SEPARATOR', relative, i, col, f'Separador de línea ocultable U+{cp:04X}')
            elif cp == 0 or (cp < 32 and ch not in '\n\r\t') or cp == 127:
                _issue(findings, 'BLOQUEO', 'CONTROL_EN_CODIGO', relative, i, col, f'Carácter de control U+{cp:04X}')
            elif _noncharacter(cp):
                _issue(findings, 'BLOQUEO', 'UNICODE_NONCHARACTER', relative, i, col, f'No-carácter Unicode U+{cp:04X}')
    # El escape fuente (p.ej. U+202E) no es en sí un ataque Trojan Source,
    # pero puede convertirse en control invisible durante la ejecución.
    for m in ESCAPED_CODEPOINT.finditer(text):
        cp = int(next(part for part in m.groups() if part is not None), 16)
        if cp in BIDI or cp in INVISIBLE or cp in SEPARATORS:
            line = text.count('\n', 0, m.start()) + 1
            col = m.start() - text.rfind('\n', 0, m.start())
            _issue(findings, 'REVISION', 'UNICODE_ESCAPE_CONTROL', relative, line, col, f'Escape de control potencial en tiempo de ejecución U+{cp:04X}')
    return findings, text


def _check_python_identifiers(relative, text, findings):
    # tokenize detecta el nombre fuente antes de que AST normalice NFKC.
    from io import StringIO
    try:
        for tok in tokenize.generate_tokens(StringIO(text).readline):
            if tok.type != tokenize.NAME or tok.string.isascii():
                continue
            token = tok.string
            scripts = {_script(ch) for ch in token if ch.isalpha()} - {None, 'ASCII'}
            # Cualquier mezcla de escritura latina y no latina puede suplantar nombres.
            latin = any((ch.isascii() and ch.isalpha()) or _script(ch) == 'LATIN' for ch in token)
            if latin and scripts - {'LATIN'}:
                _issue(findings, 'BLOQUEO', 'IDENTIFICADOR_MEZCLA_SCRIPTS', relative, tok.start[0], tok.start[1] + 1, f'Identificador de escrituras mezcladas: {ascii(token)}')
            if ud.normalize('NFKC', token) != token:
                _issue(findings, 'BLOQUEO', 'IDENTIFICADOR_NFKC', relative, tok.start[0], tok.start[1] + 1, f'Identificador se normaliza de {ascii(token)} a {ascii(ud.normalize("NFKC", token))}')
            if not latin and scripts:
                _issue(findings, 'REVISION', 'IDENTIFICADOR_NO_LATINO', relative, tok.start[0], tok.start[1] + 1, f'Identificador no latino: {ascii(token)}')
    except (tokenize.TokenError, IndentationError) as exc:
        _issue(findings, 'BLOQUEO', 'TOKENIZACION_FALLIDA', relative, 1, 1, str(exc))


def _attr_path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _attr_path(node.value)
        return left + '.' + node.attr if left else node.attr
    return ''


def _is_orchestrator(relative):
    p = Path(relative)
    return p.name in ORCHESTRATOR_NAMES and ('spartaco_ui' in p.parts or p.name == 'user.py' and 'spartaco_seguridad' in p.parts)


def scan_python_ast(relative, text, findings):
    try:
        tree = ast.parse(text, filename=str(relative))
    except SyntaxError as exc:
        _issue(findings, 'BLOQUEO', 'PY_SYNTAX', relative, exc.lineno or 1, exc.offset or 1, f'Error de sintaxis: {exc.msg}')
        return
    protected = _is_orchestrator(relative)
    for node in ast.walk(tree):
        if protected and isinstance(node, (ast.Import, ast.ImportFrom)):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ''])
            if any(n.split('.')[0] in CRYPTO_IMPORT_ROOTS for n in names):
                _issue(findings, 'BLOQUEO', 'CRIPTOGRAFIA_FUERA_AUTORIDAD', relative, node.lineno, node.col_offset + 1, f'Import criptográfico en capa coordinadora: {names}')
        if protected and isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                path = _attr_path(target)
                if path.split('.')[0] in {'CredencialUser', 'AccesoUser', 'VinculacionUser', 'ProteccionUser', 'ClavesUser', 'CREDENCIAL', 'PROTECCION', 'ACCESO', 'VINCULACION'} and '.' in path:
                    _issue(findings, 'BLOQUEO', 'AUTORIDAD_REASIGNADA', relative, node.lineno, node.col_offset + 1, f'Posible reemplazo de autoridad: {path}')
        if protected and isinstance(node, ast.Call):
            callee = _attr_path(node.func)
            if callee == 'setattr' and len(node.args) >= 2 and _attr_path(node.args[0]) in {'CredencialUser', 'AccesoUser', 'VinculacionUser', 'ProteccionUser', 'ClavesUser', 'CREDENCIAL', 'PROTECCION', 'ACCESO', 'VINCULACION'}:
                _issue(findings, 'BLOQUEO', 'AUTORIDAD_REASIGNADA', relative, node.lineno, node.col_offset + 1, 'setattr intenta modificar un adaptador o autoridad')
            if callee.split('.')[-1] in CRYPTO_PRIMITIVES:
                _issue(findings, 'BLOQUEO', 'CRIPTOGRAFIA_PRIMITIVA_DIRECTA', relative, node.lineno, node.col_offset + 1, f'Construcción de cifrador en capa coordinadora: {callee}')
            if callee in ('eval', 'exec', '__import__'):
                _issue(findings, 'BLOQUEO', 'EJECUCION_DINAMICA_COORDINADOR', relative, node.lineno, node.col_offset + 1, f'Ejecución dinámica en capa coordinadora: {callee}')
        if protected and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and SECURITY_NAME.search(node.name):
            # Retorno incondicional como única instrucción en una función de seguridad.
            body = [x for x in node.body if not isinstance(x, ast.Expr) or not isinstance(x.value, ast.Constant) or not isinstance(x.value.value, str)]
            if len(body) == 1 and isinstance(body[0], ast.Return):
                value = body[0].value
                always_true = isinstance(value, ast.Constant) and value.value is True
                success_dict = isinstance(value, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == 'ok' and isinstance(v, ast.Constant) and v.value is True for k, v in zip(value.keys, value.values))
                if always_true or success_dict:
                    _issue(findings, 'BLOQUEO', 'GATE_EXITO_INCONDICIONAL', relative, body[0].lineno, body[0].col_offset + 1, f'{node.name} devuelve éxito sin consultar autoridad')
            # Hallazgo orientativo: NO es prueba suficiente de sabotaje.
            for statement in node.body:
                if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Constant) and statement.value.value is True:
                    _issue(findings, 'REVISION', 'RETORNO_TRUE_GATE', relative, statement.lineno, statement.col_offset + 1, f'Retorno True directo en {node.name}: revisar con pruebas de falsificación')
    # Detecta shadowing por definiciones duplicadas a nivel de módulo.
    seen = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if stmt.name in seen:
                _issue(findings, 'BLOQUEO', 'DEFINICION_DUPLICADA', relative, stmt.lineno, stmt.col_offset + 1, f'{stmt.name} redefinido a nivel de módulo; anterior línea {seen[stmt.name]}')
            seen[stmt.name] = stmt.lineno
    _check_python_identifiers(relative, text, findings)


def scan_js_source(relative, text, findings):
    # Hallazgo de revisión porque las secuencias también pueden aparecer legalmente en cadenas.
    for m in JAVASCRIPT_ESCAPE.finditer(text):
        before = text[max(0, m.start()-40):m.start()]
        # Alta certeza para nombres de capacidades/propiedades disfrazados con escape:
        # foo\\u0062ar o .\\u0065ntrar, pero podría estar dentro de texto.
        if before and (before[-1].isalnum() or before[-1] in '._$'):
            line = text.count('\n', 0, m.start()) + 1
            col = m.start() - text.rfind('\n', 0, m.start())
            _issue(findings, 'REVISION', 'JS_UNICODE_ESCAPE', relative, line, col, 'Escape Unicode en posible identificador JavaScript; verificar AST/semántica')


def scan_file(relative, raw):
    findings, text = scan_unicode(relative, raw)
    if text is None:
        return findings
    if str(relative).endswith('.py'):
        scan_python_ast(relative, text, findings)
    if Path(relative).suffix in {'.js', '.jsx', '.ts', '.tsx'}:
        scan_js_source(relative, text, findings)
    return findings


def scan_repo(root):
    root = Path(root).resolve()
    findings = []
    count = 0
    if not (root / 'modules' / 'spartaco_seguridad').is_dir():
        raise RuntimeError('No se encontró modules/spartaco_seguridad; el auditor debe ejecutarse desde la raíz de ESPARTACO')
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in CODE_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if any(p in SKIP_DIRS for p in relative.parts):
            continue
        # Los nombres de archivo también pueden engañar al revisor (homógrafos).
        for component in relative.parts:
            for ch in component:
                cp = ord(ch)
                if cp in BIDI or cp in INVISIBLE or cp in SEPARATORS:
                    _issue(findings, 'BLOQUEO', 'RUTA_UNICODE_OCULTO', relative, 1, 1, f'Carácter invisible o direccional U+{cp:04X} en la ruta')
            scripts = {_script(ch) for ch in component if ch.isalpha()} - {None, 'ASCII'}
            latin = any((ch.isascii() and ch.isalpha()) or _script(ch) == 'LATIN' for ch in component)
            if latin and scripts - {'LATIN'}:
                _issue(findings, 'BLOQUEO', 'RUTA_HOMOGLIFO', relative, 1, 1, f'Nombre de ruta con escrituras mezcladas: {ascii(component)}')
            if ud.normalize('NFKC', component) != component:
                _issue(findings, 'BLOQUEO', 'RUTA_NFKC', relative, 1, 1, f'Nombre de ruta cambia tras normalización NFKC: {ascii(component)}')
        if path.is_symlink():
            _issue(findings, 'BLOQUEO', 'FUENTE_SYMLINK', relative, 1, 1, 'Fuente enlazada simbólicamente: revisar procedencia y destino')
            continue
        # No omitir tests ni workflows: pueden introducir evasiones en CI.
        count += 1
        try:
            data = path.read_bytes()
        except OSError as exc:
            _issue(findings, 'BLOQUEO', 'NO_LEIBLE', relative, 1, 1, f'Error de lectura: {exc}')
            continue
        findings.extend(scan_file(relative, data))
    if count == 0:
        raise RuntimeError('No se encontraron fuentes; auditoría inválida')
    return count, sorted(findings, key=lambda x: (x.archivo, x.linea, x.columna, x.codigo))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Auditoría antisuplantación Unicode y autoridad de ESPARTACO')
    parser.add_argument('--root', default='.', help='Raíz del repositorio')
    parser.add_argument('--json', default='', help='Guardar hallazgos en JSON')
    parser.add_argument('--warnings-as-errors', action='store_true', help='También bloquear hallazgos de revisión')
    args = parser.parse_args(argv)
    try:
        count, findings = scan_repo(args.root)
    except Exception as exc:
        print(f'AUDITOR_INVALIDO: {exc}', file=sys.stderr)
        return 2
    blocking = sum(item.severidad == 'BLOQUEO' for item in findings)
    for item in findings:
        print(f'{item.severidad} {item.codigo} {item.archivo}:{item.linea}:{item.columna} — {item.detalle}')
    print(f'ESPARTACO_ANTI_SABOTAJE archivos={count} bloqueos={blocking} revision={len(findings)-blocking}')
    if args.json:
        destination = Path(args.json)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps({'archivos': count, 'bloqueos': blocking, 'hallazgos': [asdict(x) for x in findings]}, indent=2, ensure_ascii=False), encoding='utf-8')
    return 1 if blocking or args.warnings_as_errors and findings else 0


if __name__ == '__main__':
    sys.exit(main())
