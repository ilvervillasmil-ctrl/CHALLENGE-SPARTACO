"""Regresión de portada original de SPARTACO: entrega, navegación y cuatro renders.

NO toca autoridades, claves, ni lógica de la portada. Comprueba la cadena
Spartaco_UI.py -> VISTA_USER.portada -> portada/render.js -> HTML de presentación.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import threading
from pathlib import Path
from urllib.request import urlopen

import pytest

from modules.interfaz.paquetes.spartaco_ui import Spartaco_UI as UI
from modules.interfaz.paquetes.spartaco_ui import vista_user as VISTA

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'modules/interfaz/paquetes/interfaz_ui/portada'


def test_portada_fuentes_originales_y_cuatro_renders():
    contenido, css, js = ((ASSETS / n).read_text(encoding='utf-8')
                          for n in ('contenido.py', 'estilo.css', 'render.js'))
    assert 'PORTADA' in contenido and '"es"' in contenido and '"en"' in contenido
    assert 'spartacoRenderPortada' in js and 'fort3d' in js
    for escena in ('hero', 'flujo-scene', 'genea-scene', 'defensa-scene'):
        assert escena in js, f'Render original desapareció: {escena}'
        assert escena in css, f'Estilos originales desaparecieron: {escena}'
    assert 'function entrarRecinto' in UI.HTML  # Navegación original intacta
    assert '/portada/render.js' in UI.HTML and '/portada/estilo.css' in UI.HTML


@pytest.mark.parametrize('idioma,rotulo', [('es', 'Entrar al recinto'), ('en', 'Enter the enclosure')])
def test_render_real_de_cuatro_secciones_y_portada_completa(idioma, rotulo):
    """Evalúa el JS auténtico con datos auténticos, no una portada inventada."""
    assert shutil.which('node'), 'Node.js requerido para validar el render auténtico'
    portada = VISTA.portada(idioma=idioma)
    assert portada.get('ok') and len(portada.get('bloques', [])) >= 10
    js = (ASSETS / 'render.js').read_text(encoding='utf-8')
    payload = json.dumps(portada, ensure_ascii=False)
    script = (js + '\nconsole.log(spartacoRenderPortada(' + payload + ','
              + json.dumps(idioma) + ', (t)=>String(t), ()=>{}));')
    result = subprocess.run(['node', '-'], input=script, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert result.returncode == 0, result.stderr
    html = result.stdout
    for elemento in ('class="hero"', 'class="fort3d"', 'class="flujo-scene"',
                     'class="genea-scene"', 'class="defensa-scene"',
                     'class="portada-block', rotulo):
        assert elemento in html, f'Falta elemento renderizado: {elemento}'
    assert html.count('class="portada-block') >= 10


def test_http_conserva_portada_navegacion_logo_y_assets():
    """Se solicita al servidor real; no se sustituyen respuestas por mocks."""
    server = UI.Servidor(('127.0.0.1', 0), UI.Handler)
    hilo = threading.Thread(target=server.serve_forever, daemon=True)
    hilo.start()
    try:
        base = f'http://127.0.0.1:{server.server_port}'
        def get(path):
            with urlopen(base + path, timeout=10) as res:
                return res.status, res.read()
        status, html = get('/')
        assert status == 200 and b'/portada/render.js' in html
        assert b'Entrar al recinto' in html
        for asset in ('render.js', 'estilo.css'):
            code, data = get('/portada/' + asset)
            assert code == 200 and data == (ASSETS / asset).read_bytes()
        code, body = get('/api/vista/portada?idioma=es')
        p = json.loads(body)
        assert code == 200 and p.get('ok') and len(p.get('bloques', [])) >= 10
        code, body = get('/api/vista/menu?idioma=es')
        m = json.loads(body)
        sec = [s['id'] for s in m['secciones']]
        assert code == 200 and sec[0] == 'PORTADA' and 'INICIO' in sec
        code, body = get('/api/vista/logo')
        logo = json.loads(body)
        assert code == 200 and logo.get('ok') and '<svg' in logo.get('svg', '')
    finally:
        server.shutdown()
        server.server_close()
        hilo.join(timeout=5)
