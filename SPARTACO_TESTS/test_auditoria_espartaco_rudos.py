"""AUDITORÍA RUDOS UNIFICADA — un solo test para el workflow e2e.yml.

Funde en un único archivo de pruebas (recogido por pytest) los cinco frentes
adversariales de SPARTACO, sin debilitar ninguno:

  R1  E2E de integración real contra el dispatcher (subproceso aislado,
      HOME propio, sin mocks de éxito; espías sobre autoridades reales).
  R2  Barrido anti-sabotaje del repositorio completo (Unicode/Trojan Source,
      criptografía fuera de autoridad, reasignación de autoridades).
  R3  Autocalibración del auditor antisabotaje con falsificaciones sintéticas.
  R4  Arquitectura estricta SC -> USER -> Spartaco_UI -> UI3 (baseline con
      pin SHA-256, biyección catálogo/backend, delegación a autoridades).
  R5  La cara (UI3) no interpreta credenciales ni cifra en el navegador.

Soporte (no son tests, son instrumentos): espartaco_anti_sabotaje.py,
_auditoria_espartaco_integracion.py, auditoria_espartaco_motor.py,
contrato_original_espartaco.json.

Nunca sustituye a la suite original: la acompaña. Sin mocks de éxito.
"""
from __future__ import annotations

import base64
import importlib
import importlib.util
import inspect
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# ------------------------------------------------------------------
# Instrumentos: scanner antisabotaje y motor AST (importlib, sin PATH)
# ------------------------------------------------------------------


def _cargar(nombre: str, archivo: str):
    spec = importlib.util.spec_from_file_location(nombre, HERE / archivo)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"AUDITOR_INCOMPLETO: falta {archivo}")
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modulo
    spec.loader.exec_module(modulo)
    return modulo


scanner = _cargar("espartaco_anti_sabotaje", "espartaco_anti_sabotaje.py")
_MOTOR = _cargar("_espartaco_auditoria_motor", "auditoria_espartaco_motor.py")

BOUNDARY_PATHS = _MOTOR.BOUNDARY_PATHS
crypto_violations = _MOTOR.crypto_violations
divergencias_baseline = _MOTOR.divergencias_baseline
extra_in_catalog = _MOTOR.extra_in_catalog
find_js_functions = _MOTOR.find_js_functions
get_call_names = _MOTOR.get_call_names
load_baseline = _MOTOR.load_baseline
unregistered_public = _MOTOR.unregistered_public

_SUBPROCESO_E2E = HERE / "_auditoria_espartaco_integracion.py"


def _hallazgos(file, content):
    return scanner.scan_file(file, content)


def _js_function_body(source: str, name: str) -> str:
    match = re.search(rf"\b(?:async\s+)?function\s+{re.escape(name)}\s*\(", source)
    if not match:
        return ""
    tail = source[match.end():]
    next_match = re.search(r"\b(?:async\s+)?function\s+ui3\w+\s*\(", tail)
    return tail[: next_match.start()] if next_match else tail


def _runtime():
    sc = importlib.import_module("modules.interfaz.paquetes.spartaco_ui.Spartaco_UI")
    assert sc.CAPA is not None, "CAPA_NO_CONECTADA"
    assert sc.VISTA_USER is not None, "VISTA_USER_NO_CONECTADA"
    inv = sc.inventario_seguro()
    assert isinstance(inv, dict) and isinstance(inv.get("recursos"), dict) and inv["recursos"], "INVENTARIO_NO_RESUELTO"
    return sc, inv


# ==================================================================
# R1 — E2E REAL: subproceso aislado contra el dispatcher
# ==================================================================


def test_rudos_01_e2e_alta_cierre_apertura_y_ataques_reales(tmp_path):
    runner = _SUBPROCESO_E2E
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["SPARTACO_AUDIT_ISOLATED"] = str(home)
    env["PYTHONPATH"] = str(ROOT)
    p = subprocess.run(
        [sys.executable, str(runner)], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120,
    )
    assert p.returncode == 0 and "ESPARTACO_E2E=PASS" in p.stdout, (
        f"AUDITORIA_E2E_RECHAZADA\nSTDOUT:\n{p.stdout[-3500:]}\nSTDERR:\n{p.stderr[-2500:]}"
    )


# ==================================================================
# R2 — Barrido antisabotaje del repositorio completo
# ==================================================================


def test_rudos_02_repositorio_sin_bloqueos_unicode_ni_cripto_paralela():
    _, findings = scanner.scan_repo(ROOT)
    blocking = [f for f in findings if f.severidad == "BLOQUEO"]
    assert not blocking, "\n" + "\n".join(
        f"{f.codigo} {f.archivo}:{f.linea}:{f.columna}: {f.detalle}" for f in blocking[:80]
    )


# ==================================================================
# R3 — Autocalibración del auditor (falsificaciones sintéticas)
# ==================================================================


@pytest.mark.parametrize("point,code", [
    (0x202E, "UNICODE_BIDI"),
    (0x2066, "UNICODE_BIDI"),
    (0x200B, "UNICODE_INVISIBLE"),
    (0x00AD, "UNICODE_INVISIBLE"),
    (0xFEFF, "UNICODE_INVISIBLE"),
    (0x2028, "UNICODE_SEPARATOR"),
    (0x0000, "CONTROL_EN_CODIGO"),
    (0xFFFF, "UNICODE_NONCHARACTER"),
])
def test_rudos_03_control_unicode_detectado(point, code):
    sample = ("# codigo " + chr(point) + " oculto\n").encode("utf-8")
    assert code in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/user.py", sample)}


def test_rudos_04_utf8_ilegal_no_se_ignora():
    assert "ENCODING_INVALIDO" in {f.codigo for f in _hallazgos("core/engine.py", b"x = 1\n\xff")}


def test_rudos_05_identificador_confundible_se_detecta():
    name = "aut" + chr(0x043E) + "rizar"
    findings = _hallazgos("modules/spartaco_seguridad/user.py", f"{name} = 1\n".encode())
    assert "IDENTIFICADOR_MEZCLA_SCRIPTS" in {f.codigo for f in findings}


def test_rudos_06_bom_se_detecta():
    assert "UTF8_BOM" in {f.codigo for f in _hallazgos("core/engine.py", b"\xef\xbb\xbfvalue = 1\n")}


def test_rudos_07_espanol_legitimo_no_falla():
    assert not [
        f for f in _hallazgos("core/engine.py", "# Protección de documentos\nmensaje = \"Contraseña válida\"\n".encode())
        if f.severidad == "BLOQUEO"
    ]


def test_rudos_08_cripto_nueva_en_user_se_detecta():
    x = b"from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    assert "CRIPTOGRAFIA_FUERA_AUTORIDAD" in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/user.py", x)}


def test_rudos_09_cripto_legitima_en_credencial_no_es_perseguida():
    x = b"from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    assert "CRIPTOGRAFIA_FUERA_AUTORIDAD" not in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/credencial.py", x)}


def test_rudos_10_sombra_de_funcion_publica_detectada():
    x = b"def autorizar():\n    return False\ndef autorizar():\n    return True\n"
    assert "DEFINICION_DUPLICADA" in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/user.py", x)}


def test_rudos_11_modificacion_de_autoridad_detectada():
    x = b"def entrar():\n    CredencialUser.abrir = lambda *a: {\"ok\": True}\n"
    assert "AUTORIDAD_REASIGNADA" in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/user.py", x)}


def test_rudos_12_gate_falseado_sin_verificacion_detectado():
    x = b"def autorizar():\n    return {\"ok\": True}\n"
    assert "GATE_EXITO_INCONDICIONAL" in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/user.py", x)}


def test_rudos_13_ejecucion_dinamica_en_user_detectada():
    x = b"def entrar():\n    eval(\"1\")\n"
    assert "EJECUCION_DINAMICA_COORDINADOR" in {f.codigo for f in _hallazgos("modules/spartaco_seguridad/user.py", x)}


def test_rudos_14_no_ejecuta_codigo_inspeccionado(tmp_path):
    project = tmp_path / "repo"
    (project / "modules" / "spartaco_seguridad").mkdir(parents=True)
    (project / "core").mkdir()
    marker = tmp_path / "EXPLOIT_EXECUTED"
    (project / "core" / "engine.py").write_text(f'open({str(marker)!r}, "w").write("BAD")\n', encoding="utf-8")
    count, findings = scanner.scan_repo(project)
    assert count == 1
    assert not marker.exists()
    assert not any(x.codigo == "ENCODING_INVALIDO" for x in findings)


def test_rudos_15_ruta_homoglifa_detectada(tmp_path):
    project = tmp_path / "repo"
    (project / "modules" / "spartaco_seguridad").mkdir(parents=True)
    name = "use" + chr(0x0440) + ".py"
    (project / "modules" / "spartaco_seguridad" / name).write_text("a = 1\n", encoding="utf-8")
    _, findings = scanner.scan_repo(project)
    assert "RUTA_HOMOGLIFO" in {f.codigo for f in findings}


def test_rudos_16_falla_cerrado_si_no_hay_repositorio(tmp_path):
    with pytest.raises(RuntimeError):
        scanner.scan_repo(tmp_path)


def test_rudos_17_cli_rechaza_ataque_real_sintetico(tmp_path):
    (tmp_path / "modules" / "spartaco_seguridad").mkdir(parents=True)
    f = tmp_path / "modules" / "spartaco_seguridad" / "user.py"
    f.write_text("x = \"" + chr(0x202E) + "\"\n", encoding="utf-8")
    p = subprocess.run(
        [sys.executable, str(HERE / "espartaco_anti_sabotaje.py"), "--root", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert p.returncode == 1
    assert "UNICODE_BIDI" in p.stdout


# ==================================================================
# R4 — Arquitectura estricta de la cadena SC -> USER -> UI -> UI3
# ==================================================================


def test_rudos_18_se_conservan_todas_las_capacidades_del_backend_original():
    old = load_baseline()
    _, inv = _runtime()
    actual = {k: v.get("capacidades_recurso", []) for k, v in inv["recursos"].items()}
    issues = divergencias_baseline(old["required_backend_public"], actual)
    assert not issues, "\n".join(issues)


def test_rudos_19_catalogo_es_biyeccion_con_backend_real():
    sc, inv = _runtime()
    public = {f"{r}.{c}" for r, meta in inv["recursos"].items() for c in meta.get("capacidades_recurso", [])}
    catalog = set(sc.CAPA.ACCIONES_MAP)
    missing, extra = unregistered_public(public, catalog), extra_in_catalog(public, catalog)
    assert not missing and not extra, (
        f"BACKEND_SIN_CATALOGO_UI={missing}\nCATALOGO_SIN_BACKEND={extra}\n"
        "No ocultar ni eliminar capacidades para hacer pasar este test."
    )
    assert len(public) == len(catalog), "CONTEO_INCONSISTENTE"


def test_rudos_20_capacidad_catalogada_resuelve_callable_firma_y_wire():
    sc, _ = _runtime()
    issues = []
    for identifier, action in sorted(sc.CAPA.ACCIONES_MAP.items()):
        rid, dot, name = identifier.partition(".")
        fn, reason = sc._resolver_capacidad(rid, name)
        if not callable(fn):
            issues.append(f"{identifier}: NO_CALLABLE_O_NO_PUBLICO: {reason}")
            continue
        try:
            signature = inspect.signature(fn)
        except (TypeError, ValueError) as e:
            issues.append(f"{identifier}: FIRMA_NO_INSPECCIONABLE: {e}")
            continue
        fields = action.campos
        params = {p for p, v in signature.parameters.items() if v.kind not in (v.VAR_KEYWORD, v.VAR_POSITIONAL)}
        if set(fields) - params:
            issues.append(f"{identifier}: CAMPOS_INVENTADOS: {sorted(set(fields) - params)}")
        for p, field in fields.items():
            if field.wire not in sc.CAPA.TRANSPORTES:
                issues.append(f"{identifier}.{p}: WIRE_DESCONOCIDO: {field.wire}")
            if field.kind not in sc.CAPA.SEMANTICAS:
                issues.append(f"{identifier}.{p}: SEMANTICA_DESCONOCIDA: {field.kind}")
    assert not issues, "\n".join(issues)


def test_rudos_21_nueva_puerta_publicada_en_toda_la_cadena():
    sc, inv = _runtime()
    action = "USER.entrar_con_paquetes"
    assert "entrar_con_paquetes" in inv["recursos"]["USER"]["capacidades_recurso"], "NO_DECLARADA_EN_SPARTACO_SEGURIDAD"
    user = importlib.import_module("modules.spartaco_seguridad.user")
    assert action in sc.CAPA.ACCIONES_MAP, "NO_CATALOGADA_CAPA_UNIVERSAL"
    assert "entrar_con_paquetes" in user.CAPACIDADES_USER, "FALTA_CAPACIDADES_USER"
    assert "entrar_con_paquetes" in user.__all__, "FALTA_EXPORTACION_USER"
    signature = inspect.signature(user.entrar_con_paquetes)
    required = {"alias", "paquete_priv", "paquete_kit", "dispositivo_id"}
    assert set(signature.parameters) == required, f"FIRMA_INCOMPATIBLE: {signature}"
    for name in ("paquete_priv", "paquete_kit"):
        f = sc.CAPA.ACCIONES_MAP[action].campos
        assert name in f and f[name].wire == sc.CAPA.T_BYTES, f"TRANSPORTE_INCORRECTO: {name}"
    assert sc._accion_visible_usuario(action), "OPERACION_OCULTA_EN_VISTA_USER"
    real, error = sc._resolver_capacidad("USER", "entrar_con_paquetes")
    assert real is user.entrar_con_paquetes and not error, "DISPATCHER_NO_RESUELVE_LA_OPERACION_REAL"


def test_rudos_22_user_no_contiene_criptografia_paralela_ni_ui_tampoco():
    issues = []
    for rel in BOUNDARY_PATHS:
        path = ROOT / rel
        assert path.is_file(), f"FALTA_ARCHIVO_CONTRATO: {rel}"
        issues.extend(crypto_violations(path.read_text(encoding="utf-8"), rel))
    assert not issues, "\n".join(issues)


def test_rudos_23_no_desaparecieron_operaciones_originales_de_user():
    user = importlib.import_module("modules.spartaco_seguridad.user")
    baseline = load_baseline()["required_backend_public"]["USER"]
    issues = [name for name in baseline if not callable(getattr(user, name, None))]
    assert not issues, f"OPERACIONES_USER_PERDIDAS: {issues}"
    for name in (
        "abrir_documento", "cerrar_documento", "recuperar_documento",
        "comprobar_archivo", "firmar_archivo", "crear_keyset", "rotar_keyset",
    ):
        assert callable(getattr(user, name, None)), f"REGRESION_DE_CAPACIDAD: USER.{name}"


def test_rudos_24_adaptador_user_delega_al_motor_original():
    path = ROOT / "modules/spartaco_seguridad/user.py"
    names = get_call_names(path.read_text(encoding="utf-8"))
    assert "CredencialUser.cerrar" in names or "CREDENCIAL.proteger" in names, "NO_DELEGA_CIERRE_A_CREDENCIAL"
    assert "CredencialUser.abrir" in names or "CREDENCIAL.abrir_documento" in names, "NO_DELEGA_APERTURA_A_CREDENCIAL"


def test_rudos_25_despachador_niega_accion_no_publicada_sin_invocarla(monkeypatch):
    sc, _ = _runtime()
    touched = []
    monkeypatch.setattr(sc, "_ejecutar_directo_usuario", lambda *args, **kwargs: touched.append(1))
    r = sc.ejecutar_accion_usuario({"accion_id": "USER.__accion_que_no_existe__", "inputs": {}})
    assert isinstance(r, dict) and r.get("ok") is False
    assert r.get("error") in ("ACCION_NO_PUBLICADA_EN_VISTA", "SIN_CLASIFICAR")
    assert not touched, "FAIL_OPEN: accion inexistente alcanzó ejecutor"


def test_rudos_26_despachador_no_permite_saltar_vista(monkeypatch):
    sc, _ = _runtime()
    touched = []
    monkeypatch.setattr(sc, "_accion_visible_usuario", lambda _: False)
    monkeypatch.setattr(sc, "_resolver_capacidad", lambda *args: touched.append(1))
    r = sc.ejecutar_accion_usuario({"accion_id": "USER.alta", "inputs": {}})
    assert r.get("ok") is False and r.get("error") == "ACCION_NO_PUBLICADA_EN_VISTA"
    assert not touched, "FAIL_OPEN: resolución antes de autorización de vista"


def test_rudos_27_conservar_portada_logo_renders_y_rutas_originales():
    old = load_baseline()
    for name in old["original_portada_files"]:
        p = ROOT / name
        assert p.is_file() and p.stat().st_size > 100, f"PORTADA_ELIMINADA: {name}"
    front = (ROOT / "modules/interfaz/paquetes/spartaco_ui/interfaz_3.py").read_text(encoding="utf-8")
    server = (ROOT / "modules/interfaz/paquetes/spartaco_ui/Spartaco_UI.py").read_text(encoding="utf-8")
    assert "/portada/render.js" in front and "/portada/estilo.css" in front, "PORTADA_DESCONECTADA"
    for route in old["legacy_routes"]:
        assert route in front or route in server, f"RUTA_ORIGINAL_ELIMINADA: {route}"
    view = importlib.import_module("modules.interfaz.paquetes.spartaco_ui.vista_user")
    svg = view.logo()
    assert isinstance(svg, dict) and svg.get("ok") and "<svg" in str(svg), "LOGO_ORIGINAL_NO_DISPONIBLE"


def test_rudos_28_no_se_borraron_las_pestanas_y_funciones_criticas():
    p = ROOT / "modules/interfaz/paquetes/spartaco_ui/interfaz_3.py"
    text = p.read_text(encoding="utf-8")
    observed = find_js_functions(text)
    expected = load_baseline()["legacy_ui_essential"]
    assert not (set(expected) - observed), f"REGRESION_UI3: {sorted(set(expected) - observed)}"
    for action in ("ui3Alta", "ui3Entrar", "ui3Abrir", "ui3Comprobar", "ui3CrearPar"):
        assert action in observed, f"CONTROL_SIN_CAPACIDAD: {action}"


def test_rudos_29_solo_el_backend_toma_decisiones_criptograficas():
    p = ROOT / "modules/interfaz/paquetes/spartaco_ui/interfaz_3.py"
    source = p.read_text(encoding="utf-8")
    forbidden = (
        r"crypto\.subtle\s*\.\s*(?:encrypt|decrypt|deriveKey|importKey|sign|verify)\s*\(",
        r"new\s+(?:AESGCM|Fernet)\s*\(",
        r"CryptoJS\.(?:AES|DES|TripleDES|PBKDF2)\b",
    )
    leaks = [pat for pat in forbidden if re.search(pat, source)]
    assert not leaks, f"CRIPT0GRAFIA_EN_LA_CARA: {leaks}"


def test_rudos_30_doble_comprobacion_de_autoridad_y_publicacion():
    sc, inv = _runtime()
    for action in (
        "USER.cerrar_documento", "USER.abrir_documento",
        "USER.recuperar_documento", "CREDENCIAL.proteger",
        "CREDENCIAL.abrir_documento", "PROTECCION.generar_claves",
        "VINCULACION.verificar_vinculacion",
        "ACCESO.verificar_acceso",
    ):
        rid, _, cap = action.partition(".")
        assert cap in inv["recursos"][rid]["capacidades_recurso"], f"AUTORIDAD_DESPUBLICADA: {action}"
        fn, err = sc._resolver_capacidad(rid, cap)
        assert callable(fn), f"AUTORIDAD_NO_RESUELTA: {action}: {err}"
    internal = importlib.import_module("modules.spartaco_seguridad.generador_claves")
    assert "resolver_clave" in internal.SEGURIDAD.get("capacidades_internas", [])
    assert callable(internal.resolver_clave)


def test_rudos_31_auditor_detecta_import_crypto_y_alias_y_construccion():
    malicious = [
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM as M\nM(key)",
        "import Crypto.Cipher.AES as aes\naes.new(key)",
        "import importlib\nimportlib.import_module(\"cryptography.hazmat.primitives\")",
        "def cerrar(x):\n    return AESGCM(key).encrypt(nonce,x,tag)",
    ]
    for mutant in malicious:
        assert crypto_violations(mutant, "mutante.py"), f"AUDITOR_CIEGO_A_CRIPTOGRAFIA: {mutant!r}"
    assert not crypto_violations(
        "from modules.spartaco_seguridad import credencial as CREDENCIAL\nCREDENCIAL.proteger(x)", "limpio.py"
    )


def test_rudos_32_auditor_detecta_mutaciones_de_inventario_y_catalogo():
    old = {"CREDENCIAL": ["proteger", "abrir_documento"]}
    assert divergencias_baseline(old, {"CREDENCIAL": ["proteger"]}) == [
        "CAPACIDAD_ORIGINAL_ELIMINADA: CREDENCIAL.abrir_documento"
    ]
    assert unregistered_public({"USER.alta", "OMEGA_PERIMETER.classify_uis"}, {"USER.alta"}) == [
        "OMEGA_PERIMETER.classify_uis"
    ]
    assert extra_in_catalog({"USER.alta"}, {"USER.alta", "USER.capacidad_inventada"}) == [
        "USER.capacidad_inventada"
    ]


# ==================================================================
# R5 — La cara no interpreta credenciales ni cifra en el navegador
# ==================================================================


def test_rudos_33_entrada_ui3_transmite_documentos_sin_descifrado_local():
    text = (ROOT / "modules/interfaz/paquetes/spartaco_ui/interfaz_3.py").read_text("utf-8")
    body = _js_function_body(text, "ui3Entrar")
    assert body, "FORMULARIO_ENTRAR_ELIMINADO"
    assert "USER.entrar_con_paquetes" in body, "UI3_NO_LLEGA_A_NUEVA_PUERTA"
    for forbidden in ("ui3PrivDe(", "ui3LeerKit(", "ui3AbrirTarjeta("):
        assert forbidden not in body, f"UI3_INTERPRETA_CREDENCIALES_LOCALMENTE: {forbidden}"


def test_rudos_34_crear_y_guardar_reconocen_dos_paquetes_y_publica():
    text = (ROOT / "modules/interfaz/paquetes/spartaco_ui/interfaz_3.py").read_text("utf-8")
    alta = _js_function_body(text, "ui3Alta")
    descarga = _js_function_body(text, "ui3GuardarPieza")
    assert alta and descarga, "CONTROLES_ALTA_DESCARGA_ELIMINADOS"
    assert "paquete_priv" in text and "paquete_kit" in text, "UI3_ESPERA_PRIVADA_O_KIT_CRUDOS"
    assert "pub" in descarga or "pub" in text, "CLAVE_PUBLICA_NO_DESCARGABLE"


def test_rudos_35_ui_no_hace_cifrado_ni_uso_directo_de_autoridades():
    issues = []
    for path in (ROOT / "modules/interfaz").rglob("*"):
        if path.is_file() and path.suffix in (".py", ".js"):
            raw = path.read_text("utf-8", errors="replace")
            rel = str(path.relative_to(ROOT))
            if path.suffix == ".py":
                issues.extend(crypto_violations(raw, rel))
            else:
                for marker in (
                    r"crypto\.subtle\.(?:encrypt|decrypt|deriveKey|sign)\s*\(",
                    r"CryptoJS\.(?:AES|DES|PBKDF2)\b",
                ):
                    if re.search(marker, raw):
                        issues.append(f"{rel}: CIFRADO_PARALELO_FRONTEND: {marker}")
    assert not issues, "\n".join(issues)
