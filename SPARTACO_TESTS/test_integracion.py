# ============================================================================
# VPSI-TRUTH — test_integracion.py
# ============================================================================
# Integration smoke test over the modules that actually exist in the
# spartaco_seguridad package.
#
# POSTURE
# -------
# Unlike the adversarial suite, this file is cooperative: it exercises
# the honest end-to-end path and confirms that the real modules fit
# together. It still keeps two disciplines of the suite:
#   1. It never couples to an imaginary surface: if a module is not in
#      the tree, it is not imported; if a function is not exported, it
#      is not called.
#   2. It demands the correct failure node: the single mutation must
#      fail specifically at "nucleo", not merely at "something".
#
# SCOPE
# -----
#   0) Discovery via SC.barrer() / SC.catalogo()
#        - package is self-documented (recursos > 0, catalogo.n > 0)
#        - resources PROTECCION, ML and LAUNCHER are present
#
#   1) proteccion.py — baseline cycle
#        - generar_claves produces 32 B priv and 32 B pub
#        - bootstrap.elf present and non-empty
#        - build() seals and signs (n_neutro=3, version=1)
#        - verificar() on the sealed artifact: ok=True, no fallos
#        - verificar() on a one-bit mutation: ok=False AND
#          "nucleo" appears in fallos (correct node, not any node)
#
#   2) ml_proteccion.py — real inventory weights
#        - manifestar_modelo on a dummy model: ok=True and exactly
#          n_pesos == 2 (config.json is not counted as a weight)
#        - verificar_modelo on the intact model: ok=True, no fallos
#        - verificar_modelo on a tampered shard: ok=False AND
#          "nucleo" in fallos; original shard restored afterwards
#
#   3) launcher.py — verificar_y_ejecutar (SUBPROCESS mode)
#        - sealed bootstrap: ok=True, ejecutado=True, exit_code=46,
#          and "46" present in captured stdout (not just exit code)
#        - tampered bootstrap (ELF header + zeros): ejecutado=False
#          and ok=False; original restored from backup
#
# EXPLICIT NON-SCOPE
# ------------------
#   - deteccion_intoxicacion is not imported: it does not exist in the
#     tree.
#   - capacidades(), conceptos() and modulos() are not called: the
#     package __init__ does not export them.
#   - The launcher is exercised for ONE mutation only; exhaustive
#     adversarial coverage of its surface belongs to the adversarial
#     harness, not here.
#
# DESIGN NOTES
# ------------
#   - The discovery step ties the test to the real package contract
#     via SC.barrer()/SC.catalogo(), not to a hardcoded module list.
#   - ok=True is never accepted alone: the fallos list must also be
#     empty in the success cases.
#   - The single mutation is required to fail at the correct node
#     ("nucleo"), which lets this file catch refactors that migrate
#     the failure to a different barrier even when the public surface
#     still returns ok=False.
#   - Fixtures are restored after mutation so that no later test is
#     poisoned by leftover state.
#   - Exit code is 0 only when every check passed; otherwise 1.
#
# ROLE IN THE SUITE
# -----------------
#   test_credencial_aniquilador.py .......... monolithic attack
#   test_credencial_redteam.py ................ 35 attacks
#   test_credencial_redteam_continuacion.py ... 14 attacks
#   test_D1_D7_... ............................ package as declaration
#   test_d6_lector_calibracion.py ............. D6 reader calibration
#   test_espartaco_cadena_grafo.py ............ topological map
#   test_espartaco_multi_atacante_montecarlo.py  forensic Monte Carlo
#   test_integracion.py ....................... honest end-to-end smoke
#                                              over the modules that
#                                              actually exist.
#
# PRINCIPLE
# ---------
#   An integration test that imports what is not there and calls what
#   is not exported is worse than no test at all: it produces false
#   confidence. This file walks only the real surface, demands the
#   correct failure node for its one mutation, and restores every
#   fixture it touches.
# ============================================================================
import json
import shutil
import sys
from pathlib import Path

BASE = Path(__file__).parent.resolve()
ROOT = BASE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BASE))

from modules.spartaco_seguridad import (
    proteccion as P,
    ml_proteccion as ML,
    launcher as L,
)
from modules.spartaco_seguridad import barrer, catalogo

KEYS = BASE / "keys"
KEYS.mkdir(exist_ok=True)
PRIV = KEYS / "priv.bin"
PUB = KEYS / "pub.bin"
BOOTSTRAP = ROOT / "bootstrap.elf"
if not BOOTSTRAP.exists():
    BOOTSTRAP = BASE / "bootstrap.elf"
SELLADO = KEYS / "bootstrap.sellado.elf"
MANIF = KEYS / "bootstrap.manifest.json"
MODELO = KEYS / "modelo_demo"

resultados = []


def paso(n, nombre, ok, detalle=""):
    ok = bool(ok)
    marca = "PASS" if ok else "FAIL"
    print(f"  [{n}] {nombre:42s} {marca}  {detalle}")
    resultados.append((nombre, ok))


def banner(t):
    print("\n" + "=" * 72)
    print("  " + t)
    print("=" * 72)


banner("0) Descubrimiento automático desde SC")
barrido = barrer()
cat = catalogo()
recursos = barrido.get("recursos") or []
conceptos_hallados = barrido.get("conceptos") or []
print("  recursos            :", recursos)
print("  archivos            :", barrido.get("archivos"))
print("  conceptos           :", len(conceptos_hallados))
print("  coherente           :", barrido.get("coherente"))
paso(
    "0.1",
    "paquete autodocumentado",
    isinstance(recursos, list) and len(recursos) > 0 and int(cat.get("n") or 0) > 0,
    f"recursos={len(recursos)} conceptos={len(conceptos_hallados)} n={cat.get('n')}",
)
nombres = [str(x).upper() for x in recursos]
paso(
    "0.2",
    "recursos reales presentes",
    any("PROTECCION" in n for n in nombres)
    and any("ML" in n for n in nombres)
    and any("LAUNCHER" in n for n in nombres),
    f"recursos={recursos}",
)

banner("1) proteccion: build + verificar baseline")
r = P.generar_claves(str(PRIV), str(PUB))
paso(
    "1.1",
    "generar_claves Ed25519",
    r.get("ok") is True and PRIV.exists() and PUB.exists()
    and PRIV.stat().st_size == 32 and PUB.stat().st_size == 32,
    f"pub={PUB.stat().st_size if PUB.exists() else 0}B priv={PRIV.stat().st_size if PRIV.exists() else 0}B",
)
paso(
    "1.2a",
    "bootstrap.elf disponible",
    BOOTSTRAP.exists() and BOOTSTRAP.is_file() and BOOTSTRAP.stat().st_size > 0,
    f"bytes={BOOTSTRAP.stat().st_size if BOOTSTRAP.exists() else 0}",
)
b = {"ok": False, "datos": b"", "manifiesto": {}}
if BOOTSTRAP.exists() and BOOTSTRAP.is_file():
    b = P.build(
        BOOTSTRAP.read_bytes(),
        str(PRIV),
        n_neutro=3,
        artifact_id="bootstrap-v0.4",
        version=1,
        clave_publica_id="red-spartaco",
    )
build_ok = (
    b.get("ok") is True
    and isinstance(b.get("datos"), (bytes, bytearray))
    and len(b["datos"]) > 0
    and isinstance(b.get("manifiesto"), dict)
)
nucleo = "N/A"
cuerpo = (b.get("manifiesto") or {}).get("cuerpo") if build_ok else None
if isinstance(cuerpo, dict) and "nucleo" in cuerpo:
    nucleo = str(cuerpo["nucleo"])[:12] + "..."
paso(
    "1.2",
    "build() sella y firma bootstrap.elf",
    build_ok,
    f"artefacto_sellado={len(b['datos']) if build_ok else 0}B nucleo={nucleo}",
)
if build_ok:
    SELLADO.write_bytes(b["datos"])
    MANIF.write_text(json.dumps(b["manifiesto"], indent=2), encoding="utf-8")
    SELLADO.chmod(0o755)

pub_bytes = PUB.read_bytes() if PUB.exists() else b""
v_ok = {"ok": False, "fallos": ["sin_build"]}
if build_ok:
    v_ok = P.verificar(
        b["datos"],
        manifiesto=b["manifiesto"],
        pub_bytes=pub_bytes,
        modo=P.MODO_PROTEGIDO,
    )
paso(
    "1.3",
    "verificar() manifiesto OK esperado",
    v_ok.get("ok") is True and not v_ok.get("fallos"),
    f"fallos={v_ok.get('fallos')}",
)
v_mal = {"ok": True, "fallos": []}
if build_ok and len(b["datos"]) > 100:
    mal = bytearray(b["datos"])
    mal[100] ^= 0x01
    v_mal = P.verificar(
        bytes(mal),
        manifiesto=b["manifiesto"],
        pub_bytes=pub_bytes,
        modo=P.MODO_PROTEGIDO,
    )
paso(
    "1.4",
    "verificar() detecta manipulación",
    v_mal.get("ok") is False and "nucleo" in v_mal.get("fallos", []),
    f"fallos={v_mal.get('fallos')}",
)

banner("2) ml_proteccion: pesos reales del inventario")
if MODELO.exists():
    shutil.rmtree(MODELO)
MODELO.mkdir(parents=True, exist_ok=True)
(MODELO / "config.json").write_text(
    json.dumps({"model_type": "bert", "hidden_size": 768}), encoding="utf-8"
)
(MODELO / "model.safetensors").write_bytes(b"shard1_pretrained_weights" * 30)
(MODELO / "weights.onnx").write_bytes(b"onnx_dummy_payload" * 20)
m = ML.manifestar_modelo(
    MODELO,
    str(PRIV),
    artifact_id="fraud-detector-v3",
    version=1,
    clave_publica_id="ml-team",
    recursivo=True,
)
n_pesos = (m.get("inventario") or {}).get("n")
paso(
    "2.1",
    "manifestar_modelo (2 archivos de pesos)",
    m.get("ok") is True
    and isinstance(m.get("manifiesto"), dict)
    and n_pesos == 2
    and (m.get("inventario") or {}).get("n_bytes_total", 0) > 0,
    f"n_archivos={n_pesos} bytes={(m.get('inventario') or {}).get('n_bytes_total')}",
)
v_model = ML.verificar_modelo(MODELO, m.get("manifiesto") or {}, str(PUB), recursivo=True)
paso(
    "2.2",
    "verificar_modelo: modelo intacto OK",
    v_model.get("ok") is True and not v_model.get("fallos"),
    f"fallos={v_model.get('fallos')}",
)
(MODELO / "model.safetensors").write_bytes(b"shard1_MANIPULATED!!" * 30)
v_touch = ML.verificar_modelo(MODELO, m.get("manifiesto") or {}, str(PUB), recursivo=True)
paso(
    "2.3",
    "verificar_modelo detecta shard alterado",
    v_touch.get("ok") is False and "nucleo" in (v_touch.get("fallos") or []),
    f"fallos={v_touch.get('fallos')}",
)
(MODELO / "model.safetensors").write_bytes(b"shard1_pretrained_weights" * 30)

banner("3) launcher: verificar_y_ejecutar en modo SUBPROCESS")
out = {"ok": False, "ejecutado": False, "exit_code": None, "stdout": ""}
if SELLADO.exists() and MANIF.exists() and PUB.exists():
    out = L.verificar_y_ejecutar(
        ruta_artefacto=str(SELLADO),
        ruta_manifiesto=str(MANIF),
        ruta_pub=str(PUB),
        modo=L.MODO_SUBPROCESS,
    )
stdout = out.get("stdout") or ""
exit_code = out.get("exit_code")
paso(
    "3.1",
    "verificar_y_ejecutar OK + ejecuta bootstrap",
    out.get("ok") is True and out.get("ejecutado") is True and exit_code == 46,
    f"ejecutado={out.get('ejecutado')} exit_code_real={exit_code} (esperado 46)",
)
paso("3.2", "STDOUT contiene 46", "46" in stdout, f"stdout={stdout[:60]!r}...")

out_block = {"ok": True, "ejecutado": True, "conceptos": []}
if SELLADO.exists() and MANIF.exists() and PUB.exists():
    backup = SELLADO.with_suffix(".bak")
    shutil.copy2(SELLADO, backup)
    try:
        SELLADO.write_bytes(b"\x7fELF" + b"\x00" * 100)
        out_block = L.verificar_y_ejecutar(
            ruta_artefacto=str(SELLADO),
            ruta_manifiesto=str(MANIF),
            ruta_pub=str(PUB),
            modo=L.MODO_SUBPROCESS,
        )
    finally:
        SELLADO.write_bytes(backup.read_bytes())
        backup.unlink(missing_ok=True)
paso(
    "3.3",
    "artefacto manipulado bloqueado por launcher",
    out_block.get("ejecutado") is False and out_block.get("ok") is False,
    f"conceptos={out_block.get('conceptos')}",
)

banner("RESUMEN")
total = len(resultados)
ok = sum(1 for _, resultado in resultados if resultado)
print(f"  {ok}/{total} tests PASARON")
for nombre, resultado in resultados:
    print(f"    {'OK   ' if resultado else 'FAIL '} {nombre}")
print("=" * 72)
if ok == total:
    print("  INTEGRACIÓN VERIFICADA SOBRE MÓDULOS REALES")
    print("  proteccion.py / ml_proteccion.py / launcher.py / barrer+catalogo")
else:
    print("  INTEGRACIÓN INCOMPLETA: HAY PRUEBAS FALLIDAS")
print("=" * 72)

if __name__ == "__main__":
    sys.exit(0 if ok == total else 1)
