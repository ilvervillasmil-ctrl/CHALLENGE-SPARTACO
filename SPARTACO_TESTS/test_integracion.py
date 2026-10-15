"""
============================================================================
  test_integracion.py -- Test integral de los módulos que SÍ existen
============================================================================
  0) descubrimiento SC via barrer()/catalogo()
  1) proteccion: generar claves + build + verificar
  2) ml_proteccion: modelo dummy + manifestar + verificar
  3) launcher: verificar_y_ejecutar el bootstrap.elf firmado

No importa deteccion_intoxicacion: no existe en el árbol.
No llama capacidades()/conceptos()/modulos(): __init__.py no las exporta.
============================================================================
"""
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
