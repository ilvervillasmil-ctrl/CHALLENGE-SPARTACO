# ===========================================================================
# SPARTACO-SECURITY — tests/test_spartaco_ataque_total_atribucion.py
# ===========================================================================
#
# TOTAL ATTACK CAMPAIGN WITH DEFENSIVE ATTRIBUTION
# ---------------------------------------------------------------------------
#
# OBJECTIVE
# ---------------------------------------------------------------------------
# Execute the tests already present in the repository — without modifying
# the backend and without creating new defense mechanisms — and produce
# an autopsy that answers, for every executed test:
#
#   1) Which test was executed?
#   2) Which actual program components were exercised?
#   3) Which component can be identified as the primary defender,
#      based on evidence from the test itself?
#   4) How did the defense respond, according to the observable test
#      outcome?
#   5) What was the final result?
#
# FIDELITY RULES
# ---------------------------------------------------------------------------
#   - No invented defenders: attribution is derived exclusively from the
#     actual production imports declared by the test under analysis,
#     extracted with AST, never executed.
#   - No modification of production code.
#   - No description of offensive procedures; no generation of new
#     payloads.
#   - Only tests already present in the repository are used.
#   - A PASS validates the specific property required by that test; it
#     does NOT serve as a universal guarantee that no vulnerabilities
#     exist.
#   - If attribution is not unequivocal, it is reported as
#     INDETERMINATE, never forced into a convenient answer.
#
# WHAT THIS FILE IS
# ---------------------------------------------------------------------------
# A meta-test. It does not attack any module, it does not qualify an
# instrument, it does not audit an isolated resource, it does not
# verify a closure, and it does not prove a theorem. It measures the
# coherence and the attributability of the entire adversarial suite
# and produces a forensic report of that measurement.
#
# DISCOVERY
# ---------------------------------------------------------------------------
# The file iterates over tests/test_*.py, excluding itself to avoid
# recursion, and filters the adversarial suites by nominal pattern:
#
#     adversarial, redteam, aniquilador, demolicion, montecarlo,
#     cadena_grafo, killdog, centinela, probe_deeper,
#     universal_closure, sello_clausura
#
# The classification is by convention, not by inference. No new tests
# are created; no existing tests are reclassified.
#
# COMPONENT EXTRACTION
# ---------------------------------------------------------------------------
# Production imports are extracted via AST, without executing the file.
# Only imports starting with core. or modules. count as evidence of a
# production component. Paths are normalized to concrete components:
#
#     modules.spartaco_seguridad.proteccion  ->  SPARTACO_SEGURIDAD.PROTECCION
#     core.centinela                          ->  CORE.CENTINELA
#     modules.interfaz.paquetes.spartaco_ui   ->  INTERFAZ.SPARTACO_UI
#
# ATTRIBUTION
# ---------------------------------------------------------------------------
# Attribution is strict and conservative:
#
#   - One production component imported -> that component is the
#     unequivocal primary defender. Evidence key:
#     atribucion=import_unico_del_test.
#   - More than one production component imported -> no hierarchy is
#     invented. Primary defender is INDETERMINADO; every imported
#     component is recorded as an observed secondary candidate.
#     Evidence key: atribucion=varios_componentes_importados.
#   - Zero production components imported -> INDETERMINADO. Evidence
#     key: atribucion=sin_import_de_produccion_directo.
#
# This design avoids the classic failure mode of security reports:
# attributing a defender by convenience when the evidence does not
# support it.
#
# EXECUTION
# ---------------------------------------------------------------------------
# Each adversarial suite is executed in an isolated subprocess:
#
#     pytest -q <file> --junitxml=<tmp> --tb=short
#
# with cwd at the repository root and PYTHONPATH configured. Results
# are parsed from the JUnit XML. States are PASS, FAIL, SKIP, ERROR.
# If a subprocess produces no testcase in the XML, the failure is not
# hidden: a synthetic case is recorded with state ERROR (nonzero return
# code) or INDETERMINATE (zero return code with no cases), and the full
# stdout is attached as failure detail.
#
# BASELINE
# ---------------------------------------------------------------------------
# After the adversarial suites have been executed individually, the
# file runs every test in the repository in a single invocation with
# --junitxml, using a temporary path outside the repo. This provides a
# single, unambiguous reference point: the repository as a whole is
# either green or not green.
#
# OBSERVED OUTCOME TRANSLATION
# ---------------------------------------------------------------------------
# The file translates test states to campaign vocabulary without
# inferring internal mechanisms:
#
#     PASS            cumplió la condición exigida por la prueba
#                     RESISTIO_LA_PRUEBA
#     FAIL | ERROR    no cumplió la condición exigida por la prueba
#                     REGRESION_O_BRECHA_POTENCIAL
#     SKIP            no produjo veredicto ejecutado
#                     INDETERMINADO
#
# No mechanism is deduced; only the observable result is recorded.
#
# STRUCTURAL COVERAGE
# ---------------------------------------------------------------------------
# Two sets are crossed:
#   - Components observed by adversarial imports (union of all
#     production imports across adversarial suites).
#   - Components detected in the repository (all .py files under
#     core/ and modules/, normalized to component names).
#
# The difference is reported as components with no direct adversarial
# evidence in this campaign. The file does not require all components
# to be covered; it reports the gap as a finding, not as a failure.
#
# PERSISTED ARTIFACTS
# ---------------------------------------------------------------------------
#   diagnostics/SPARTACO_ATAQUE_TOTAL_REPORT.json
#   diagnostics/SPARTACO_ATAQUE_TOTAL_REPORT.md
#
# Both are written before any assertion. If the test fails, the report
# is already on disk.
#
# FINAL ASSERTIONS
# ---------------------------------------------------------------------------
#   1) The campaign produced at least one adversarial case.
#   2) Zero adversarial failures.
#   3) Zero adversarial errors and the baseline total is green.
#
# No regression is disguised as campaign success. The campaign does
# not "pass" if the system underneath is not green.
#
# WHAT THIS FILE IS NOT
# ---------------------------------------------------------------------------
#   - It is not an adversarial test: it does not attack any module.
#   - It is not a metrological kernel: it does not qualify an
#     instrument.
#   - It is not an isolated-resource auditor.
#   - It is not a closure test, a purity-of-construction theorem, or a
#     monitor.
#   - It does not certify the whole system: it certifies that the
#     adversarial suite, executed together, is coherent, attributable
#     and green.
#
# ROLE IN THE SUITE
# ---------------------------------------------------------------------------
# The adversarial battery attacks the layered architecture of
# proteccion.py. The credential red-teams attack credencial.py. The
# metrological kernel audits the instruments. The integration smoke
# test checks the honest end-to-end path. The monitor correlates
# external and internal observation. The fail-closed auditor qualifies
# itself against synthetic controls. The seal closure test verifies
# that declared algebra is physically operated. The universal closure
# verifies that what is verified equals what is loaded equals what is
# executed. The enablement theorem verifies purity of construction.
# This file is the administrative closure of the suite: it verifies
# that the entire set of tests, executed together, is coherent,
# attributable by declaration, and green without exceptions disguised.
#
# PRINCIPLE
# ---------------------------------------------------------------------------
# A report that says "green" without saying who defended what is not a
# security report; it is a status indicator. A report that invents a
# defender by convenience is worse than no report. This file measures
# the coherence and attributability of the entire adversarial suite
# using only the tests that already exist and only the evidence that
# the tests themselves declare.
#
# ===========================================================================

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import pytest


HERE = Path(__file__).resolve()
REPO = HERE.parent.parent if HERE.parent.name == "tests" else Path.cwd().resolve()
TESTS = REPO / "tests"
DIAG = REPO / "diagnostics"
REPORT_JSON = DIAG / "SPARTACO_ATAQUE_TOTAL_REPORT.json"
REPORT_MD = DIAG / "SPARTACO_ATAQUE_TOTAL_REPORT.md"

SELF_NAME = HERE.name

# Se consideran adversariales por nombre; no se inventan pruebas nuevas.
ADVERSARIAL_PATTERNS = (
    "adversarial",
    "redteam",
    "aniquilador",
    "demolicion",
    "montecarlo",
    "cadena_grafo",
    "killdog",
    "centinela",
    "probe_deeper",
    "universal_closure",
    "sello_clausura",
)

# Rutas de producción reales cuyo import sí cuenta como evidencia de componente.
PRODUCTION_PREFIXES = (
    "core.",
    "modules.",
)


@dataclass
class Caso:
    suite: str
    test: str
    estado: str
    tiempo_s: Optional[float]
    componentes_ejercitados: List[str]
    defensor_primario: str
    defensor_secundario: List[str]
    que_hizo: str
    que_paso: str
    evidencia: List[str]
    detalle_fallo: str = ""


@dataclass
class SuiteResultado:
    archivo: str
    returncode: int
    casos: int
    pass_count: int
    fail_count: int
    skip_count: int
    error_count: int
    componentes_importados: List[str]
    stdout_tail: str


def _iter_test_files() -> List[Path]:
    if not TESTS.is_dir():
        raise AssertionError(f"No existe directorio tests: {TESTS}")
    return sorted(
        p for p in TESTS.glob("test_*.py")
        if p.name != SELF_NAME
    )


def _is_adversarial(path: Path) -> bool:
    low = path.name.lower()
    return any(p in low for p in ADVERSARIAL_PATTERNS)


def _imports_produccion(path: Path) -> List[str]:
    """Extrae imports de producción desde AST, sin ejecutar el archivo."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    encontrados: List[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name.startswith(PRODUCTION_PREFIXES):
                    encontrados.append(name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith(PRODUCTION_PREFIXES):
                encontrados.append(mod)

    # Normaliza a componente concreto de mayor utilidad, preservando evidencia.
    return sorted(dict.fromkeys(encontrados))


def _componente_de_import(imp: str) -> str:
    # core.centinela -> CORE.CENTINELA
    # modules.spartaco_seguridad.proteccion -> SPARTACO_SEGURIDAD.PROTECCION
    partes = imp.split(".")
    if partes[:2] == ["modules", "spartaco_seguridad"]:
        if len(partes) >= 3:
            return f"SPARTACO_SEGURIDAD.{partes[2].upper()}"
        return "SPARTACO_SEGURIDAD"
    if partes and partes[0] == "core":
        return "CORE" if len(partes) == 1 else f"CORE.{partes[1].upper()}"
    if partes[:2] == ["modules", "interfaz"]:
        return "INTERFAZ" if len(partes) == 2 else f"INTERFAZ.{partes[2].upper()}"
    return imp.upper()


def _componentes(imports: Sequence[str]) -> List[str]:
    return sorted(dict.fromkeys(_componente_de_import(x) for x in imports))


def _atribuir_defensor(componentes: Sequence[str]) -> Tuple[str, List[str], List[str]]:
    """
    Atribución estricta:
    - 1 componente concreto -> primario inequívoco.
    - >1 -> no se inventa jerarquía; primario INDETERMINADO y todos quedan como
      candidatos/segundarios observados.
    - 0 -> INDETERMINADO.
    """
    comps = list(componentes)
    if len(comps) == 1:
        return comps[0], [], ["atribucion=import_unico_del_test"]
    if len(comps) > 1:
        return "INDETERMINADO", comps, ["atribucion=varios_componentes_importados"]
    return "INDETERMINADO", [], ["atribucion=sin_import_de_produccion_directo"]


def _texto_fallo(case: ET.Element) -> str:
    for tag in ("failure", "error"):
        child = case.find(tag)
        if child is not None:
            txt = (child.get("message") or "") + "\n" + (child.text or "")
            return txt.strip()[:4000]
    return ""


def _estado_case(case: ET.Element) -> str:
    if case.find("failure") is not None:
        return "FAIL"
    if case.find("error") is not None:
        return "ERROR"
    if case.find("skipped") is not None:
        return "SKIP"
    return "PASS"


def _interpretar(estado: str, test_name: str) -> Tuple[str, str]:
    """No deduce mecanismo interno; solo traduce resultado observable."""
    if estado == "PASS":
        return (
            "Cumplió la condición de seguridad o coherencia exigida por esta prueba.",
            "RESISTIO_LA_PRUEBA",
        )
    if estado in {"FAIL", "ERROR"}:
        return (
            "No cumplió la condición exigida por la prueba o la ejecución terminó con error.",
            "REGRESION_O_BRECHA_POTENCIAL",
        )
    if estado == "SKIP":
        return (
            "La prueba no produjo veredicto ejecutado.",
            "INDETERMINADO",
        )
    return ("Resultado no clasificable.", "INDETERMINADO")


def _run_pytest_file(path: Path, junit: Path) -> Tuple[int, str]:
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        str(path.relative_to(REPO)),
        f"--junitxml={junit}",
        "--tb=short",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )
    return proc.returncode, proc.stdout


def _parse_junit(path: Path) -> List[ET.Element]:
    if not path.exists():
        return []
    root = ET.parse(path).getroot()
    return list(root.iter("testcase"))


def _suite_counts(cases: Iterable[Caso]) -> Tuple[int, int, int, int]:
    p = f = s = e = 0
    for c in cases:
        if c.estado == "PASS": p += 1
        elif c.estado == "FAIL": f += 1
        elif c.estado == "SKIP": s += 1
        elif c.estado == "ERROR": e += 1
    return p, f, s, e


def _production_files() -> List[str]:
    files: List[Path] = []
    for base in (REPO / "core", REPO / "modules"):
        if base.is_dir():
            files.extend(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)
    return sorted(str(p.relative_to(REPO)) for p in files)


def _production_components() -> List[str]:
    comps: List[str] = []
    for rel in _production_files():
        p = Path(rel)
        if p.parts[0] == "core":
            comps.append(f"CORE.{p.stem.upper()}" if p.stem != "__init__" else "CORE")
        elif p.parts[:2] == ("modules", "spartaco_seguridad"):
            if p.stem == "__init__":
                comps.append("SPARTACO_SEGURIDAD")
            else:
                comps.append(f"SPARTACO_SEGURIDAD.{p.stem.upper()}")
        elif p.parts[:2] == ("modules", "interfaz"):
            comps.append("INTERFAZ" if p.stem == "__init__" else f"INTERFAZ.{p.stem.upper()}")
    return sorted(dict.fromkeys(comps))


def _write_reports(payload: Dict[str, object]) -> None:
    DIAG.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )

    lines: List[str] = []
    lines.append("# SPARTACO — ATAQUE TOTAL / ATRIBUCIÓN DEFENSIVA")
    lines.append("")
    lines.append("Esta campaña reutiliza pruebas existentes. No crea nuevas técnicas ofensivas ni modifica el backend.")
    lines.append("")

    resumen = payload["resumen"]  # type: ignore[index]
    lines.append("## Resumen")
    lines.append("")
    for k, v in resumen.items():  # type: ignore[union-attr]
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    coverage = payload["cobertura"]  # type: ignore[index]
    lines.append("## Cobertura estructural adversarial")
    lines.append("")
    lines.append(f"- Componentes de producción observados por imports adversariales: {coverage['componentes_observados']}" )  # type: ignore[index]
    lines.append(f"- Componentes de producción detectados en repo: {coverage['componentes_totales_repo']}" )  # type: ignore[index]
    no_obs = coverage["componentes_sin_evidencia_adversarial_directa"]  # type: ignore[index]
    if no_obs:
        lines.append("- Sin evidencia adversarial directa en esta campaña: " + ", ".join(no_obs))
    else:
        lines.append("- Todos los componentes detectados tienen al menos evidencia adversarial directa por import.")
    lines.append("")

    lines.append("## Autopsia por prueba")
    lines.append("")
    lines.append("| Suite | Test | Estado | Defensor primario | Componentes ejercitados | Qué pasó |")
    lines.append("|---|---|---|---|---|---|")
    for raw in payload["casos"]:  # type: ignore[index]
        comps = ", ".join(raw["componentes_ejercitados"]) or "—"
        lines.append(
            f"| `{raw['suite']}` | `{raw['test']}` | **{raw['estado']}** | "
            f"{raw['defensor_primario']} | {comps} | {raw['que_paso']} |"
        )
    lines.append("")

    lines.append("## Suites")
    lines.append("")
    for s in payload["suites"]:  # type: ignore[index]
        lines.append(
            f"- `{s['archivo']}` — rc={s['returncode']} · casos={s['casos']} · "
            f"pass={s['pass_count']} · fail={s['fail_count']} · skip={s['skip_count']} · error={s['error_count']}"
        )

    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _campana() -> Dict[str, object]:
    all_tests = _iter_test_files()
    adversarial = [p for p in all_tests if _is_adversarial(p)]
    if not adversarial:
        raise AssertionError("No se encontraron suites adversariales existentes en tests/")

    casos_globales: List[Caso] = []
    suites_globales: List[SuiteResultado] = []
    imports_adversariales: List[str] = []

    with tempfile.TemporaryDirectory(prefix="spartaco-ataque-total-") as td:
        tmp = Path(td)
        for idx, suite in enumerate(adversarial):
            imports = _imports_produccion(suite)
            imports_adversariales.extend(imports)
            componentes = _componentes(imports)
            primario, secundarios, evidencia_attr = _atribuir_defensor(componentes)

            junit = tmp / f"suite_{idx}.xml"
            rc, stdout = _run_pytest_file(suite, junit)
            xml_cases = _parse_junit(junit)

            suite_cases: List[Caso] = []
            if not xml_cases:
                # Si pytest no alcanzó a producir casos, no se oculta el fallo.
                estado = "ERROR" if rc else "INDETERMINADO"
                que_hizo, que_paso = _interpretar(estado, suite.name)
                suite_cases.append(Caso(
                    suite=suite.name,
                    test="<sin_testcase_junit>",
                    estado=estado,
                    tiempo_s=None,
                    componentes_ejercitados=componentes,
                    defensor_primario=primario,
                    defensor_secundario=secundarios,
                    que_hizo=que_hizo,
                    que_paso=que_paso,
                    evidencia=evidencia_attr + ["junit=ausente_o_vacio"],
                    detalle_fallo=stdout[-4000:],
                ))
            else:
                for xc in xml_cases:
                    estado = _estado_case(xc)
                    name = xc.get("name") or "<sin_nombre>"
                    time_raw = xc.get("time")
                    try:
                        tiempo = float(time_raw) if time_raw is not None else None
                    except ValueError:
                        tiempo = None
                    que_hizo, que_paso = _interpretar(estado, name)
                    suite_cases.append(Caso(
                        suite=suite.name,
                        test=name,
                        estado=estado,
                        tiempo_s=tiempo,
                        componentes_ejercitados=componentes,
                        defensor_primario=primario,
                        defensor_secundario=secundarios,
                        que_hizo=que_hizo,
                        que_paso=que_paso,
                        evidencia=evidencia_attr + [f"pytest={estado}", f"suite={suite.name}"],
                        detalle_fallo=_texto_fallo(xc),
                    ))

            p, f, s, e = _suite_counts(suite_cases)
            suites_globales.append(SuiteResultado(
                archivo=suite.name,
                returncode=rc,
                casos=len(suite_cases),
                pass_count=p,
                fail_count=f,
                skip_count=s,
                error_count=e,
                componentes_importados=componentes,
                stdout_tail=stdout[-2000:],
            ))
            casos_globales.extend(suite_cases)

    # Baseline total del repo: ejecuta todos los tests existentes, excepto este meta-test.
    # Se hace en una sola invocación explícita para no recursar.
    baseline_junit = Path(tempfile.gettempdir()) / "spartaco_baseline_total.xml"
    baseline_cmd = [
        sys.executable, "-m", "pytest", "-q",
        *[str(p.relative_to(REPO)) for p in all_tests],
        f"--junitxml={baseline_junit}", "--tb=short",
    ]
    baseline_proc = subprocess.run(
        baseline_cmd,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )
    baseline_xml = _parse_junit(baseline_junit)
    baseline_counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "ERROR": 0}
    for xc in baseline_xml:
        baseline_counts[_estado_case(xc)] += 1

    observed_components = sorted(dict.fromkeys(_componentes(imports_adversariales)))
    repo_components = _production_components()
    missing = sorted(c for c in repo_components if c not in observed_components)

    total_pass = sum(1 for c in casos_globales if c.estado == "PASS")
    total_fail = sum(1 for c in casos_globales if c.estado == "FAIL")
    total_skip = sum(1 for c in casos_globales if c.estado == "SKIP")
    total_error = sum(1 for c in casos_globales if c.estado == "ERROR")

    payload: Dict[str, object] = {
        "schema": "SPARTACO_ATAQUE_TOTAL_REPORT_V1",
        "repo": str(REPO),
        "metodo": {
            "tipo": "reutilizacion_de_tests_existentes",
            "modifica_backend": False,
            "genera_payloads_nuevos": False,
            "atribucion": "imports_AST_del_test; si no es inequivoca => INDETERMINADO",
        },
        "resumen": {
            "suites_adversariales": len(adversarial),
            "casos_adversariales": len(casos_globales),
            "pass_adversarial": total_pass,
            "fail_adversarial": total_fail,
            "skip_adversarial": total_skip,
            "error_adversarial": total_error,
            "baseline_total_returncode": baseline_proc.returncode,
            "baseline_total_casos": len(baseline_xml),
            "baseline_total_pass": baseline_counts["PASS"],
            "baseline_total_fail": baseline_counts["FAIL"],
            "baseline_total_skip": baseline_counts["SKIP"],
            "baseline_total_error": baseline_counts["ERROR"],
        },
        "cobertura": {
            "componentes_observados": len(observed_components),
            "componentes_totales_repo": len(repo_components),
            "lista_componentes_observados": observed_components,
            "lista_componentes_repo": repo_components,
            "componentes_sin_evidencia_adversarial_directa": missing,
        },
        "suites": [asdict(s) for s in suites_globales],
        "casos": [asdict(c) for c in casos_globales],
        "baseline_stdout_tail": baseline_proc.stdout[-5000:],
    }
    _write_reports(payload)
    return payload



def test_spartaco_ataque_total_atribucion() -> None:
    payload = _campana()
    r = payload["resumen"]

    # La campaña misma debe haberse podido ejecutar y producir evidencia.
    assert r["casos_adversariales"] > 0, "La campaña adversarial no produjo casos."
    assert REPORT_JSON.exists(), f"No se generó {REPORT_JSON}"
    assert REPORT_MD.exists(), f"No se generó {REPORT_MD}"

    # Un fallo real en cualquier prueba existente hace fallar este meta-test.
    # No se maquilla una regresión como éxito de campaña.
    assert r["fail_adversarial"] == 0, (
        f"Hay {r['fail_adversarial']} fallos adversariales. Ver {REPORT_MD}"
    )
    assert r["error_adversarial"] == 0, (
        f"Hay {r['error_adversarial']} errores adversariales. Ver {REPORT_MD}"
    )
    assert r["baseline_total_returncode"] == 0, (
        "La suite total del repositorio no está verde. "
        f"Ver {REPORT_MD} y {REPORT_JSON}"
    )


if __name__ == "__main__":
    data = _campana()
    print(json.dumps(data["resumen"], ensure_ascii=False, indent=2))
    print(f"\nJSON: {REPORT_JSON}")
    print(f"MD:   {REPORT_MD}")
