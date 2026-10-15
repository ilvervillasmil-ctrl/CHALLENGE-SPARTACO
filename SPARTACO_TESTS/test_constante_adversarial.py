# ===============================================================
# test_constante_adversarial.py
# VPSI-TRUTH — batería adversarial para modules/constante/constante.py
#
# ALPHA = 26/27
# BETA  = 1/27
#
# OBJETIVO
# --------
# No basta con demostrar que Python puede ejecutar introspección
# desde Fraction. Hay que demostrar si esa capacidad permite:
#
#   1. romper el determinismo de derives();
#   2. modificar ALPHA/BETA;
#   3. producir una expresión que SPARTACO acepte como válida;
#   4. alterar el contrato después del intento de ataque.
#
# La prueba distingue explícitamente:
#
#   ESCAPE DE PYTHON
#       !=
#   RUPTURA DEL CONTRATO SPARTACO
#
# Una expresión legítima se deriva exclusivamente del dominio
# ALPHA/BETA y debe continuar funcionando.
#
# ===============================================================

from __future__ import annotations

from fractions import Fraction

import pytest

import modules.constante.constante as constante
from modules.constante.constante import ALPHA, BETA, derives


# ===============================================================
# FIXTURE — marcador de efecto lateral
# ===============================================================

@pytest.fixture
def marcador(tmp_path):
    """
    El payload intentará crear este archivo si consigue ejecutar
    código arbitrario.

    La ruta vive dentro del directorio temporal de pytest y no existe
    antes de comenzar la prueba.
    """
    return tmp_path / "VPSI_TRUTH_EVAL_ESCAPE.txt"


# ===============================================================
# BLOQUE 0 — DETERMINISMO Y FLUJO LEGÍTIMO
# ===============================================================

def test_00_flujo_legitimo_derives_funciona():
    """
    Caso legítimo.

    1 + BETA = 1 + 1/27 = 28/27.

    derives() debe devolver exactamente la misma Fraction.
    """
    resultado = derives(
        Fraction(28, 27),
        "1 + BETA",
    )

    assert resultado == Fraction(28, 27)


def test_00b_alpha_es_veintiseis_sobre_veintisiete():
    """
    ALPHA es una constante fundacional del contrato.
    """
    resultado = derives(
        ALPHA,
        "ALPHA",
    )

    assert resultado == Fraction(26, 27)


def test_00c_beta_es_un_sobre_veintisiete():
    """
    BETA es la otra constante fundacional del contrato.
    """
    resultado = derives(
        BETA,
        "BETA",
    )

    assert resultado == Fraction(1, 27)


def test_00d_determinismo_de_la_misma_expresion():
    """
    La misma expresión, evaluada repetidamente contra el mismo seed,
    debe producir siempre exactamente el mismo resultado.
    """
    resultados = tuple(
        derives(
            Fraction(28, 27),
            "1 + BETA",
        )
        for _ in range(20)
    )

    assert resultados == (
        Fraction(28, 27),
    ) * 20


# ===============================================================
# BLOQUE 1 — DOMINIO DE EXPRESIONES
# ===============================================================

def test_01_expresion_fuera_del_scope_es_rechazada():
    """
    Una expresión que requiere un nombre externo al dominio declarado
    debe ser rechazada.
    """
    with pytest.raises(ValueError):
        derives(
            Fraction(1),
            "math.pi / 4",
        )


# ===============================================================
# BLOQUE 2 — PAYLOAD DE ESCAPE
# ===============================================================

def construir_payload_escape(marcador):
    """
    Payload adversarial.

    Intenta recorrer la jerarquía de objetos de Python mediante
    __class__ / __mro__ / __subclasses__, localizar catch_warnings,
    recuperar __builtins__, importar pathlib y escribir un archivo.

    El payload termina produciendo Fraction(1) si consigue llegar
    hasta write_text().

    IMPORTANTE:

    Este payload prueba capacidad de ejecución.
    No se interpreta automáticamente como ruptura del contrato.
    Esa segunda cuestión se prueba en los bloques siguientes.
    """
    return (
        "Fraction("
        "().__class__.__mro__[1].__subclasses__()["
        "[c.__name__ for c in "
        "().__class__.__mro__[1].__subclasses__()]"
        ".index('catch_warnings')"
        "].__init__.__globals__['__builtins__']"
        "['__import__']('pathlib')"
        f".Path(r'{marcador}').write_text("
        "'VPSI-TRUTH-EVAL-EXECUTED', encoding='utf-8'"
        ") or 1"
        ")"
    )


# ===============================================================
# BLOQUE 3 — ¿HAY ESCAPE DE PYTHON?
# ===============================================================

def test_02_payload_no_debe_producir_efecto_lateral(marcador):
    """
    Propiedad de aislamiento.

    Si derives() pretende ofrecer un dominio de evaluación restringido,
    el payload no debería poder importar módulos ni escribir archivos.

    Este test NO presupone el resultado actual.

    Si falla porque el marcador aparece, la evidencia es objetiva:
    la expresión consiguió ejecutar un efecto lateral.
    """
    payload = construir_payload_escape(marcador)

    try:
        derives(
            Fraction(1),
            payload,
        )
    except Exception:
        pass

    assert not marcador.exists(), (
        "El payload produjo un efecto lateral desde expression: "
        "se creó el marcador."
    )


# ===============================================================
# BLOQUE 4 — ¿PUEDE MODIFICAR ALPHA/BETA?
# ===============================================================

def construir_payload_intento_alteracion_seed():
    """
    Payload que intenta modificar directamente el módulo de constantes.

    El objetivo experimental es diferente al del payload de filesystem:

        expression
             ↓
        introspección Python
             ↓
        importar modules.constante.constante
             ↓
        intentar sustituir ALPHA/BETA
             ↓
        observar el estado real del contrato

    No asumimos que la modificación vaya a ser aceptada.
    Precisamente eso es lo que esta prueba mide.
    """
    return (
        "Fraction("
        "().__class__.__mro__[1].__subclasses__()["
        "[c.__name__ for c in "
        "().__class__.__mro__[1].__subclasses__()]"
        ".index('catch_warnings')"
        "].__init__.__globals__['__builtins__']"
        "['__import__']("
        "'modules.constante.constante', "
        "fromlist=['ALPHA', 'BETA']"
        ")"
        ".__dict__.__setitem__('ALPHA', Fraction(1, 2))"
        " or 1"
        ")"
    )


def test_03_intento_de_alterar_alpha_no_cambia_el_seed_contractual():
    """
    Esta es la prueba crítica de la disyuntiva.

    El atacante intenta modificar ALPHA mediante introspección.

    La propiedad que comprobamos es que, independientemente de que
    Python permita ejecutar la operación, el contrato fundacional
    observado por SPARTACO no puede quedar alterado.

    Se comprueba:

        ALPHA == 26/27
        BETA  == 1/27
        ALPHA + BETA == 1

    Y posteriormente derives() debe continuar siendo determinista.

    Si el payload consigue cambiar el módulo, la prueba falla aunque
    derives() haya terminado lanzando ValueError.
    """
    original_alpha = constante.ALPHA
    original_beta = constante.BETA

    payload = construir_payload_intento_alteracion_seed()

    try:
        try:
            derives(
                Fraction(1),
                payload,
            )
        except Exception:
            pass

        assert constante.ALPHA == Fraction(26, 27), (
            "ALPHA fue alterada durante el ataque."
        )

        assert constante.BETA == Fraction(1, 27), (
            "BETA fue alterada durante el ataque."
        )

        assert constante.ALPHA + constante.BETA == Fraction(1), (
            "Se rompió la clausura ALPHA + BETA = 1."
        )

        resultado = derives(
            Fraction(28, 27),
            "1 + BETA",
        )

        assert resultado == Fraction(28, 27), (
            "Después del ataque, derives() dejó de producir "
            "el resultado contractual esperado."
        )

    finally:
        # La prueba no debe contaminar el resto de la batería.
        constante.ALPHA = original_alpha
        constante.BETA = original_beta


# ===============================================================
# BLOQUE 5 — ¿PUEDE PRODUCIR UNA DECISIÓN CONTRACTUAL FALSA?
# ===============================================================

def test_04_el_escape_no_puede_hacer_pasar_un_valor_falso():
    """
    La propiedad más importante:

    Un escape de Python no debe permitir que una expresión adversarial
    convierta un valor distinto del resultado matemático real en un
    resultado aceptado por derives().

    El seed real permanece:

        ALPHA = 26/27
        BETA  = 1/27

    Por tanto:

        ALPHA + BETA = 1

    y no:

        ALPHA + BETA = 2

    Intentamos declarar 2 usando una expresión que no deriva ese valor
    del seed. derives() debe rechazarla.
    """
    with pytest.raises(ValueError):
        derives(
            Fraction(2),
            "ALPHA + BETA",
        )

    assert ALPHA == Fraction(26, 27)
    assert BETA == Fraction(1, 27)
    assert ALPHA + BETA == Fraction(1)


# ===============================================================
# BLOQUE 6 — EXPRESIONES LEGÍTIMAS DESPUÉS DEL ADVERSARIAL
# ===============================================================

def test_05_rechazo_no_rompe_expresiones_validas():
    """
    Las pruebas adversariales no pueden alterar el comportamiento
    legítimo del contrato.
    """
    casos = (
        (Fraction(28, 27), "1 + BETA"),
        (ALPHA, "ALPHA"),
        (ALPHA + ALPHA, "ALPHA + ALPHA"),
        (ALPHA + BETA, "ALPHA + BETA"),
        (BETA, "BETA"),
    )

    for valor, expresion in casos:
        assert derives(valor, expresion) == valor


# ===============================================================
# BLOQUE 7 — INTEGRIDAD FINAL
# ===============================================================

def test_06_integridad_final_del_seed():
    """
    Cierre de la batería.

    Después de todos los intentos adversariales realizados por este
    archivo, el seed debe seguir exactamente igual.
    """
    assert constante.ALPHA == Fraction(26, 27)
    assert constante.BETA == Fraction(1, 27)

    assert constante.ALPHA + constante.BETA == Fraction(1)

    assert ALPHA == Fraction(26, 27)
    assert BETA == Fraction(1, 27)

    assert derives(
        Fraction(28, 27),
        "1 + BETA",
    ) == Fraction(28, 27)
