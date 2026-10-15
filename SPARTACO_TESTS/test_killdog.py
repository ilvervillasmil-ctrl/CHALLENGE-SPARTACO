# ==============================================================
# SPARTACO-SECURITY — tests/test_killdog.py
# ==============================================================
#
# Batería funcional de Killdog.
#
# Comprueba:
#
#   1. Artefacto coherente        -> PERMITIR
#   2. Identidad incorrecta       -> ELIMINAR
#   3. Contrato incorrecto        -> ELIMINAR
#   4. Pertenencia incorrecta     -> ELIMINAR
#   5. Coherencia incorrecta      -> ELIMINAR
#   6. Autoautorización           -> ELIMINAR
#   7. Ausencia de evidencia      -> ELIMINAR
#   8. Discriminación SELF/NONSELF
#   9. Vector Φ
#  10. Clonación
#  11. Misma capacidad
#  12. Cuerpos diferentes
#  13. Misma A_K
#  14. Ubicaciones diferentes
#  15. Un cuerpo no modifica la capacidad
#  16. No consulta Engine
#  17. No consulta Centinela
#
# IMPORTANTE:
#
# Este test comprueba la DECISIÓN de enforcement.
# No elimina procesos ni archivos reales.
#
# ==============================================================

from __future__ import annotations

from core.killdog import (
    AJENO,
    ID_CAPACIDAD_KILLDOG,
    K_ACEPTADO,
    K_RECHAZADO,
    PROPIO,
    REACCION_ELIMINAR,
    REACCION_PERMITIR,
    Killdog,
    clonar_killdog,
)


# ===============================================================
# ANCLA DE PRUEBA
# ===============================================================

ANCLA = {
    "id": "MODULO-001",
    "nombre": "modulo_seguro",
    "rol": "SEGURIDAD",
    "artifact_id": "ART-001",
    "nucleo": "NUCLEO-001",

    "esquemas": [
        "VPSI-CONTRACT-1.0",
    ],

    "claves_cuerpo": [
        "id",
        "nombre",
        "rol",
        "artifact_id",
    ],

    "firma": "FIRMA-VALIDA",

    "miembros": [
        {
            "id": "MODULO-001",
            "nombre": "modulo_seguro",
            "rol": "SEGURIDAD",
            "artifact_id": "ART-001",
        }
    ],

    "estados": [
        "OPERATIVO",
    ],

    "capacidades": [
        "proteger",
        "verificar",
        "evaluar",
    ],

    "nombres": [
        "modulo_seguro",
        "SEGURIDAD",
    ],

    "permisos": [
        "leer",
        "consultar",
        "ejecutar",
    ],
}


# ===============================================================
# OBJETO COHERENTE
# ===============================================================

OBJETO_SEGURO = {
    "id": "MODULO-001",
    "nombre": "modulo_seguro",
    "rol": "SEGURIDAD",
    "artifact_id": "ART-001",
    "nucleo": "NUCLEO-001",

    "esquema": "VPSI-CONTRACT-1.0",
    "firma": "FIRMA-VALIDA",

    "estado": "OPERATIVO",

    "capacidades": {
        "proteger": object(),
        "verificar": object(),
        "evaluar": object(),
    },

    "requiere": [
        "SEGURIDAD",
    ],

    "autoriza_engine": {
        "leer": True,
        "consultar": True,
        "ejecutar": True,
    },

    "errores_arranque": [],

    "registro_total": 1,
}


# ===============================================================
# TEST 1 — OBJETO COHERENTE
# ==============================================================

def test_objeto_coherente():

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        OBJETO_SEGURO
    )

    assert resultado["k"] == K_ACEPTADO

    assert resultado["reaccion"] == (
        REACCION_PERMITIR
    )

    assert resultado["consulta_engine"] is False
    assert resultado["consulta_centinela"] is False

    print(
        "PASS 1 — objeto coherente -> PERMITIR"
    )


# ===============================================================
# TEST 2 — IDENTIDAD FALSA
# ==============================================================

def test_identidad_falsa():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["artifact_id"] = (
        "ART-ATACANTE"
    )

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    assert (
        "I_FALLO"
        in resultado["reconocimiento"]["motivos"]
    )

    print(
        "PASS 2 — identidad falsa -> ELIMINAR"
    )


# ===============================================================
# TEST 3 — CONTRATO FALSO
# ==============================================================

def test_contrato_falso():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["esquema"] = (
        "CONTRATO-FALSO"
    )

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    print(
        "PASS 3 — contrato falso -> ELIMINAR"
    )


# ===============================================================
# TEST 4 — FIRMA FALSA
# ==============================================================

def test_firma_falsa():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["firma"] = (
        "FIRMA-ATACANTE"
    )

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    print(
        "PASS 4 — autenticidad falsa -> ELIMINAR"
    )


# ===============================================================
# TEST 5 — NO PERTENECE A LA ARQUITECTURA
# ==============================================================

def test_no_pertenece():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["id"] = (
        "MODULO-EXTERNO"
    )

    objeto["nombre"] = (
        "codigo_desconocido"
    )

    objeto["rol"] = (
        "ROL_DESCONOCIDO"
    )

    objeto["artifact_id"] = (
        "ART-EXTERNO"
    )

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    print(
        "PASS 5 — objeto ajeno -> ELIMINAR"
    )


# ===============================================================
# TEST 6 — COHERENCIA VIOLADA
# ==============================================================

def test_coherencia_violada():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["estado"] = (
        "COMPROMETIDO"
    )

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    print(
        "PASS 6 — incoherencia -> ELIMINAR"
    )


# ===============================================================
# TEST 7 — CAPACIDAD NO AUTORIZADA
# ==============================================================

def test_capacidad_no_autorizada():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["capacidades"] = {
        "proteger": object(),
        "ejecutar": object(),
        "destruir_sistema": object(),
    }

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    print(
        "PASS 7 — capacidad no autorizada -> ELIMINAR"
    )


# ===============================================================
# TEST 8 — AUTOAUTORIZACIÓN
# ==============================================================

def test_autoautorizacion():

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["autoautoriza"] = True

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        objeto
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    assert (
        "AUTOAUTORIZACION"
        in resultado["reconocimiento"]["motivos"]
    )

    print(
        "PASS 8 — autoautorización -> ELIMINAR"
    )


# ===============================================================
# TEST 9 — SIN EVIDENCIA
# ==============================================================

def test_sin_evidencia():

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        None
    )

    assert resultado["k"] == K_RECHAZADO

    assert resultado["reaccion"] == (
        REACCION_ELIMINAR
    )

    print(
        "PASS 9 — sin evidencia -> ELIMINAR"
    )


# ===============================================================
# TEST 10 — SELF / NONSELF
# ==============================================================

def test_self_nonself():

    kd = Killdog(ANCLA)

    assert kd.propio(
        OBJETO_SEGURO
    ) is True

    assert kd.ajeno(
        OBJETO_SEGURO
    ) is False

    objeto = dict(
        OBJETO_SEGURO
    )

    objeto["artifact_id"] = (
        "ART-EXTERNO"
    )

    assert kd.propio(
        objeto
    ) is False

    assert kd.ajeno(
        objeto
    ) is True

    print(
        "PASS 10 — SELF/NONSELF correcto"
    )


# ===============================================================
# TEST 11 — VECTOR Φ
# ==============================================================

def test_vector_phi():

    kd = Killdog(ANCLA)

    vector = kd.vector_phi(
        OBJETO_SEGURO
    )

    assert vector["I"] == 1
    assert vector["C"] == 1
    assert vector["P"] == 1
    assert vector["H"] == 1
    assert vector["S"] == 1

    print(
        "PASS 11 — Φ = (1,1,1,1,1)"
    )


# ===============================================================
# TEST 12 — CLONACIÓN
# ==============================================================

def test_clonacion():

    kd = Killdog(
        ANCLA,
        ubicacion="CORE",
    )

    clon = kd.clonar(
        ubicacion="MODULO-001"
    )

    assert clon is not kd

    assert (
        clon.cuerpo_id
        != kd.cuerpo_id
    )

    assert (
        clon.capacidad_id
        == kd.capacidad_id
        == ID_CAPACIDAD_KILLDOG
    )

    assert (
        clon.ancla_id
        == kd.ancla_id
    )

    assert (
        clon.ubicacion
        != kd.ubicacion
    )

    print(
        "PASS 12 — clon = mismo Killdog, otro cuerpo"
    )


# ===============================================================
# TEST 13 — MUCHOS CUERPOS / UNA CAPACIDAD
# ==============================================================

def test_multiples_cuerpos():

    kd = Killdog(
        ANCLA,
        ubicacion="CORE",
    )

    clones = clonar_killdog(
        kd,
        cantidad=100,
    )

    assert len(clones) == 100

    ids_cuerpo = {
        c.cuerpo_id
        for c in clones
    }

    ids_capacidad = {
        c.capacidad_id
        for c in clones
    }

    ids_ancla = {
        c.ancla_id
        for c in clones
    }

    assert len(ids_cuerpo) == 100

    assert ids_capacidad == {
        ID_CAPACIDAD_KILLDOG
    }

    assert ids_ancla == {
        kd.ancla_id
    }

    print(
        "PASS 13 — 100 cuerpos / 1 capacidad / 1 A_K"
    )


# ===============================================================
# TEST 14 — TODAS LAS INSTANCIAS RECONOCEN IGUAL
# ==============================================================

def test_misma_logica_en_todos_los_cuerpos():

    kd = Killdog(
        ANCLA,
        ubicacion="CORE",
    )

    clones = clonar_killdog(
        kd,
        cantidad=100,
    )

    for clon in clones:

        seguro = clon.aplicar(
            OBJETO_SEGURO
        )

        assert seguro["k"] == K_ACEPTADO
        assert seguro["reaccion"] == (
            REACCION_PERMITIR
        )

        atacante = dict(
            OBJETO_SEGURO
        )

        atacante["artifact_id"] = (
            "ART-ATACANTE"
        )

        resultado = clon.aplicar(
            atacante
        )

        assert resultado["k"] == (
            K_RECHAZADO
        )

        assert resultado["reaccion"] == (
            REACCION_ELIMINAR
        )

    print(
        "PASS 14 — todos los cuerpos aplican la misma lógica"
    )


# ===============================================================
# TEST 15 — UN CUERPO NO CAMBIA LA LEY
# ==============================================================

def test_inmutabilidad():

    kd = Killdog(
        ANCLA,
        ubicacion="CORE",
    )

    ancla_id_original = (
        kd.ancla_id
    )

    capacidad_original = (
        kd.capacidad_id
    )

    ubicacion_original = (
        kd.ubicacion
    )

    kd.ubicar(
        "OTRA-ZONA"
    )

    assert kd.ancla_id == (
        ancla_id_original
    )

    assert kd.capacidad_id == (
        capacidad_original
    )

    assert kd.ubicacion != (
        ubicacion_original
    )

    print(
        "PASS 15 — puede cambiar posición, no cambia la ley"
    )


# ===============================================================
# TEST 16 — NO GOBERNABLE
# ==============================================================

def test_no_gobernable():

    kd = Killdog(ANCLA)

    assert kd.gobernable_por(
        object()
    ) is False

    try:
        kd.desactivar()
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "Killdog permitió desactivación"
        )

    print(
        "PASS 16 — Killdog no es gobernable"
    )


# ===============================================================
# TEST 17 — NO CONSULTA ENGINE NI CENTINELA
# ==============================================================

def test_autonomia():

    kd = Killdog(ANCLA)

    resultado = kd.aplicar(
        OBJETO_SEGURO
    )

    assert (
        resultado["consulta_engine"]
        is False
    )

    assert (
        resultado["consulta_centinela"]
        is False
    )

    assert (
        resultado["discrecional"]
        is False
    )

    print(
        "PASS 17 — enforcement autónomo"
    )


# ===============================================================
# EJECUCIÓN DIRECTA
# ==============================================================

if __name__ == "__main__":

    tests = [
        test_objeto_coherente,
        test_identidad_falsa,
        test_contrato_falso,
        test_firma_falsa,
        test_no_pertenece,
        test_coherencia_violada,
        test_capacidad_no_autorizada,
        test_autoautorizacion,
        test_sin_evidencia,
        test_self_nonself,
        test_vector_phi,
        test_clonacion,
        test_multiples_cuerpos,
        test_misma_logica_en_todos_los_cuerpos,
        test_inmutabilidad,
        test_no_gobernable,
        test_autonomia,
    ]

    print()
    print("=" * 70)
    print("KILLDOG — TEST FUNCIONAL")
    print("=" * 70)
    print()

    fallos = 0

    for test in tests:

        try:
            test()

        except Exception as exc:

            fallos += 1

            print(
                f"FAIL — {test.__name__}: {exc}"
            )

    print()
    print("=" * 70)

    if fallos == 0:
        print(
            f"RESULTADO: {len(tests)}/{len(tests)} PASS"
        )
        print(
            "KILLDOG: comportamiento coherente con el contrato."
        )
    else:
        print(
            f"RESULTADO: {len(tests) - fallos}/{len(tests)} PASS"
        )
        print(
            f"FALLOS: {fallos}"
        )

    print("=" * 70)

    raise SystemExit(
        0 if fallos == 0 else 1
    )
