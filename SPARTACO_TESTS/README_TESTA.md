SPARTACO Test Suite

This document describes what the test suite contains, what each file does, and how to read it.

---

What this is

A collection of test files under tests/ that exercise the SPARTACO security stack. Each file is self-contained, executable with pytest, and lives at a specific layer of the verification stack. Together they cover:

· module-level adversarial pressure on individual security modules
· metrological qualification of the instruments that measure the system
· audits of isolated resources with persisted evidence
· internal observation of the system during test execution
· closure checks between declared properties and produced bytes
· integration verification of the honest path
· user-facing guarantees about what the interface actually delivers
· administrative coherence across the entire suite

Every file follows the same conventions and emits the same vocabulary of states.

---

Families of tests

1. Module adversarial tests

Attack one specific module with hostile inputs.

File Module under test Focus
test_probe_deeper.py multiple boundaries with highest uncertainty: cycles, manifest shape, non-callable capabilities, path traversal, key round-trip
test_proteccion_adversarial.py proteccion.py declared contract, 38 blocks from happy path to structural attacks
test_proteccion_adversarial_demolicion.py proteccion.py layered architecture, crash-as-failure doctrine, TOCTOU, aliasing, Ed25519 malleability, DoS
test_credencial_aniquilador.py credencial.py single monolithic test that accumulates findings by level (CRITICAL/HIGH/MEDIUM)
test_credencial_redteam.py credencial.py 35 independent attacks with PASS/FAIL/FIXTURE/EXCEPTION policy
test_credencial_redteam_continuacion.py credencial.py 14 additional tests that complete the red-team
test_vinculacion_rotativa.py vinculacion.py full lifecycle of a rotating link: register, build proof, verify, rotate, revoke
test_killdog.py killdog decision consistency across 17 scenarios

2. Metrological tests

Measure the reliability of the instruments that measure the system.

File Focus
test_invariantes_kernel_spartaco.py central metrological kernel: qualifies each invariant against KnownGood, MutationScore, and independent oracles
test_uhcr_calibracion_microscopio.py measures the perturbation introduced by the act of observing, across four instrumental regimes
test_teorema_habilitacion_cierre_v2_2.py verifies purity of construction: engine registers without executing the code it registers

3. Isolated resource auditors

Apply a universal instrument to one resource and produce a persisted record.

File Focus
test_uhcr_fail_closed_falsificacion.py full system surface audit with symmetric calibration, E_P/E_Q separation, mutation testing of the auditor, universal ablation
test_uhcr_v3_4_2.py RAW causal boundary between Engine and provider; refuses to infer absorption semantics from observable consequences alone

4. Observers

Correlate external observation with internal observation.

File Focus
test_monitoreo_diario.py monitor that observes declared capabilities while pytest stimulates them from outside; publishes correlated evidence
test_uhcr_transiciones_neutrales.py measures observable state changes between consecutive invocations; admits or rejects claims according to sampling policy

5. Closure tests

Check that declared properties hold over produced bytes.

File Focus
test_sello_clausura_fisica.py verifies that the algebraic partition of the cube is operated on the bytes the sealing produces
test_spartaco_universal_closure.py verifies verified == loaded == executed across the whole chain, from cube to kernel
test_D1_D7_spartaco_declaracion_vs_conducta.py audits the package as a declaration: what it says it does vs. what can be measured

6. Integration tests

Verify the honest path works end to end.

File Focus
test_integracion.py builds, seals, verifies and executes the bootstrap over the real modules

7. Contract and user tests

Fix architectural decisions in executable form.

File Focus
test_ui_abrir_documento_descargable.py verifies the UI exposes a real path to recover and download protected content, distinct from verify

8. Administrative tests

Consolidate coherence across the suite.

File Focus
test_spartaco_ataque_total_atribucion.py runs existing tests in subprocesses, attributes defenders by AST of production imports, produces a forensic autopsy

---

Shared conventions

Every file in the suite follows these conventions.

Denial by contract

A rejected attack counts as PASS only when the rejection comes through the contract: ok=False, an access_denied concept, and a specific reason code. Crashes, uncaught exceptions, silent None returns, and malformed dicts are not PASS. They are recorded as distinct failure types.

Separate planes

Description, applicability, measurement and verdict are separate stages. Each file declares which plane it is operating in and does not let one plane silently feed another.

Instrument qualification

Before an auditor emits a verdict about the system, it qualifies itself against synthetic controls. If the instrument cannot distinguish a case that should pass from a case that should fail, the verdict about the system is withheld.

Evidence before assertion

Every artifact is persisted to disk before the first assertion runs. If a test fails, the record is already complete.

Vocabulary of states

Each file emits one of a small set of states, and never collapses them:

State Meaning
PASS attack was blocked by the contract in the tested domain
FAIL attack was accepted, or the contract was broken
FIXTURE attack was not executed because the fixture could not be built
EXCEPTION API raised where it should have denied
INSTRUMENT_NOT_QUALIFIED instrument could not be qualified against its own controls
NO_DETERMINADO observation policy does not preserve the information the claim requires
COUNTEREXAMPLE_OBSERVED at least one input produced the protected effect under a falsified precondition
NO_COUNTEREXAMPLE_IN_QUALIFIED_TESTED_DOMAIN no counterexample found in the qualified tested domain
PROPERTY_SUPPORTED_FOR_EXHAUSTIVE_FINITE_DOMAIN declared finite domain enumerated exhaustively with a qualified oracle
SECURITY_VERDICT=NOT_EVALUATED the auditor does not emit security verdicts by doctrine

---

Reading order

The suite is cumulative. A new reader should follow this order.

Step 1 — Vocabulary. Start with test_probe_deeper.py. It is the smallest and most conventional. It introduces the vocabulary: contract, rejection, boundary, decision pinned in executable form.

Step 2 — Basic adversarial. Follow with test_proteccion_adversarial.py. The most direct battery. 38 blocks that walk a module's contract from happy path to structural attacks.

Step 3 — Full adversarial. Then test_proteccion_adversarial_demolicion.py. Architectural layers are stacked, and the crash-as-failure doctrine appears. The same module is attacked from thirteen complementary angles.

Step 4 — Integration. test_integracion.py. Short, clear, verifies the honest path works. The necessary contrast after so much adversarial pressure.

Step 5 — Metrology. test_invariantes_kernel_spartaco.py. Introduces instrument qualification before use. Dense. Only makes sense after seeing what a normal adversarial test looks like.

Step 6 — Full auditor. test_uhcr_fail_closed_falsificacion.py. The largest file. By the time you read it, you have the vocabulary, the adversarial doctrine, the metrological doctrine, and the separation of planes. You will see how all of it integrates into one instrument that audits the full system.

Step 7 — Universal closure. test_spartaco_universal_closure.py. Verifies that what is verified equals what is loaded equals what is executed.

Step 8 — The rest. Every other file is accessible once you have the vocabulary and the doctrine. Each declares in its own header what it measures.

---

How to run

Each file is self-contained and runs with pytest from the repository root.

Run the full suite:

```bash
pytest -q tests/ --junitxml=diagnostics/junit.xml
```

Run a single file:

```bash
pytest -q tests/test_uhcr_fail_closed_falsificacion.py -s
```

Files that spawn subprocesses have internal timeouts and are safe to run in CI. Files that use universal ablation rename files temporarily and restore them in finally, so they do not leave the repository in an inconsistent state even when they fail.

---

How to extend

If you are adding a new file to the suite, follow these five rules:

1. Declare at the top what the file measures and what it does not measure.
2. Persist evidence before any assertion.
3. Separate the instrument's verdict from the object's verdict.
4. Use the vocabulary of states the suite already uses.
5. If your instrument emits verdicts, qualify it against synthetic controls before emitting them.

If you are modifying an existing file, the evolution is monotonic: you can add fields, mechanisms and evidence, but you cannot remove existing ones without an explicit documented reason. The SPEC_EVOLUTION field in the larger files records the full history of increments. This keeps design decisions traceable across versions.

If you are pointing the UHCR auditor at a new resource, copy the file, change the TARGET line, and verify that the three identity hashes (full file, template without TARGET, engine without tests) demonstrate that only the audited resource changed. Nothing else is touched.

---

Vocabulary

Contract. The observable shape a module declares and the auditor verifies. Not the implementation; the promise it makes to the outside.

Boundary. The point in a module where a decision is taken or a protected effect is produced. Boundaries are discovered by structural shape, not by name.

Protected effect. What a boundary guarantees will not happen if the precondition is not satisfied. It can be authorizing, opening a resource, issuing a credential, releasing material, establishing a binding, or executing a privileged transition.

Falsification. Systematic mutation of a precondition to verify the protected effect is not produced.

Positive witness. Frozen evidence that the boundary works correctly in the base case. Without a positive witness, the boundary is NOT_QUALIFIED, not FAIL.

Counterexample. The finding that the protected effect is produced under a falsified precondition.

Symmetric calibration. Qualifying the instrument against one control that must pass and another that must fail. Both directions are mandatory.

Production evidence vs qualification evidence. The two sets of cases the auditor accumulates and never mixes. The first measures the system; the second measures the instrument.

Universal ablation. Proof that the auditor survives the temporary disappearance of any component of the system.

Mutation testing of the instrument. Proof that the auditor detects internal sabotage against itself.

---

Layout

```
tests/
├── test_probe_deeper.py
├── test_proteccion_adversarial.py
├── test_proteccion_adversarial_demolicion.py
├── test_credencial_aniquilador.py
├── test_credencial_redteam.py
├── test_credencial_redteam_continuacion.py
├── test_vinculacion_rotativa.py
├── test_killdog.py
├── test_invariantes_kernel_spartaco.py
├── test_uhcr_calibracion_microscopio.py
├── test_teorema_habilitacion_cierre_v2_2.py
├── test_uhcr_fail_closed_falsificacion.py
├── test_uhcr_v3_4_2.py
├── test_monitoreo_diario.py
├── test_uhcr_transiciones_neutrales.py
├── test_sello_clausura_fisica.py
├── test_spartaco_universal_closure.py
├── test_D1_D7_spartaco_declaracion_vs_conducta.py
├── test_integracion.py
├── test_ui_abrir_documento_descargable.py
├── test_spartaco_ataque_total_atribucion.py
└── _spartaco_dvc_motor.py
└── _spartaco_dvc_probe.py
```

Artifacts produced by the audit files land under diagnostics/, with one subdirectory per auditor:

```
diagnostics/
├── uhcr_fail_closed/
├── uhcr_resources/
├── uhcr_transiciones_neutrales/
├── uhcr_v3_4_2/
├── uhcr_calibracion_microscopio/
├── habilitacion_cierre_v2_2/
├── test_evidence.json
└── test_evidence_history/
```
