# SPARTACO/VPSI v1 — Open Cryptanalysis Challenge

**A public challenge to the international cryptographic and cybersecurity research community**

**Author and developer:** I\. Villasmil
**Research area:** Applied cryptography, authenticated encryption, digital signatures, cryptographic key derivation, integrity verification, and formal security architectures\.

## 1\. Scientific Invitation

I formally invite cryptographers, mathematicians, cybersecurity specialists, academic researchers, and independent security laboratories to examine and attempt to defeat the cryptographic protections of **SPARTACO/VPSI v1** using a publicly available collection of encrypted artifacts\.

The challenge is direct:

**Recover the original plaintext or protected cryptographic material from the released artifacts without possessing the legitimate secret material required by SPARTACO’s opening procedure\.**

All challenge files are my property, were generated for this experiment, and contain no sensitive third\-party information\. I expressly authorize independent cryptanalytic examination of these specific files\.

The SPARTACO engine and its source code are not distributed as part of this challenge\.

The published materials are the cryptographic artifacts themselves\.

## 2\. Technical Architecture

SPARTACO is a cryptographic protection and authorization architecture developed around the separation of integrity, identity, authentication, confidential recovery, and execution authority\.

Its construction combines established cryptographic primitives with artifact\-specific integrity commitments and a contractual authorization model\.

The relevant mechanisms are:

**AES\-256\-GCM — Authenticated Encryption**

Document content is protected using AES\-256\-GCM, which combines ciphertext confidentiality with authentication of the encrypted data and associated authenticated information\.

**HKDF\-SHA256 — Domain\-Separated Key Derivation**

The architecture derives cryptographic keys from account\-associated input key material &#40;IKM&#41;, using distinct derivation domains and artifact\-binding context\.

The four documented domains are:

- `K_AUTH` — Authentication\.
- `K_DEF` — Authenticated defensive\-state transitions\.
- `K_DOC` — Protected document opening\.
- `K_REC` — Content recovery\.

These domains represent separate cryptographic authorities\. Possession of material associated with one domain does not automatically grant the capabilities of another\.

**Ed25519 — Digital Signature Verification**

The PRIV and KIT artifacts include externally signed canonical manifests\.

Their Ed25519 signatures are independently verifiable using the supplied public key, `rol_PUB.pub`\.

The signed manifests bind cryptographic commitments to the corresponding protected blobs\.

**SHA\-256 — Structural Integrity**

The protection scheme uses SHA\-256 commitments for the artifact nucleus &#40;`nucleo`&#41; and its structural channels `S` and `Q`\.

These commitments allow independent comparison of the protected bytes against their signed manifest representations\.

**SPARTACO Neutral Seal**

The role packages additionally contain neutral\-seal information associated with their protected content, including fragment\-derived values and the `#VPSI-NEUTRO:n` marker\.

**SPARTACO\-Ω — Contractual Mathematical Perimeter**

SPARTACO’s broader authorization architecture includes mathematical invariants evaluated alongside authentication, integrity, resource binding, authorization, and lifecycle conditions\.

The contractual acceptance rule is expressed as:

# &#91; \\mathrm\{ACCESS\_GRANTED\}&#40;r&#41;

\\bigwedge\_\{c\\in\\mathcal\{C\}&#40;r&#41;\}c&#40;r&#41;
&#93;

An operation is authorized only when every predicate required by its contract is satisfied\.

The published challenge concerns the encrypted artifacts; the complete execution engine is not supplied\.

## 3\. Public Experimental Artifacts

The research corpus consists of four files:

|File                       |Function                                                                               |
|---------------------------|---------------------------------------------------------------------------------------|
|`rol_PRIV.png`             |PNG container holding sealed private signing material and an externally signed manifest|
|`rol_KIT.png`              |PNG container holding sealed keyset material and an externally signed manifest         |
|`SC_IMG_9115.jpeg.spartaco`|Standalone AES-256-GCM encrypted document envelope                                     |
|`rol_PUB.pub`              |Raw Ed25519 public key for independent signature verification                          |

The PNG role containers incorporate an `spRt` chunk containing their protected cryptographic package\.

The standalone `.spartaco` document follows the document\-encryption path and does not include the same outer Ed25519\-signed manifest\.

The supplied public key is sufficient for signature verification of the relevant signed packages\. It does not provide the secret material used to derive the document\-opening key\.

## 4\. The Cryptanalytic Problem

The challenge is to determine whether an independent researcher can recover the protected content from the released bytes\.

The adversary is granted access to the complete published artifact corpus, including the raw public key and all exposed headers, signatures, commitments, ciphertext, and metadata\.

The adversary is not supplied with:

- The SPARTACO execution engine\.
- The legitimate account IKM\.
- The decrypted keyset\.
- The authenticated session material\.
- The document\-opening key `K_DOC`\.

Researchers may apply mathematical cryptanalysis, independent cryptographic implementations, structural analysis, and computational experimentation to the published files\.

The investigation may address ciphertext confidentiality, key derivation, authenticated data binding, digital signatures, or possible interactions among the exposed cryptographic structures\.

The central experimental question is:

**Can the original protected plaintext be recovered using the published artifacts alone?**

## 5\. Evidence Required for a Successful Result

A successful confidentiality challenge result must demonstrate actual recovery of protected plaintext or protected cryptographic material from the released artifacts without the legitimate opening secrets\.

A successful integrity challenge result must demonstrate an unauthorized modification or substitution that remains accepted under the relevant original verification conditions\.

For scientific reproducibility, submissions should contain:

1. Identification of the original artifact and its SHA\-256 digest\.
2. A precise description of the cryptanalytic technique\.
3. Reproducible computational or mathematical evidence\.
4. The recovered plaintext or independently verifiable demonstration of the claimed result\.
5. A clear statement of the cryptographic boundary crossed\.

Metadata extraction, successful public signature verification, or observation of ciphertext structure is not, by itself, a successful confidentiality break\.

## 6\. Experimental Authorization

I, I\. Villasmil, creator of SPARTACO and owner of the challenge artifacts, expressly authorize researchers to download, copy, inspect, modify, analyze, and attempt to decrypt the published experimental files\.

These artifacts were created specifically for public cryptographic research\.

The authorization applies to the published experimental files, not to unrelated accounts, servers, systems, or infrastructure\.

There is no requirement to obtain my private credentials or access my personal environment\.

**The purpose is to confront the cryptographic construction with independent mathematical and experimental investigation\.**

## 7\. Public Research Repository

**SPARTACO — Cryptographic Challenge**

https://github\.com/ilvervillasmil\-ctrl/CHALLENGE\-SPARTACO/tree/main/encryption\_SPARTACO

This repository is an artifact\-distribution repository, not a source\-code release\.

Researchers are invited to examine the published bytes, formulate cryptanalytic methods, reproduce their results, and submit technically documented findings\.

---

**SPARTACO/VPSI v1 — Independent Cryptanalysis Challenge**

**The encrypted artifacts are public\. The cryptanalytic problem is defined\. The invitation is open to the international research community\.**

**I\. Villasmil**
Creator and Developer — SPARTACO
