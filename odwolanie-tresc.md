# Tresc odwolania (do pola "Reason for the appeal")

Uwaga (PL): formularz ma jedno pole tekstowe i opcjonalne PDF-y. Ponizej propozycja tekstu po angielsku.
Zalacznik: `cvp-appeal-evidence.pdf` (PDF z README tego repo). Przed wyslaniem uzupelnij/usun
fragmenty w nawiasach kwadratowych.

---

I am asking for a second look at my application (version 7, denied on 2026-10-29), because the
evidence I submitted did not represent my work and I chose the wrong qualifying basis.

What went wrong in the application:

1. I selected "an accepted vulnerability disclosure or advisory published under your name". I do not
   have a CVE, a bug bounty record or a published advisory. My security work is on proprietary
   software I build and operate myself for the dental laboratory where I work, so there is no
   third-party vendor to disclose to.
2. The link I gave (github.com/mbuas/dental-lab-security) is a written description of my role with no
   verifiable material. That repository and my main account github.com/mbuasm both belong to me.

What I am submitting now:

A public repository, github.com/mbuasm/cvp-odwolanie (attached as PDF), that documents my defensive
security work using only the commit history of four repositories I own, with a commit SHA, date and
summary for every claim. In short:

- Two formal internal security reviews with numbered findings (R-01..R-13, P6), each followed by
  failing tests, fixes and regression tests. Vulnerability classes found and fixed in my own code
  include privilege escalation through an elevated scheduled task with a user-writable directory,
  secret exposure in a plaintext UI field, a private key leaking into a diagnostics archive, weak RSA
  parameters accepted from a network peer, CSV formula injection, replay in a UDP state protocol,
  and a named-pipe ACL mismatch across the UAC boundary.
- A hand-written RFB/VNC client including the RealVNC RSA-AES handshake with key pinning and negative
  tests, used against real industrial machines.
- An own secret and PII scanner with honest exit codes (an incomplete scan is never reported clean),
  run from a trusted host copy rather than the PR checkout; gitleaks and Semgrep gates pinned by
  SHA-256 that a pull request cannot weaken; weekly Trivy CVE scans of production images with the
  findings acted on; Authenticode-signed releases and checksum-verified updates.
- A workstation program for the dental lab that processes patient data (3D scans of restorations
  matched to design STL files, chip detection, assignment to patient orders) built from the first
  commit with data minimisation, no network egress, synthetic-only test data and an audit log.

This is exactly the activity the decision letter lists: secure code review, threat modeling,
patching, finding vulnerabilities in my own source code. I am applying as an individual for Defense
Access only, for use on systems I own and operate.

The four source repositories are private because they contain a company's production systems. I will
grant read access to a reviewer account on request, or provide `git log --stat` exports for every
commit cited.

[Opcjonalnie: jedno zdanie, po co Ci CVP - np. "I need the adjusted controls for ... when working on
my own RFB client, ACL/UAC audits and analysis of diagnostic dumps."]

---

## Co jeszcze poprawic przy ponownym wniosku (od 5.11.2026)

- Podstawa kwalifikacji: nie "accepted vulnerability disclosure/advisory". Sprawdz pozostale opcje w
  "Track record (at least one)" i wybierz te, ktora pasuje do pracy na wlasnych systemach.
- Opis pracy: w wersji 7 jest zdanie o "find ways to replicate them or withdraw patient data" -
  brzmi dwuznacznie. Lepiej: "I review and test the software I build for the lab for weaknesses that
  could expose patient data, and fix them".
- Link dowodowy: github.com/mbuasm/cvp-odwolanie (publiczne, z SHA), nie opisowe README.
- Jedno konto: wniosek z konta Anthropic powiazanego z Google (wymog 3a Exhibit A) i spojna nazwa
  GitHub (mbuasm) w dowodach.
