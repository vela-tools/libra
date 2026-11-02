# Security policy

Libra is the policy enforcement point in front of an NGSI-LD context broker, so a flaw in it is a flaw in who can read and change your context data. This document explains how to report security vulnerabilities in Libra responsibly.

---

## Beta status

> [!WARNING]
> Libra is in beta and has not been independently audited. Do not put it in front of production data yet.

What this release does not defend, and the behaviours it accepts on purpose, are listed under [known limitations](https://vela-tools.github.io/libra/docs/security/known-limitations) in the documentation. Those are not vulnerabilities. A gap not listed there that lets a caller past a policy is one, and is reported as described below.

Known weaknesses that are not yet fixed are tracked as private advisories and published once fixed. Until then, the published notes describe only the class of a weakness (for example, resource exhaustion under hostile load, or an edge case of JSON-LD term resolution against a particular broker), never the steps to exploit it.

---

## Supported versions

Only the latest release receives security fixes during the beta.

---

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report privately through [GitHub private vulnerability reporting](https://github.com/vela-tools/libra/security/advisories/new), with:

- A description of the vulnerability
- Steps to reproduce, including the configuration, the policy and the request involved
- The version from `libra --version`
- The broker and broker version behind Libra, if the behaviour depends on it
- Any potential impact you have identified
- Optionally, a suggested fix

Leave out real keys, tokens and tenant data. A reproduction against the test broker in `tests/docker-compose.yaml` is ideal.

You should receive an acknowledgement within **2 working days** (Monday to Friday, EU CET/CEST hours).

After triage, we will:

1. Confirm the vulnerability and determine its severity.
2. Develop and test a fix.
3. Coordinate a release that includes the fix.
4. Publicly disclose the vulnerability after users have had reasonable time to update.

---

## Disclosure timeline

We aim for the following timeline, though complex issues may take longer:

| Phase | Target |
|---|---|
| Initial response | 2 working days |
| Triage and severity assessment | 5 working days |
| Fix development and testing | 30 days for high/critical |
| Public disclosure | Within 90 days, or after fix is widely deployed |

We will keep you informed at each stage.

---

## Scope

This security policy covers:

- Code and dependencies in this repository
- Build and release artefacts published from this repository
- Documentation that could mislead users into insecure configurations

In Libra, that includes in particular:

- A request allowed that no policy allows, or a policy matching a caller, tenant, entity type or attribute it does not name
- A response, notification or error body carrying data a restriction should have removed
- A caller's credential (an API key or a token) reaching the broker or a log
- Authentication accepting a token or key it should refuse
- A request that Libra and the broker read differently, so that what Libra checked is not what the broker acts on
- Resource exhaustion that a single unauthenticated or low-privilege caller can trigger

This policy does **not** cover:

- Vulnerabilities in the context broker itself, or in third-party software Libra depends on (please report those upstream)
- A broker reachable without going through Libra
- Issues with deployment infrastructure operated by individual users
- Social engineering, physical attacks, or denial-of-service against velacontext.com

---

## Recognition

We are happy to credit reporters in the release notes of the fix, unless you prefer to remain anonymous. Let us know your preference when you report.

We do not currently operate a paid bug bounty programme, but genuine security improvements are deeply appreciated and may be eligible for swag, public recognition, or commercial discounts on Vela Context Data Hub.

---

## Contact

- **Security reports:** [GitHub private vulnerability reporting](https://github.com/vela-tools/libra/security/advisories/new)
- **General contact:** info@senlab.io
- **Commercial:** [velacontext.com/contact](https://velacontext.com/contactus)
