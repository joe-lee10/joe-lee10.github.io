# SAML 2.0 SSO — Interactive Flow Diagram & Security Checklist

A technical walkthrough of the SAML 2.0 SP-initiated Single Sign-On flow — built to demonstrate both the authentication mechanics and the security controls required at each step. Includes an interactive step-by-step diagram and a 28-point security configuration checklist.

---

## What's included

### `sso_diagram.html` — Interactive flow diagram

A self-contained HTML page that walks through the full SAML 2.0 SP-initiated SSO flow in 10 annotated steps:

| Step | Description |
|------|-------------|
| 1 | User attempts to access protected SP resource |
| 2 | SP checks for session — none found |
| 3 | SP generates signed AuthnRequest (XML) |
| 4 | SP redirects browser to IdP SSO URL (302) |
| 5 | Browser forwards AuthnRequest to IdP |
| 6 | IdP presents login form + MFA challenge |
| 7 | User authenticates; IdP validates and signs Assertion |
| 8 | IdP returns SAMLResponse via HTML auto-submit form |
| 9 | Browser POSTs SAMLResponse to SP's ACS URL |
| 10 | SP validates Assertion, creates session, grants access |

Each step includes:
- **Technical detail** — HTTP method, endpoint, XML structure
- **Security note** — what can go wrong and what must be validated

Controls: Next / Previous / Play (auto-advance) / Reset, keyboard arrows (← →), spacebar to play/pause.

### `sso_security_checklist.csv` — 28-point security configuration checklist

Covers SP configuration, IdP configuration, network/transport, audit/monitoring, and governance. Each item includes pass/fail/partial status and remediation notes — structured for use in a SAML SSO security review.

---

## The SAML 2.0 actors

```
Browser (User)        Service Provider (SP)        Identity Provider (IdP)
      │                       │                              │
      │  1. GET /resource      │                              │
      │──────────────────────►│                              │
      │  4. 302 → IdP SSO URL  │                              │
      │◄──────────────────────│                              │
      │  5. GET /sso?SAMLRequest=...                          │
      │──────────────────────────────────────────────────────►│
      │  6. 200 Login Form                                    │
      │◄──────────────────────────────────────────────────────│
      │  7. POST credentials + MFA                            │
      │──────────────────────────────────────────────────────►│
      │  8. HTML form (SAMLResponse)                          │
      │◄──────────────────────────────────────────────────────│
      │  9. POST /acs (SAMLResponse)                          │
      │──────────────────────►│                              │
      │  10. 302 /resource (session set)                      │
      │◄──────────────────────│                              │
```

---

## Key security validations (SP side)

The SP must validate all of the following on receipt of the SAMLResponse or the authentication is not secure:

1. **IdP signature** — validate against IdP's registered public certificate
2. **NotBefore / NotOnOrAfter** — reject Assertions outside the validity window
3. **AudienceRestriction** — must match the SP's EntityID exactly
4. **InResponseTo** — must match the ID of the original AuthnRequest
5. **ACS URL** — destination must match the SP's registered ACS URL
6. **Duplicate Assertion ID** — cache processed IDs to prevent replay within validity window

Skipping any one of these creates an exploitable vulnerability.

---

## Common SAML vulnerabilities

| Vulnerability | Description | Mitigation |
|---------------|-------------|------------|
| XML Signature Wrapping (XSW) | Attacker injects unsigned XML elements that some parsers evaluate instead of the signed content | Use a hardened SAML library with XSW protection |
| Assertion Replay | Attacker captures and re-submits a valid Assertion within its validity window | Maintain Assertion ID cache; enforce tight validity windows |
| Open Redirect via RelayState | Attacker crafts a RelayState pointing to an external URL | Validate RelayState against allowlist of internal URLs |
| IdP-initiated SSO CSRF | Attacker initiates an IdP-initiated SSO flow, bypassing InResponseTo check | Disable IdP-initiated SSO or implement CSRF tokens |
| Weak signing algorithm | SHA-1 signatures can be forged | Enforce RSA-SHA256 minimum; reject weaker algorithms |

---

## Checklist findings summary (mock)

| Status | Count |
|--------|-------|
| Pass | 18 |
| Partial | 7 |
| Fail | 3 |

**Critical failures:** RelayState open redirect not validated (SSO-009), IdP-initiated SSO enabled (SSO-014), no annual SSO configuration review (SSO-027).

---

## References

- [OASIS SAML 2.0 Core Specification](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [NIST SP 800-63C — Federation and Assertions](https://pages.nist.gov/800-63-3/sp800-63c.html)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [Okta SAML 2.0 Technical Overview](https://developer.okta.com/docs/concepts/saml/)

---

## Author

**Joseph Lee** — GRC & Privacy Program Manager  
CIPP/US · CIPP/E · AWS Cloud Practitioner · OneTrust Certified  
[LinkedIn](https://linkedin.com/in/[your-handle]) · [Portfolio](https://joe-lee10.github.io)
