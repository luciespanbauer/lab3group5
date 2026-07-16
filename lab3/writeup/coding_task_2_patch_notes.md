# Coding Task 2 Patch Notes

## Scope and original data flow

This patch addresses only Coding Task 2 authentication and network-protocol
issues. The preserved originals under `lab3/copy/`, `database.db`, the Coding
Task 1 SQL-injection/password-decryption work, and `writeup/Risk Table
Justifications.txt` were intentionally left unchanged.

Before the patch, the vulnerable path was:

```text
User or Flask app
-> SampleNetworkClient
-> UDP network
-> SmartNetworkThermometer server
-> authentication response and token
-> protected commands and temperature responses
```

The Flask login obtained an activation credential from the database and passed
it to `SampleNetworkClient`. The client constructed plaintext `AUTH` and
semicolon-delimited token/command datagrams. `SmartNetworkThermometer` split
those strings, compared a source-code password literal, appended a raw token to
a list, and sent raw tokens, errors, and temperatures back in plaintext.

## Vulnerability 1: hardcoded authentication password

### 1. Vulnerability description

The UDP authentication password was a literal embedded in active Python source.
Anyone who could read the repository, a source distribution, a stack trace, or
the client code had the server credential. Changing the password required a
coordinated code edit and deployment.

### 2. Original affected files and behavior

- `SampleNetworkServer.py` compared the supplied password with a literal.
- `SampleNetworkClient.py` repeated the same literal in both temperature update
  callbacks.
- `test.py` embedded and printed authentication material.
- `app.py` obtained an activation credential from the database and passed it to
  the network client instead of using explicit runtime security configuration.

### 3. Security impact

Source access disclosed a reusable credential that authorized monitoring and
unit-changing commands. A leaked credential could not be revoked without
changing code, and copies of the repository retained it indefinitely.

### 4. Security requirements violated

The design violated secret-separation, secure configuration, least exposure,
and fail-closed configuration requirements. Password comparison was also not
performed with a constant-time primitive.

### 5. Complete systemic fix

`secure_transport.load_auth_password()` is the single configuration loader for
`INCUBATOR_AUTH_PASSWORD`. It has no default and raises a clear
`ConfigurationError` when the value is missing or empty. The server loads it
before creating a UDP socket and compares authentication values with
`hmac.compare_digest`. Client APIs accept the password explicitly from their
caller. Flask loads the configured password at startup and supplies it to the
client; it does not obtain the UDP server password from a template, hidden form
field, example, or helper fallback. The manual smoke test also loads it from the
environment and never prints it.

Moving the password to runtime environment configuration fixes source-code
hardcoding, but it does **not** secure network transport. The separate AES-GCM
transport fix below is required to protect that password in transit.

### 6. Files changed

`secure_transport.py`, `SampleNetworkServer.py`, `SampleNetworkClient.py`,
`app.py`, `test.py`, `.env.example`, `README.md`, and the automated tests.

### 7. Configuration changes

`INCUBATOR_AUTH_PASSWORD` is mandatory. `.env.example` contains only an obvious
placeholder. `.gitignore` excludes `.env`, `.env.*` except `.env.example`, and
common local secret files.

### 8. Enforcement mechanism

Server and Flask initialization fail before network use if security
configuration is absent. There is no plaintext or hardcoded fallback. The
server's password is never logged or returned in a remote error.

### 9. Tests performed

Automated tests cover missing/empty configuration behavior, correct and
incorrect passwords, removal of the original literal from active sources, and
live encrypted authentication. Exact commands and results are recorded in
`coding_task_2_test_results.md`.

### 10. Remaining limitations and assumptions

Environment variables are process-readable to appropriately privileged local
users. Production deployments should inject them through an operating-system or
platform secret manager and rotate them if exposed. Rotation requires clients
and servers to receive the new values together.

## Vulnerability 2: unbounded authentication-token list

### 1. Vulnerability description

Every successful login appended a token to a list. Tokens never expired unless
the client explicitly logged out, so repeated authentication caused continuous
memory growth. The tokens were also generated with `random.choice`, stored raw,
and accepted from any client address.

### 2. Original affected files and behavior

`SampleNetworkServer.py` owned `self.tokens = []`, created 16-character tokens
from the non-cryptographic `random` module, performed membership checks against
the raw list, and removed an entry only on a successful plaintext logout.

### 3. Security impact

An attacker could consume memory by repeatedly authenticating, predictability
was weaker than a cryptographic token generator, raw tokens were exposed in
memory/diagnostics, stolen tokens were reusable from other endpoints, and stale
sessions remained authorized indefinitely.

### 4. Security requirements violated

The implementation violated bounded-resource, cryptographic-randomness, session
expiration, secure token storage, revocation, and endpoint-binding principles.
`random.choice` is intended for simulation/general randomness and is
inappropriate for security tokens.

### 5. Complete systemic fix

Each `SmartNetworkThermometer` now uses an `OrderedDict` of `SessionRecord`
objects keyed by SHA-256 token digest. Tokens come from
`secrets.token_urlsafe(32)`, providing 256 bits of input entropy. Records contain
creation time, last-used time, and the client's IP/UDP-port tuple. The raw token
is returned only inside the encrypted authentication response and is never
stored server-side.

The production defaults are a 15-minute inactivity TTL and 100 active sessions
per thermometer. Both are constructor-configurable for tests. Cleanup runs
before issuing a token, at request processing, during validation, and on logout.
Successful protected use refreshes `last_used_at` and moves the record to the
most-recently-used end. At capacity, expired entries are removed first and then
the least recently used live session is evicted. Logout validates and deletes
the session. Tokens used from a different source address are rejected.

Hashing tokens reduces exposure if server memory or diagnostics are inspected:
the server cannot directly recover bearer tokens from its session map. Digest
comparison uses `hmac.compare_digest` after lookup.

### 6. Files changed

`SampleNetworkServer.py`, `SampleNetworkClient.py`, `app.py`, `test.py`, the
templates, automated tests, and documentation.

### 7. Configuration changes

No new production environment variable is required for session limits. The
secure defaults are `DEFAULT_SESSION_TTL = 900` and
`DEFAULT_MAX_SESSIONS = 100`. Tests can pass shorter/smaller values to the
constructor without weakening production defaults.

### 8. Enforcement mechanism

All protected commands and logout go through one session validator. The session
map is lock-protected, ordered by use, cleaned centrally, and capped on every
issuance. A separate replay request-ID cache is also expiring and explicitly
bounded to 1,024 entries by default. It rejects new validated requests while
full rather than evicting still-live replay evidence; no unbounded replacement
cache was added.

### 9. Tests performed

Tests verify token entropy/format, digest-only storage, expiration, denial after
expiration, last-used refresh, logout invalidation, address binding, the hard
maximum under repeated successful/failed authentication, LRU eviction, and the
bounded replay cache.

### 10. Remaining limitations and assumptions

Session state is in process memory, so a server restart logs every client out.
Multiple independent server processes do not share sessions. Address binding
includes the UDP source port, which is why the updated client retains one socket
for its session. NAT rebinding or a client process restart requires a new login.

## Vulnerability 3: plaintext credentials, tokens, commands, and responses

### 1. Vulnerability description

The UDP protocol exposed credentials and bearer tokens to passive observers and
allowed active attackers to read, alter, concatenate, or inject commands and
responses. Delimiters were ambiguous and carried no integrity protection.

### 2. Original affected files and behavior

- `SampleNetworkClient.py` sent plaintext authentication and
  `token;COMMAND` datagrams, received plaintext tokens/temperatures, used sockets
  without timeouts, and did not reliably close them.
- `SampleNetworkServer.py` decoded UDP bytes as text, split on spaces and
  semicolons, processed multiple delimiter-separated commands, and returned
  plaintext success/error data.
- `app.py` passed tokens through hidden form fields and rendered them visibly.
- `templates/authenticate.html` deliberately displayed the raw token.

### 3. Security impact

A network observer could steal the password or a session and impersonate a
client. An active attacker could tamper with temperature responses or control
commands. Semicolon concatenation allowed more than one operation to be encoded
where one command was expected.

### 4. Security requirements violated

The protocol lacked confidentiality, integrity, authenticated framing, strict
parsing, replay resistance, input allowlisting, and safe network resource
handling.

### 5. Complete systemic fix

`secure_transport.py` defines a version-1 AES-256-GCM envelope with exactly four
wire fields: `version`, `nonce`, `ciphertext`, and `tag`. Before encryption,
requests and responses are strict JSON objects containing an authenticated inner
protocol version, type, random request ID, and timestamp. Every encryption uses
a new 12-byte nonce from PyCryptodome's operating-system random source. The GCM
tag authenticates both ciphertext and the version-specific associated data.

`INCUBATOR_TRANSPORT_KEY` must be valid Base64 that decodes to exactly 32 bytes.
Base64 only encodes the binary envelope for UDP; Base64 is not encryption.
AES-GCM provides both confidentiality and integrity. Malformed JSON/Base64,
unknown or changed versions, wrong nonce/tag lengths, truncation, changed
ciphertext/tag, and authentication failures are rejected before dispatch.
Plaintext compatibility is intentionally absent.

The server accepts one of three exact request schemas (`AUTH`, `COMMAND`, or
`LOGOUT`) and one command from the explicit allowlist: `GET_TEMP`, `SET_DEGC`,
`SET_DEGF`, `SET_DEGK`, or `UPDATE_TEMP`. `run()` only receives a datagram and
passes it to `handle_datagram`; `processCommands()` owns the one validation,
replay, authentication, authorization, and dispatch path. Semicolon parsing no
longer exists. Every normal response, authentication failure, validation error,
token, and temperature is encrypted. Remote errors are generic and never
contain passwords, tokens, keys, decrypted payloads, or exception details.

Requests must be within a 60-second clock window and request IDs are rejected on
replay. The expiring replay structure is bounded. The client matches encrypted
responses to request IDs, checks the server endpoint, uses a two-second default
socket timeout, serializes access with a lock, and supports deterministic close
and context-manager use.

Both client and server required coordinated changes; updating only one side
would either leave data exposed or make the protocol unusable. `app.py` and the
other callers were also updated. Flask keeps the UDP token only inside an
AES-GCM-encrypted envelope in its signed session cookie; the token is no longer
rendered or placed in forms. Browser logout sends an encrypted UDP logout and
clears the cookie.

### 6. Files changed

`secure_transport.py`, `SampleNetworkClient.py`, `SampleNetworkServer.py`,
`app.py`, `test.py`, `templates/authenticate.html`, `templates/login.html`, the
tests, `.env.example`, `.gitignore`, and documentation.

### 7. Configuration changes

`INCUBATOR_TRANSPORT_KEY` is mandatory. The README includes the required secure
generation command. `INCUBATOR_COOKIE_SECURE=1` is an optional deployment flag
for HTTPS-hosted Flask sessions.

### 8. Enforcement mechanism

Authenticated decryption occurs before schema or command processing. The
transport helper has strict envelope fields and size/length checks. The command
dispatcher has exact field sets and an allowlist. There is no insecure plaintext
fallback. Importing the server no longer imports Matplotlib/`infinc`, binds
ports, opens GUI windows, or starts threads; startup lives in `main()` behind the
standard `if __name__ == "__main__"` guard.

### 9. Tests performed

The suite exercises live encrypted authentication and temperature retrieval,
plaintext rejection, ciphertext/tag tampering, malformed/random/truncated
datagrams, unsupported versions, malformed Base64, fresh nonces, encrypted error
responses, all unit commands, update, missing/incorrect tokens, semicolon and
unknown-command rejection, continued service after invalid input, client close,
and side-effect-free server import.

### 10. Remaining limitations and assumptions

- UDP remains an unreliable datagram transport; the client times out rather
  than retrying automatically because replay-safe retries need additional
  response-caching semantics.
- The symmetric transport key is shared by configured clients and servers; a
  future design could use mutually authenticated TLS/DTLS or per-device keys.
- Client/server clocks must stay within the request window.
- The Flask development server is restricted to loopback in the documented
  workflow. Non-loopback web access still requires production HTTPS; AES-GCM
  secures the application UDP leg, not arbitrary browser HTTP.
- The Coding Task 1 database encryption and SQL-injection exercise remain as
  assignment scope. They were not silently changed by this patch.

## Preserved materials

Nothing under `lab3/copy/` was edited. The manifest's MD5 values describe LF
line endings; on Windows Git checks the files out with CRLF, so raw-byte MD5
values differ while LF-normalized content matches all five manifest entries.
Git object comparison confirms the preserved files are unchanged from `HEAD`.
`writeup/Risk Table Justifications.txt` is also unchanged intentionally.
