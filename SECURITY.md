# Security review and hardening — 2026-10-01

This is a source-code review plus local integration/browser testing, not a
penetration test of the nine managed machines or a guarantee against intrusion.
No exploit attempts or port scans were performed against managed machines.

## Fixed findings

| Finding | Previous impact | Protection |
|---|---|---|
| Local SSH key/config APIs accessible to ordinary accounts | A web user could use the service owner's SSH identity on another host | Administrator-only listing, config and keyRef use, including saved credentials; key paths cannot resolve outside `.ssh` |
| Arbitrary destination for ordinary users | Logged-in users could use the app as an internal SSH connection relay | Ordinary accounts restricted to registered host/port pairs; admins retain destination management |
| No host-key verification | Credentials/terminal sessions could be sent to an impersonated SSH server | SHA-256 host-key pinning on first use, persistent in SQLite; subsequent changes rejected |
| Unsafe cookie parsing on WebSocket handshake | Malformed percent escapes could throw outside Express | Nonthrowing parser, null-prototype cookie map, authentication before upgrade |
| Missing cross-origin browser boundary | Cross-site requests/terminal handshakes insufficiently checked | Exact origin checks for configured origins; same host AND scheme by default; Fetch Metadata rejection; JSON write content type |
| Login rate limit keyed only by username+IP | Cycling usernames bypassed throttling; synchronous password checks blocked event loop | Bounded IP/account/global limiters, asynchronous scrypt and concurrency ceiling; 12-character minimum for new passwords |
| Auth cleanup removed login tokens without closing SSH | Remote shells could outlive login expiry | Token-bound SSH cleanup every 15 seconds, immediate expiry checks on terminal input; role change invalidates sessions |
| Unbounded sessions, messages and output | Resource exhaustion, huge pending input/output queues | Session/terminal/command/file limits; bounded WebSocket messages/input/backlog, uploads and command output; HTTP header/time limits |
| Cleartext credential records | A copied database disclosed passwords/private keys | AES-256-GCM, random private key file, transactional migration, secure-delete, 0700 data directory and 0600 secret files |
| Common initial password and automatic admin re-promotion | Predictable fresh-install admin; removed privileges restored on restart | Random private initial password when unset; new configured password must be 12–128 characters; no automatic re-promotion |
| Shared default SSH credentials | Automatically attempted predictable SSH password for each account | No automatic default unless explicitly configured; existing user credentials preserved |
| Third-party runtime scripts and missing browser headers | External script dependency, framing/content-sniffing exposure | Pinned locally served xterm assets, CSP without unsafe-eval/inline scripts, frame denial, nosniff, no-referrer, API no-store |
| Sudo password embedded in shell command | Password could appear in remote command/process listings | Pass sudo password over SSH stdin, never in command arguments |
| GPU process PID interpolated into shell command | Unexpected remote tool output could alter the enrichment command | Numeric-only PID allowlist |
| Terminal close-before-shell-ready race | Shell could be allocated after its browser socket closed | Immediately close late SSH channels |
| Dependency audit: express/body-parser/qs | Known transitive denial-of-service advisories | Lockfile patched with compatible updates; verify using `npm audit` |

## Deployment and operational limits

- The live deployment currently uses plain HTTP on port 9998. These code fixes
  do not encrypt browser traffic. Before exposure outside a trusted network,
  deploy a trusted HTTPS certificate/reverse proxy or use an authenticated VPN.
  Preserve Host and WebSocket upgrade headers, configure exact allowed origins,
  set secure cookies, and restrict direct access to Node. No firewall or SSH
  daemon settings were changed by this review.
- A legacy `admin` account using the known initial password was detected. A
  replacement was prepared privately; password rotation requires the owner's
  confirmation and is separate from the code migration. Other account passwords
  were not reset. Confirm the final rollout status before relying on this item.
- First-use host-key pinning is TOFU, not independent identity verification.
  First connection must use a trusted network. For a genuine reinstall, verify
  the changed host key independently before replacing its recorded fingerprint.
- Encryption protects a database-only leak. Anyone controlling this OS account
  or reading both SQLite and `credentials.key` can decrypt credentials. Use a
  dedicated least-privilege OS service account; the current service still runs
  as the existing owner account to preserve its key/import configuration.
- Back up SQLite and `credentials.key` together. Protected pre-upgrade backups
  still contain plaintext credentials; retain only as long as needed and never
  publish them. Cryptographic erasure of old filesystem snapshots is not claimed.
- The terminal intentionally allows commands permitted by the remote SSH user.
  The file manager's home restriction is a UI restriction, not a secure remote
  sandbox: shell access and SFTP path races cannot replace OS-level restrictions.
- Audit colours are heuristic live snapshots. They do not block attacking IPs,
  retain remote audit history, replace sshd policy, or prove that a host is safe.
- Login throttles are process-local and reset on restart. A large distributed
  attack still needs upstream rate limiting/network controls. No MFA was added.
- Vendored frontend assets are pinned separately from npm dependencies and need
  separate updates. An npm audit with zero findings does not cover application
  logic, the OS, or these static assets.

## Verification

`npm test` checks security helpers and monitoring; `node test/test_security_e2e.js`
starts an isolated app and disposable SSH server and tests actual HTTP/WebSocket
boundaries, migration, host-key mismatch and throttling. The existing 70-check
mock-SSH end-to-end suite and browser terminal/file-manager flows are also run.
All automated attack simulations use temporary local services and databases.

Implementation references:
[Express production security](https://expressjs.com/en/advanced/best-practice-security/)
and [ws server options / upgrade authentication](https://github.com/websockets/ws/blob/master/doc/ws.md).

## Rollout result

- Live systemd service restarted successfully with `NoNewPrivileges=yes`,
  `UMask=0077`, `MemoryMax=1G`, `TasksMax=128`, and `LimitNOFILE=4096`.
- A consistent private pre-upgrade SQLite backup was created under
  `data/backups/pre-security-2026-10-01T13-52-35-327Z.db` (directory 0700,
  file 0600). It contains the old plaintext records and must remain private.
- All 16 users and 9 servers were retained. All 144 credential records were
  encrypted and individually compared with the backup after decryption:
  identical contents. `credentials.key` permissions verified as 0600.
- Passed: 20 unit checks, 25 isolated security integration checks, 70 existing
  SSH/file/terminal end-to-end checks, and browser multi-terminal flows under
  the deployed CSP. `npm audit --omit=dev` reported zero known vulnerabilities.
- Legacy admin password rotation is still awaiting the owner's confirmation;
  the prepared password file does not mean the account has been changed.
