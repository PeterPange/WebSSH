# Web SSH Manager

Web service with sign-in, SSH terminal access, GPU/system monitoring, and file management.

## Deployment

Node.js 18 or later is required. Run the following in the project directory:

```bash
cp .env.example .env
# Edit .env and set WEBSSH_ADMIN_PASSWORD at minimum.
npm ci --omit=dev
./start.sh
```

Open `http://SERVER_IP:9998` in a browser. The first start creates the SQLite database and administrator account in `WEBSSH_DATA_DIR`.

The first administrator is `admin` (override with `WEBSSH_ADMIN_USERNAME`).
Set `WEBSSH_ADMIN_PASSWORD` to a strong password before first initialization.
If it is omitted, a random password is generated and saved with mode 0600 in
`WEBSSH_DATA_DIR/initial-admin-password`; it is never printed in logs. Existing
accounts and passwords are not changed by environment-variable changes.

SSH credentials are no longer seeded with a shared default password. Each user
configures their own connection information. Existing saved credentials are
preserved. The optional `WEBSSH_DEFAULT_SSH_PASSWORD` enables legacy seeding
explicitly and should normally remain unset.

### Docker deployment

If Docker and Docker Compose are available, run:

```bash
cp .env.example .env
# Edit .env and set WEBSSH_ADMIN_PASSWORD at minimum.
docker compose up -d --build
```

Docker provides the Node.js runtime. Application data is stored in the local `data/` directory.

## Persistent operation

Use systemd, pm2, or a container runtime to manage the process. For systemd, set the working directory to the project directory and use:

```text
/path/to/web-ssh-manager/start.sh
```

Set the same environment variables in the service configuration as in `.env`. When deployed behind an HTTPS reverse proxy, set `WEBSSH_SECURE_COOKIE=1`.

## Security notes

- The deployment package does not include the source machine's `data/` database, saved SSH connections, or credentials.
- Use unique strong passwords; existing deployments must rotate legacy default passwords separately.
- Use HTTPS and a reverse proxy for public access; do not expose the service directly to the Internet.

## File management and administrator monitoring

File management uses the SSH server's SFTP subsystem, including its initial
working directory and canonical paths. It does not require a shell, `readlink`,
or `rm`. Browsing and file operations remain restricted to that directory;
symlinks outside it are rejected. Text saves and empty-file creation wait for
remote close acknowledgement before reporting success.

As an administrator, connect to a machine and open **系统信息** to view:

- SSH TCP connections and source addresses for the configured SSH port;
- terminal login sessions and the platform users connected to that host/port;
- up to 200 failed login records from the last hour;
- the 30 processes with highest CPU usage, including owner, PID and memory usage.

The panel refreshes approximately every five seconds while open. Linux tools
`ss`, `who`, `ps`, and `lastb` are used with the current SSH account's permissions.
Unavailable tools and denied log access are shown explicitly. Failed-login
records generally require root or permission to read btmp. CPU percentages are
`ps` lifetime averages and may exceed 100% for multithreaded processes. This is
an inspection panel, not an automatic IP blocking service. With port forwarding,
the configured connection port may differ from the remote SSH listening port.

## Regression checks

```bash
npm test
node test/test_security_e2e.js
# In separate terminals, using a Python environment with paramiko installed:
python test/test_ssh_server.py
WEBSSH_ADMIN_PASSWORD=test-admin-12345 WEBSSH_DATA_DIR=$(mktemp -d) PORT=8080 node server.js
node test/test_e2e.js
```

Use a temporary data directory for these checks, not a production database.

### Visual SSH audit (administrators)

Each server card displays a compact safety indicator in its header. Hover to
see the status and reason; click to open the source-IP table, failure-frequency bars,
 triggering reasons, and collection details in System info.

- Green: both connections and failed-login logs are available; no rule triggered.
- Yellow: one source has ≥5 failed logins/hour or ≥10 concurrent connections,
  or the server has ≥10 failed logins/hour overall.
- Red: one source has ≥20 failed logins/hour or ≥30 concurrent connections,
  or the server has ≥50 failed logins/hour overall.
- Grey: disconnected, awaiting collection, collection failed, data older than
  30 seconds, or incomplete/unparseable audit data. An observed warning/red
  alert takes precedence over incomplete data.

Failure counts are based on at most 200 recent btmp records; reaching the cap
means the displayed count is a lower bound. These fixed thresholds are heuristic
alerts, not confirmation of an intrusion. The audit is a live snapshot while
an administrator's page is open; it does not persist historical events or block
IPs. CPU usage is shown separately and does not determine the SSH audit colour.

If `lastb` cannot be read, failure-log collection tries existing passwordless
`sudo -n lastb` permission, then the system SSH journal, then passwordless
`sudo -n journalctl`. It never sends a sudo password or modifies remote
permissions. Journal collection examines at most 5000 recent sshd/sshd-session
records; reaching the cap marks coverage incomplete. An empty inaccessible
journal is not reported as zero failures. The audit shows each failed attempt
and evaluates TCP connections separately from failed-login log availability.

## Multiple terminals

In a server's Terminal tab, click **＋ 新建终端** to open an independent SSH
shell. Switch between the terminal labels; each keeps its output and running
shell while navigating between servers or other panels. Click **×** to close
only that shell. Finished shells retain their output until closed.
Disconnecting a server or signing out disposes all its terminals. Refreshing or
closing the browser does not preserve terminal sessions; use a remote session
manager such as tmux for work that must survive browser disconnections.
The number of simultaneous shells is subject to the remote SSH server's limits.

## Application security controls

See [SECURITY.md](SECURITY.md) for the review findings, rollout notes and limits.
Saved credentials migrate automatically to AES-256-GCM ciphertext on startup.
Back up `data/credentials.key` together with `data/servers.db`; loss of the key
makes saved credentials unreadable. Old plaintext backups remain sensitive.

Only administrators can list/use the application's local SSH keys and config.
Ordinary users can connect only to administrator-registered host/port pairs,
using their own credentials. SSH host keys are pinned on first use; a changed
key fails closed. First use must take place on a trusted network. After a
legitimate machine reinstall, verify the new fingerprint out of band before
an administrator removes that host/port's row from `ssh_host_keys` in SQLite.

Limits: 30 SSH connection attempts/minute/user; 32 SSH sessions/user and 256
in total; 12 terminals/session and 512 total; 64 KiB per WebSocket message;
1 MiB/s terminal input; 8 MiB command output; 8 concurrent file operations/user;
2 GiB per upload by default (`WEBSSH_UPLOAD_MAX_MB`). SSH login expiry closes
its remote connections within 15 seconds, and terminal input checks expiry
immediately. Successful and failed web logins are recorded in the service log
without passwords, keys, cookies or terminal content. Rate limits are in-memory
and reset on restart.

For an HTTPS reverse proxy, set `WEBSSH_SECURE_COOKIE=1`, configure
`WEBSSH_ALLOWED_ORIGINS=https://your-exact-hostname`, and preserve the Host
header and WebSocket upgrade. Set `WEBSSH_TRUST_PROXY` only to actual proxy
addresses/subnets; forwarded client IPs are otherwise ignored. Set
`WEBSSH_BIND_HOST=127.0.0.1` when only a local reverse proxy should access Node.
Never enable secure cookies on a plain HTTP-only deployment: logins would fail.
The checked-in `deploy/security.conf` is a systemd user-service hardening drop-in.

### File-manager interaction

Folder names open the folder. Recognized text files up to 1 MiB open in the
editor; other file names download the file. The type column and action hint
show what a click will do. Binary/large files do not offer online editing.
Failed navigation preserves the last directory and offers retry/home actions.
New names must be single file names, not paths. Edits made during an in-flight
save remain marked as unsaved.

With Playwright and Chromium installed separately, run the mocked browser
regression with `WEBSSH_TEST_BASE_URL=http://127.0.0.1:9998 node test/test_files_browser.js`.
Set `PLAYWRIGHT_CHROMIUM_PATH` if using an existing Chromium executable.
This test mocks all API requests; it does not modify remote machines.

### Administrator disk ownership view

Under **Manage → System info → 磁盘 (/)**, administrators can click
**查看各用户磁盘占用** to scan the
root filesystem and see allocated bytes per remote Linux UID, sorted by usage,
with bars showing the fraction of total root-filesystem capacity. This includes
system accounts and files outside home directories; independent mounts are
excluded. It is not a per-platform-user quota or a directory-size estimate.

The remote host requires Linux and Python 3. The collector uses the current SSH
account, trying existing noninteractive sudo access where available. It does not
change sudo policy or permissions. A non-root scan, unreadable entries, or a scan
limit produces an explicitly partial result; unseen usage must not be read as
zero. Hardlinks are deduplicated and symlinks are not followed. Filesystem
metadata, open deleted files, shared extents/snapshots and concurrent changes can
make ownership totals differ from `df`.

Scans run only when opened, at reduced CPU priority, with a 90-second/2-million
entry limit and bounded traversal/hardlink tracking. Results are cached for five
minutes per SSH session; concurrent requests share a scan, with at most two
scans platform-wide and one per host/port. No periodic full-disk scan is added.
Browser regression: with optional Playwright installed, run
`WEBSSH_TEST_BASE_URL=http://127.0.0.1:9998 node test/test_disk_browser.js`.
