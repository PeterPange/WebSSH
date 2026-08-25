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

The initial administrator credentials are `admin` / `changeme`. They are intended only for local evaluation. Before deploying anywhere accessible to others, set a strong password in `.env`. The administrator is created only on the first initialization of an empty data directory; later environment-variable changes do not modify an existing account.

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
- Set a strong administrator password before first start; the default account is only for compatibility when environment variables are omitted.
- Use HTTPS and a reverse proxy for public access; do not expose the service directly to the Internet.
