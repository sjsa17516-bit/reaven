# Panel Pro on Railway

Runs the unchanged `worker-pro.js` on Node 22.13+ with SQLite. No npm dependencies.

## Files
- `worker-pro.js`  the panel (replace it with a newer version any time)
- `server.js`      HTTP + WebSocket server that loads worker-pro.js
- `runtime.mjs`    replacements for D1, cloudflare:sockets and WebSocketPair
- `Dockerfile`, `package.json`

## Deploy
1. Put this folder in a GitHub repo.
2. Railway: New Project -> Deploy from GitHub repo (the Dockerfile is picked up automatically).
3. Service -> Volumes -> add a volume mounted at `/data`. Without it the database is wiped on every deploy.
4. Service -> Settings -> Networking -> Generate Domain (or add your own domain).
5. Open the domain, set the panel password, create users, copy the subscription link.

## Variables (optional)
- `DB_PATH`        default `/data/panel.db`
- `PORT`           set by Railway
- `ALLOW_PRIVATE`  `1` lets users reach private/loopback addresses. Off by default; keep it off.

## Notes
- Subscription links use the domain you open the panel on.
- Connections to private, loopback and link-local addresses are blocked, so users cannot reach Railway's internal network.
