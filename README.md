# Panel Pro on Railway

Runs the unchanged `worker-pro.js` on Node 22.13+ with SQLite. No npm dependencies.

## Files
- `worker-pro.js`  the panel (replace it with a newer version any time)
- `server.js`      HTTP + WebSocket server that loads worker-pro.js
- `runtime.mjs`    replacements for D1, cloudflare:sockets and WebSocketPair
- `bot.mjs`        Telegram management bot (optional)
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
- `BOT_TOKEN`      token from @BotFather; enables the Telegram bot
- `ADMIN_IDS`      comma-separated numeric Telegram IDs allowed to use the bot
- `PANEL_URL`      public panel URL used in links, e.g. https://xxx.up.railway.app (defaults to RAILWAY_PUBLIC_DOMAIN)
- `ALLOW_PRIVATE`  `1` lets users reach private/loopback addresses. Off by default; keep it off.

## Notes
- Subscription links use the domain you open the panel on.
- Connections to private, loopback and link-local addresses are blocked, so users cannot reach Railway's internal network.

## Telegram bot
1. In Telegram open @BotFather, send /newbot and copy the token.
2. In Railway add variable `BOT_TOKEN`. Redeploy.
3. Send /start to your bot. It replies with your numeric Telegram ID.
4. Add that number as variable `ADMIN_IDS` (several IDs separated by commas). Redeploy.
5. Commands: /users /add /info /link /toggle /reset /newuuid /del /stats

Only IDs listed in `ADMIN_IDS` can use the bot; everyone else is ignored.
