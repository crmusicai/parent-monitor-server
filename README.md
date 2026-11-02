# Parent Monitor — Server

Backend for the Parent Monitor apps: parent accounts (multi-user, fully isolated),
pairing codes, child device registry, presence, live-listen WebRTC signalling,
location + tamper-event relay.

## Run locally
```
npm install
PORT=8080 npm start
```
Health check: `GET /health`

## Deploy free (Render, from this repo)
1. Push this folder as a GitHub repo.
2. In Render: New -> Web Service -> connect the repo (render.yaml is read automatically;
   the service name must stay `parent-monitor-server` so the apps' baked address
   `https://parent-monitor-server.onrender.com` matches).
3. Create — free plan sleeps after ~15 min idle, wakes in under a minute; apps auto-reconnect.

Note: account data lives in a local file (data.json) on the service; on the free plan it
resets if the service is redeployed. Attach a Render persistent disk and set DATA_FILE
to its path for durable storage.
