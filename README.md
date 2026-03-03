# pico.chat Server

This backend powers the realtime chat and video room features for **pico.chat**.

## About

This is a **vibe-coded app**: built quickly with a strong focus on flow, aesthetics, and real-time collaboration.

## Tech Stack

- Node.js + Express
- Socket.IO (realtime events and signaling)
- MongoDB (users, rooms, messages)
- Redis (optional message cache)
- JWT + HttpOnly cookie auth

## Run Locally

From the project root (`antigravity-scroll`):

```bash
npm install
npm run server
```

Server default URL:

- `http://localhost:3001`

Health check:

- `GET /health`

## Environment Variables

Use the root `.env` file:

- `PORT=3001`
- `MONGODB_URI=...`
- `REDIS_URL=...` (optional)
- `JWT_SECRET=...`
- `JWT_EXPIRES_IN=7d`
- `AUTH_COOKIE_NAME=pico_auth`
- `COOKIE_SECURE=false` (set `true` in production over HTTPS)
- `CORS_ORIGIN=http://localhost:5173,http://127.0.0.1:5173`

## Notes

- For production, always set a strong `JWT_SECRET`.
- Keep `COOKIE_SECURE=true` in production.
- Set `CORS_ORIGIN` to your deployed frontend domain(s).
