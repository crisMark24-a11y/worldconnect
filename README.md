# WorldConnect — online-ready starter

## Stack
- Node.js + Express
- PostgreSQL
- JWT authentication
- bcrypt password hashing
- Responsive web frontend

## Local setup
1. Install Node.js 20+ and PostgreSQL.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL` and a long random `JWT_SECRET`.
4. Run `npm install`
5. Run `npm start`
6. Open `http://localhost:3000`

## Deployment
Use a Node-compatible host plus managed PostgreSQL. Set `DATABASE_URL`, `JWT_SECRET`, `NODE_ENV=production`, and `CORS_ORIGIN` in the host's environment variables. Start command: `npm start`.

## Current API
GET `/api/health`
POST `/api/auth/register`
POST `/api/auth/login`
GET `/api/me`
GET `/api/posts`
POST `/api/posts`
POST `/api/posts/:id/like`
POST `/api/posts/:id/comment`
POST `/api/users/:id/follow`

This is a starter, not a finished production Facebook-scale service. Before public launch, add email verification, password reset, rate limiting, moderation/reporting, secure upload storage, CSRF/CORS hardening, validation, logging, backups, privacy/legal pages, and abuse protection.
