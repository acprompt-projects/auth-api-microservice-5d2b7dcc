===
const request = require('supertest');
const app = require('../../src/app');
const { knex } = require('../../src/db/connection');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
const BASE = '/api/v1/auth';

let refreshCookie;

afterAll(async () => { await knex.destroy(); });

describe('Auth Integration Tests', () => {
  const userEmail = `test+${Date.now()}@example.com`;
  const userPass = 'Str0ng!Pass';

  // ─── Registration ───────────────────────────────────────────
  describe('POST /register', () => {
    it('201 — registers a new user', async () => {
      const res = await request(app).post(`${BASE}/register`).send({
        email: userEmail, password: userPass, name: 'Test User',
      });
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject({ user: { email: userEmail }, message: /verification/i });
    });

    it('409 — rejects duplicate email', async () => {
      const res = await request(app).post(`${BASE}/register`).send({
        email: userEmail, password: userPass, name: 'Dup',
      });
      expect(res.status).toBe(409);
      expect(res.body.error).toMatch(/exist/i);
    });

    it('400 — validates missing fields', async () => {
      const res = await request(app).post(`${BASE}/register`).send({ email: 'bad' });
      expect(res.status).toBe(400);
      expect(res.body.errors).toBeDefined();
    });

    it('400 — rejects weak password', async () => {
      const res = await request(app).post(`${BASE}/register`).send({
        email: `weak+${Date.now()}@x.com`, password: '123', name: 'Weak',
      });
      expect(res.status).toBe(400);
    });
  });

  // ─── Login ──────────────────────────────────────────────────
  describe('POST /login', () => {
    it('200 — logs in and returns tokens', async () => {
      // Seed verified user
      const hash = await bcrypt.hash(userPass, 10);
      await knex('users').where({ email: userEmail }).update({ password_hash: hash, email_verified: true });
      const res = await request(app).post(`${BASE}/login`).send({ email: userEmail, password: userPass });
      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
      const cookies = res.headers['set-cookie'];
      refreshCookie = cookies?.find(c => c.startsWith('refreshToken='));
      expect(refreshCookie).toBeDefined();
    });

    it('401 — wrong password', async () => {
      const res = await request(app).post(`${BASE}/login`).send({ email: userEmail, password: 'wrong' });
      expect(res.status).toBe(401);
    });

    it('401 — non-existent user', async () => {
      const res = await request(app).post(`${BASE}/login`).send({ email: 'no@no.com', password: 'whatever' });
      expect(res.status).toBe(401);
    });

    it('403 — unverified email', async () => {
      const unverified = `unv+${Date.now()}@x.com`;
      const hash = await bcrypt.hash(userPass, 10);
      await knex('users').insert({ email: unverified, password_hash: hash, name: 'Unverified', email_verified: false });
      const res = await request(app).post(`${BASE}/login`).send({ email: unverified, password: userPass });
      expect(res.status).toBe(403);
    });
  });

  // ─── Token Refresh ──────────────────────────────────────────
  describe('POST /refresh', () => {
    it('200 — refreshes access token', async () => {
      const res = await request(app).post(`${BASE}/refresh`).set('Cookie', refreshCookie);
      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
    });

    it('401 — missing refresh cookie', async () => {
      const res = await request(app).post(`${BASE}/refresh`);
      expect(res.status).toBe(401);
    });

    it('401 — invalid refresh token', async () => {
      const res = await request(app).post(`${BASE}/refresh`).set('Cookie', 'refreshToken=invalid');
      expect(res.status).toBe(401);
    });
  });

  // ─── Profile (protected) ────────────────────────────────────
  describe('GET /me', () => {
    let authToken;
    beforeAll(async () => {
      const res = await request(app).post(`${BASE}/login`).send({ email: userEmail, password: userPass });
      authToken = res.body.accessToken;
    });

    it('200 — returns authenticated user profile', async () => {
      const res = await request(app).get(`${BASE}/me`).set('Authorization', `Bearer ${authToken}`);
      expect(res.status).toBe(200);
      expect(res.body.email).toBe(userEmail);
    });

    it('401 — no token', async () => {
      const res = await request(app).get(`${BASE}/me`);
      expect(res.status).toBe(401);
    });

    it('401 — expired / invalid token', async () => {
      const res = await request(app).get(`${BASE}/me`).set('Authorization', 'Bearer bad.token.here');
      expect(res.status).toBe(401);
    });
  });

  // ─── Password Reset ─────────────────────────────────────────
  describe('POST /password-reset/request', () => {
    it('200 — always returns ok (no user enumeration)', async () => {
      const res = await request(app).post(`${BASE}/password-reset/request`).send({ email: userEmail });
      expect(res.status).toBe(200);
      const res2 = await request(app).post(`${BASE}/password-reset/request`).send({ email: 'none@none.com' });
      expect(res2.status).toBe(200);
    });

    it('400 — missing email', async () => {
      const res = await request(app).post(`${BASE}/password-reset/request`).send({});
      expect(res.status).toBe(400);
    });
  });

  describe('POST /password-reset/confirm', () => {
    it('400 — invalid or expired token', async () => {
      const res = await request(app).post(`${BASE}/password-reset/confirm`).send({ token: 'bad', password: 'NewP@ss1' });
      expect(res.status).toBe(400);
    });
  });

  // ─── Logout ─────────────────────────────────────────────────
  describe('POST /logout', () => {
    it('200 — clears refresh cookie', async () => {
      const res = await request(app).post(`${BASE}/logout`).set('Cookie', refreshCookie);
      expect(res.status).toBe(200);
      const cookies = res.headers['set-cookie'] || [];
      const cleared = cookies.some(c => c.includes('refreshToken=;') || c.includes('Max-Age=0'));
      expect(cleared).toBe(true);
    });

    it('200 — idempotent without cookie', async () => {
      const res = await request(app).post(`${BASE}/logout`);
      expect(res.status).toBe(200);
    });
  });

  // ─── OAuth2 Callbacks ───────────────────────────────────────
  describe('GET /oauth/:provider/callback', () => {
    it('400 — unsupported provider', async () => {
      const res = await request(app).get(`${BASE}/oauth/fak.provider/callback?code=x`);
      expect(res.status).toBe(400);
    });

    it('502 — provider auth failure (bad code)', async () => {
      const res = await request(app).get(`${BASE}/oauth/google/callback?code=bad_code`);
      expect([400, 502]).toContain(res.status);
    });
  });
});
===