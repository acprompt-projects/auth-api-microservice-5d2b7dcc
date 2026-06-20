const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");

const SALT_ROUNDS = 12;
const ACCESS_TTL = "15m";
const REFRESH_TTL = "7d";

function loadKey(filename) {
  const p = path.resolve(process.env.KEY_DIR || __dirname, filename);
  return fs.readFileSync(p, "utf8");
}

let _priv, _pub;
function privateKey() { return _priv || (_priv = loadKey("private.pem")); }
function publicKey()  { return _pub  || (_pub  = loadKey("public.pem")); }

/* ── password hashing ─────────────────────────────────────── */
async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

/* ── JWT helpers ──────────────────────────────────────────── */
function signAccessToken(payload) {
  const { sub, role, ...rest } = payload;
  return jwt.sign(
    { sub, role, type: "access", ...rest },
    privateKey(),
    { algorithm: "RS256", expiresIn: ACCESS_TTL }
  );
}

function signRefreshToken(payload) {
  const { sub } = payload;
  return jwt.sign(
    { sub, type: "refresh", tokenVersion: payload.tokenVersion || 0 },
    privateKey(),
    { algorithm: "RS256", expiresIn: REFRESH_TTL }
  );
}

function generateTokenPair(payload) {
  return {
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
  };
}

function verifyAccessToken(token) {
  return jwt.verify(token, publicKey(), { algorithms: ["RS256"] });
}

function verifyRefreshToken(token) {
  const decoded = jwt.verify(token, publicKey(), { algorithms: ["RS256"] });
  if (decoded.type !== "refresh") {
    const err = new Error("Not a refresh token");
    err.code = "INVALID_TOKEN_TYPE";
    throw err;
  }
  return decoded;
}

function refreshAccessToken(refreshToken, currentTokenVersion) {
  const decoded = verifyRefreshToken(refreshToken);
  if (decoded.tokenVersion !== currentTokenVersion) {
    const err = new Error("Refresh token revoked");
    err.code = "TOKEN_REVOKED";
    throw err;
  }
  return signAccessToken({ sub: decoded.sub, role: decoded.role });
}

function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}

module.exports = {
  hashPassword,
  verifyPassword,
  signAccessToken,
  signRefreshToken,
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  refreshAccessToken,
  decodeToken,
};