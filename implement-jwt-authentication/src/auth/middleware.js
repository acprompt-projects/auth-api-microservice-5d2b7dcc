const { verifyAccessToken } = require("./tokens");

function extractToken(req) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

/* ── authenticate ──────────────────────────────────────────── */
function authenticate(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: "Missing authorization token" });
  }
  try {
    const decoded = verifyAccessToken(token);
    if (decoded.type !== "access") {
      return res.status(401).json({ error: "Invalid token type" });
    }
    req.user = { id: decoded.sub, role: decoded.role, ...decoded };
    next();
  } catch (err) {
    const msg = err.name === "TokenExpiredError" ? "Token expired" : "Invalid token";
    return res.status(401).json({ error: msg });
  }
}

/* ── role-based access control ────────────────────────────── */
function authorize(...allowedRoles) {
  const roles = new Set(allowedRoles);
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    if (!roles.has(req.user.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

/* ── optional auth (sets req.user if present, never blocks) ─ */
function optionalAuth(req, res, next) {
  const token = extractToken(req);
  if (token) {
    try {
      const decoded = verifyAccessToken(token);
      if (decoded.type === "access") {
        req.user = { id: decoded.sub, role: decoded.role, ...decoded };
      }
    } catch { /* ignore */ }
  }
  next();
}

module.exports = { authenticate, authorize, optionalAuth };