const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const session = require('express-session');
const connectRedis = require('connect-redis');
const cors = require('cors');
const csrf = require('csurf');
const helmet = require('helmet');
const redis = require('redis');

const RedisSessionStore = connectRedis(session);

let redisClient = null;

async function getRedisClient() {
  if (redisClient && redisClient.isOpen) return redisClient;
  redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: { reconnectStrategy: (retries) => Math.min(retries * 100, 5000) },
  });
  redisClient.on('error', (err) => console.error('Redis client error:', err));
  await redisClient.connect();
  return redisClient;
}

function createRateLimiter(options = {}) {
  const {
    windowMs = 15 * 60 * 1000,
    max = 100,
    keyGenerator = (req) => req.ip,
    skipSuccessfulRequests = false,
    message = 'Too many requests, please try again later.',
  } = options;

  const storeOpts = {};
  if (process.env.REDIS_URL) {
    storeOpts.store = new RedisStore({
      sendCommand: (...args) => redisClient.sendCommand(args),
    });
  }

  return rateLimit({
    windowMs,
    max,
    keyGenerator,
    skipSuccessfulRequests,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message },
    ...storeOpts,
  });
}

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many authentication attempts. Please try again later.',
});

const loginLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.ip + ':' + (req.body?.email || ''),
  message: 'Too many login attempts for this account. Please try again later.',
});

const passwordResetLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: 'Too many password reset requests. Please try again later.',
});

function corsConfig() {
  const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').filter(Boolean);
  return cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
        callback(null, true);
      } else {
        callback(new Error('CORS policy violation'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    credentials: true,
    maxAge: 86400,
  });
}

async function sessionConfig() {
  const client = await getRedisClient();
  return session({
    store: new RedisSessionStore({
      client,
      prefix: 'sess:',
      ttl: 86400,
    }),
    name: process.env.SESSION_COOKIE_NAME || '__host.sid',
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 86400000,
      path: '/',
      domain: process.env.COOKIE_DOMAIN || undefined,
    },
    genid: () => require('crypto').randomBytes(16).toString('hex'),
  });
}

function csrfProtection() {
  const csrfMiddleware = csrf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' } });
  return (req, res, next) => {
    const excluded = ['/health', '/auth/login', '/auth/register', '/auth/oauth'];
    if (excluded.some((p) => req.path.startsWith(p))) return next();
    csrfMiddleware(req, res, next);
  };
}

function applySecurityHeaders(app) {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  }));
}

module.exports = {
  getRedisClient,
  createRateLimiter,
  authLimiter,
  loginLimiter,
  passwordResetLimiter,
  corsConfig,
  sessionConfig,
  csrfProtection,
  applySecurityHeaders,
};