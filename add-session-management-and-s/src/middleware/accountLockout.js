const { getRedisClient } = require('./security');

const LOCKOUT_KEY_PREFIX = 'lockout:';
const ATTEMPTS_KEY_PREFIX = 'attempts:';

const DEFAULTS = {
  maxAttempts: parseInt(process.env.LOCKOUT_MAX_ATTEMPTS, 10) || 5,
  lockoutDuration: parseInt(process.env.LOCKOUT_DURATION_MS, 10) || 30 * 60 * 1000,
  attemptWindow: parseInt(process.env.LOCKOUT_ATTEMPT_WINDOW_MS, 10) || 15 * 60 * 1000,
};

async function recordFailedAttempt(email) {
  const client = await getRedisClient();
  const attemptsKey = ATTEMPTS_KEY_PREFIX + email;
  const lockoutKey = LOCKOUT_KEY_PREFIX + email;
  const { maxAttempts, lockoutDuration, attemptWindow } = DEFAULTS;

  const current = await client.incr(attemptsKey);
  if (current === 1) {
    await client.expire(attemptsKey, Math.ceil(attemptWindow / 1000));
  }

  if (current >= maxAttempts) {
    const ttl = Math.ceil(lockoutDuration / 1000);
    await client.set(lockoutKey, String(current), { EX: ttl });
    await client.del(attemptsKey);
    return { locked: true, attempts: current, remaining: 0 };
  }

  return { locked: false, attempts: current, remaining: maxAttempts - current };
}

async function clearFailedAttempts(email) {
  const client = await getRedisClient();
  await client.del(ATTEMPTS_KEY_PREFIX + email);
}

async function checkAccountLockout(email) {
  const client = await getRedisClient();
  const lockoutKey = LOCKOUT_KEY_PREFIX + email;

  const locked = await client.get(lockoutKey);
  if (locked) {
    const ttl = await client.ttl(lockoutKey);
    const minutesLeft = Math.ceil(ttl / 60);
    return {
      isLocked: true,
      message: `Account locked due to too many failed attempts. Try again in ${minutesLeft} minute${minutesLeft !== 1 ? 's' : ''}.`,
      ttlSeconds: ttl,
    };
  }
  return { isLocked: false };
}

function lockoutGuard() {
  return async (req, res, next) => {
    const email = req.body?.email;
    if (!email) return next();

    try {
      const status = await checkAccountLockout(email);
      if (status.isLocked) {
        return res.status(423).json({
          error: 'Account temporarily locked',
          message: status.message,
          retryAfter: status.ttlSeconds,
        });
      }
      next();
    } catch (err) {
      console.error('Lockout check failed:', err);
      next();
    }
  };
}

function handleLoginOutcome() {
  return async (req, res, next) => {
    const email = req.body?.email;
    if (!email) return next();

    const originalJson = res.json.bind(res);
    res.json = function (data) {
      const isFailed = res.statusCode === 401;
      const handler = isFailed ? recordFailedAttempt(email) : clearFailedAttempts(email);
      handler.catch((err) => console.error('Lockout tracking error:', err));
      return originalJson(data);
    };
    next();
  };
}

module.exports = {
  recordFailedAttempt,
  clearFailedAttempts,
  checkAccountLockout,
  lockoutGuard,
  handleLoginOutcome,
  DEFAULTS,
};