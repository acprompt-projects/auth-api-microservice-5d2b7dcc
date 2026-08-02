import { Router, Request, Response, NextFunction } from 'express';
import Joi from 'joi';

const router = Router();

// ── Validation Schemas ──────────────────────────────────────────────
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required(),
  name: Joi.string().min(1).max(100).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const refreshSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

const passwordResetSchema = Joi.object({
  email: Joi.string().email().required(),
  newPassword: Joi.string().min(8).max(128).required(),
  token: Joi.string().required(),
});

// ── Validation Middleware ────────────────────────────────────────────
function validate(schema: Joi.ObjectSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error, value } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'Invalid input',
        details: error.details.map((d) => d.message),
      });
      return;
    }
    req.body = value;
    next();
  };
}

// ── Error Helper ────────────────────────────────────────────────────
class AuthError extends Error {
  constructor(
    public statusCode: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

function asyncHandler(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ── POST /auth/register ─────────────────────────────────────────────
router.post(
  '/register',
  validate(registerSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { email, password, name } = req.body;

    // TODO: replace with actual service calls
    // const existing = await userService.findByEmail(email);
    // if (existing) throw new AuthError(409, 'USER_EXISTS', 'Email already registered');
    // const user = await userService.create({ email, password, name });
    // const tokens = await tokenService.generatePair(user);

    res.status(201).json({
      message: 'User registered successfully',
      user: { id: 'placeholder', email, name },
      accessToken: 'placeholder-access-token',
      refreshToken: 'placeholder-refresh-token',
    });
  }),
);

// ── POST /auth/login ────────────────────────────────────────────────
router.post(
  '/login',
  validate(loginSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    // TODO: replace with actual service calls
    // const user = await userService.findByEmail(email);
    // if (!user) throw new AuthError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    // const valid = await userService.verifyPassword(user, password);
    // if (!valid) throw new AuthError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    // const tokens = await tokenService.generatePair(user);

    res.status(200).json({
      message: 'Login successful',
      accessToken: 'placeholder-access-token',
      refreshToken: 'placeholder-refresh-token',
      user: { id: 'placeholder', email },
    });
  }),
);

// ── POST /auth/logout ───────────────────────────────────────────────
router.post(
  '/logout',
  asyncHandler(async (req: Request, res: Response) => {
    const refreshToken = req.body.refreshToken as string | undefined;

    if (!refreshToken) {
      throw new AuthError(400, 'MISSING_TOKEN', 'Refresh token is required');
    }

    // TODO: replace with actual service calls
    // await tokenService.revoke(refreshToken);

    res.status(200).json({ message: 'Logged out successfully' });
  }),
);

// ── POST /auth/refresh ──────────────────────────────────────────────
router.post(
  '/refresh',
  validate(refreshSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.body;

    // TODO: replace with actual service calls
    // const payload = await tokenService.verifyRefresh(refreshToken);
    // if (!payload) throw new AuthError(401, 'INVALID_TOKEN', 'Invalid or expired refresh token');
    // await tokenService.revoke(refreshToken);
    // const user = await userService.findById(payload.sub);
    // const tokens = await tokenService.generatePair(user);

    res.status(200).json({
      accessToken: 'placeholder-access-token',
      refreshToken: 'placeholder-refresh-token',
    });
  }),
);

// ── POST /auth/password-reset ───────────────────────────────────────
router.post(
  '/password-reset',
  validate(passwordResetSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const { email, newPassword, token } = req.body;

    // TODO: replace with actual service calls
    // const valid = await tokenService.verifyPasswordResetToken(email, token);
    // if (!valid) throw new AuthError(401, 'INVALID_TOKEN', 'Reset token is invalid or expired');
    // await userService.updatePassword(email, newPassword);
    // await tokenService.revokeAllForUser(email);

    res.status(200).json({ message: 'Password reset successfully' });
  }),
);

// ── Central Error Handler ───────────────────────────────────────────
router.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof AuthError) {
    res.status(err.statusCode).json({ error: err.code, message: err.message });
    return;
  }
  console.error('Unhandled auth error:', err);
  res.status(500).json({ error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' });
});

export default router;