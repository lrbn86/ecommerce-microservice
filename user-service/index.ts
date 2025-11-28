import crypto from 'node:crypto';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { isEmail } from 'validator';
import { Pool } from 'pg';

if (!process.env.PORT) throw new Error('PORT undefined');
if (!process.env.JWT_SECRET_KEY) throw new Error('JWT_SECRET_KEY undefined');

const pool = new Pool({
  database: 'users'
});

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors());
app.use(helmet());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
}));

const loginLimiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts' }
});

app.use(enforceHTTPS);
app.use(handleLogging);
app.post('/v1/register', handleRegister);
app.post('/v1/login', loginLimiter, handleLogin);
app.get('/v1/profile', authenticate, requireRoles(['user']), getProfile);
app.use(handleNotFound);
app.use(handleError);

const port = process.env.PORT;
app.listen(port, handleServerStart);


async function handleServerStart() {
  console.log(`[${new Date().toISOString()}] User service started at http://localhost:${port}`);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role in ('guest', 'user', 'admin')),
        createdAt TIMESTAMPTZ DEFAULT NOW(),
        updatedAt TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  } catch (err) {
    console.error(err);
  }
}

async function authenticate(req: Request, res: Response, next: NextFunction) {

  const token = req?.headers?.authorization?.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    if (!process.env.JWT_SECRET_KEY) throw new Error('JWT_SECRET_KEY undefined');

    const user = jwt.verify(token, process.env.JWT_SECRET_KEY);

    // TODO: validate token to make sure it actually has the claims like sub, name, email, role
    // because this can be crafted

    res.locals.user = user;

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or missing token' })
  }
}

async function handleRegister(req: Request, res: Response, next: NextFunction) {
  const email = req?.body?.email?.toLowerCase().trim();
  const password = req?.body?.password;

  // TODO: enforce password strength

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email format' });

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    await pool.query(
      'INSERT INTO users (id, email, password, role) VALUES ($1, $2, $3, $4)',
      [crypto.randomUUID(), email, passwordHash, 'user']
    );

    res.locals.user = { email };

    return res.status(201).json({ message: 'User successfully registered' });
  } catch (err: any) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    return next(err);
  }
}

async function handleLogin(req: Request, res: Response, next: NextFunction) {
  const email = req?.body?.email?.toLowerCase().trim();
  const password = req?.body?.password;

  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  if (!isEmail(email)) return res.status(400).json({ error: 'Invalid email format' });

  try {
    const { rows: [user] } = await pool.query(
      'SELECT id, email, password, role FROM users WHERE email=$1',
      [email]
    );

    const fakeHash = await bcrypt.hash('fake-password', 12);
    const passwordMatch = await bcrypt.compare(password, user?.password ?? fakeHash);

    if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });

    if (!process.env.JWT_SECRET_KEY) throw new Error('JWT_SECRET_KEY undefined');

    const payload = {
      sub: user?.id,
      email: user?.email,
      role: user?.role,
    };

    res.locals.user = payload;

    // TODO: create refresh tokens, revoke mechnicams, rotation
    const token = jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: '5m' });

    return res.status(200).json({ token });
  } catch (err) {
    return next(err);
  }
}

async function getProfile(req: Request, res: Response, next: NextFunction) {
  try {
    const { rows: [user] } = await pool.query(
      'SELECT email FROM users where id=$1',
      [res.locals.user.sub],
    )
    return res.status(200).json({ message: 'Get Profile', data: user });
  } catch (err) {
    return next(err);
  }
}

function handleNotFound(req: Request, res: Response, next: NextFunction) {
  return res.status(404).json({ error: 'Not found' });
}

function handleError(err: Error, req: Request, res: Response, next: NextFunction) {
  console.error(err);
  return res.status(500).json({ error: 'Internal server error' });
}

function requireRoles(roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { role } = res.locals.user;
    if (!roles.includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    return next();
  }
}

function handleLogging(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();
  res.on('finish', () => {
    const user = res.locals.user;
    const duration = Date.now() - start;
    console.log({
      time: new Date().toISOString(),
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration,
      // TODO: below is PII
      ip: req.ip,
      user: { id: user?.sub, email: user?.email },
      userAgent: req.headers['user-agent']
    });
  });
  return next();
}

function enforceHTTPS(req: Request, res: Response, next: NextFunction) {
  if (process.env.NODE_ENV === 'development') return next();
  if (!req.secure) return res.status(403).json({ error: 'HTTPS required' });
  if (req.headers['x-forwarded-proto'] !== 'https') return res.status(403).json({ error: 'HTTPS required' });
  return next();
}
