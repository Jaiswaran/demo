const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.warn('JWT_SECRET is not set; authentication endpoints will reject requests until it is configured.');
}

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '1mb' }));

const authSchema = z.object({
  email: z.string().email().transform((value) => value.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  name: z.string().trim().min(2).max(80).optional(),
  role: z.enum(['READER', 'AUTHOR']).default('READER')
});

function signUser(user) {
  if (!JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return jwt.sign({ sub: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

async function auth(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Authentication required' });
    const claims = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: claims.sub }, select: { id: true, email: true, name: true, role: true } });
    if (!user) return res.status(401).json({ error: 'Account not found' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => roles.includes(req.user?.role) ? next() : res.status(403).json({ error: 'Insufficient role permissions' });
}

app.get('/api/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, database: 'connected' });
  } catch {
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const input = authSchema.parse(req.body);
    const exists = await prisma.user.findUnique({ where: { email: input.email } });
    if (exists) return res.status(409).json({ error: 'An account with this email already exists' });
    const passwordHash = await bcrypt.hash(input.password, 12);
    const user = await prisma.user.create({
      data: { email: input.email, name: input.name || input.email.split('@')[0], passwordHash, role: input.role },
      select: { id: true, email: true, name: true, role: true }
    });
    res.status(201).json({ user, token: signUser(user) });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ error: 'Invalid registration data', details: error.issues });
    res.status(500).json({ error: 'Unable to create account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const input = authSchema.pick({ email: true, password: true }).parse(req.body);
    const user = await prisma.user.findUnique({ where: { email: input.email } });
    if (!user || !(await bcrypt.compare(input.password, user.passwordHash))) return res.status(401).json({ error: 'Invalid email or password' });
    const safeUser = { id: user.id, email: user.email, name: user.name, role: user.role };
    res.json({ user: safeUser, token: signUser(safeUser) });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ error: 'Invalid login data' });
    res.status(500).json({ error: 'Unable to sign in' });
  }
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));
app.get('/api/author/dashboard', auth, requireRole('AUTHOR'), async (req, res) => {
  const [books, sales] = await Promise.all([
    prisma.book.findMany({ where: { authorId: req.user.id }, orderBy: { createdAt: 'desc' } }),
    prisma.purchase.findMany({ where: { authorId: req.user.id }, select: { amount: true, platformFee: true } })
  ]);
  const gross = sales.reduce((sum, sale) => sum + sale.amount, 0);
  const fees = sales.reduce((sum, sale) => sum + sale.platformFee, 0);
  res.json({ books, salesCount: sales.length, gross, platformFees: fees, net: gross - fees });
});

app.get('/api/reader/library', auth, requireRole('READER'), async (req, res) => {
  const purchases = await prisma.purchase.findMany({ where: { readerId: req.user.id }, include: { book: true }, orderBy: { createdAt: 'desc' } });
  res.json({ purchases });
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`BOOKSPHERE API listening on :${PORT}`));
