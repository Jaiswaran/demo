const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { z } = require('zod');
const { PrismaClient } = require('@prisma/client');
const { createObjectKey, createPreviewKey, uploadPrivateObject, signedDownloadUrl } = require('./storage');
const { buildPreview } = require('./preview');

const app = express();
const prisma = new PrismaClient();
const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = process.env.JWT_SECRET;
const PLATFORM_FEE_PERCENT = 10;
const MAX_BOOK_BYTES = 50 * 1024 * 1024;
const allowedTypes = new Map([
  ['application/pdf', 'PDF'],
  ['application/epub+zip', 'EPUB'],
  ['application/octet-stream', 'EPUB']
]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BOOK_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => cb(null, allowedTypes.has(file.mimetype) || /\.(pdf|epub)$/i.test(file.originalname))
});

if (!JWT_SECRET) console.warn('JWT_SECRET is not set; authentication endpoints will reject requests until it is configured.');

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '1mb' }));

const authSchema = z.object({
  email: z.string().email().transform((value) => value.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  name: z.string().trim().min(2).max(80).optional(),
  role: z.enum(['READER', 'AUTHOR']).default('READER')
});
const bookSchema = z.object({
  title: z.string().trim().min(1).max(180),
  description: z.string().trim().min(1).max(5000),
  genre: z.string().trim().min(1).max(80),
  price: z.number().int().positive().max(10000000),
  format: z.enum(['PDF', 'EPUB']),
  objectKey: z.string().trim().min(1).max(500),
  previewKey: z.string().trim().max(500).optional(),
  published: z.boolean().default(false)
});
const reviewSchema = z.object({ rating: z.number().int().min(1).max(5), body: z.string().trim().max(2000).optional() });

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
  } catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}

function requireRole(...roles) {
  return (req, res, next) => roles.includes(req.user?.role) ? next() : res.status(403).json({ error: 'Insufficient role permissions' });
}

app.get('/api/health', async (_req, res) => {
  try { await prisma.$queryRaw`SELECT 1`; res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const input = authSchema.parse(req.body);
    const exists = await prisma.user.findUnique({ where: { email: input.email } });
    if (exists) return res.status(409).json({ error: 'An account with this email already exists' });
    const passwordHash = await bcrypt.hash(input.password, 12);
    const user = await prisma.user.create({ data: { email: input.email, name: input.name || input.email.split('@')[0], passwordHash, role: input.role }, select: { id: true, email: true, name: true, role: true } });
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

app.get('/api/books', async (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  const genre = typeof req.query.genre === 'string' ? req.query.genre.trim() : '';
  const books = await prisma.book.findMany({
    where: { published: true, ...(genre ? { genre } : {}), ...(query ? { OR: [{ title: { contains: query, mode: 'insensitive' } }, { description: { contains: query, mode: 'insensitive' } }, { author: { name: { contains: query, mode: 'insensitive' } } }] } : {}) },
    select: { id: true, title: true, description: true, genre: true, price: true, currency: true, format: true, author: { select: { id: true, name: true } }, createdAt: true },
    orderBy: { createdAt: 'desc' }
  });
  res.json({ books });
});

app.get('/api/books/:id', async (req, res) => {
  const book = await prisma.book.findFirst({ where: { id: req.params.id, published: true }, select: { id: true, title: true, description: true, genre: true, price: true, currency: true, format: true, previewKey: true, author: { select: { id: true, name: true } }, reviews: { orderBy: { createdAt: 'desc' }, select: { id: true, rating: true, body: true, createdAt: true, reader: { select: { name: true } } } } } });
  if (!book) return res.status(404).json({ error: 'Book not found' });
  res.json({ book });
});

app.post('/api/author/uploads', auth, requireRole('AUTHOR'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'A PDF or EPUB file is required' });
    const detected = allowedTypes.get(req.file.mimetype) || (/\.epub$/i.test(req.file.originalname) ? 'EPUB' : /\.pdf$/i.test(req.file.originalname) ? 'PDF' : null);
    if (!detected) return res.status(415).json({ error: 'Only PDF and EPUB files are supported' });
    const key = createObjectKey({ authorId: req.user.id, originalName: req.file.originalname });
    const preview = await buildPreview({ buffer: req.file.buffer, format: detected });
    const previewKey = createPreviewKey({ authorId: req.user.id });
    await Promise.all([
      uploadPrivateObject({ key, body: req.file.buffer, contentType: detected === 'PDF' ? 'application/pdf' : 'application/epub+zip' }),
      uploadPrivateObject({ key: previewKey, body: preview.body, contentType: preview.contentType })
    ]);
    res.status(201).json({ objectKey: key, previewKey, format: detected, bytes: req.file.size, previewPages: preview.pageCount });
  } catch (error) {
    console.error(error);
    res.status(422).json({ error: 'Unable to validate or generate preview for this book file' });
  }
});

app.post('/api/author/books', auth, requireRole('AUTHOR'), async (req, res) => {
  try {
    const input = bookSchema.parse(req.body);
    const book = await prisma.book.create({ data: { ...input, authorId: req.user.id } });
    res.status(201).json({ book });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ error: 'Invalid book data', details: error.issues });
    res.status(500).json({ error: 'Unable to create book' });
  }
});

app.get('/api/books/:id/preview', async (req, res) => {
  const book = await prisma.book.findFirst({ where: { id: req.params.id, published: true }, select: { previewKey: true } });
  if (!book) return res.status(404).json({ error: 'Book not found' });
  if (!book.previewKey) return res.status(404).json({ error: 'Preview is not available yet' });
  try { res.json({ url: await signedDownloadUrl(book.previewKey, 300), expiresIn: 300 }); }
  catch { res.status(503).json({ error: 'Preview storage is not configured' }); }
});

app.post('/api/books/:id/purchase', auth, requireRole('READER'), async (req, res) => {
  const book = await prisma.book.findFirst({ where: { id: req.params.id, published: true } });
  if (!book) return res.status(404).json({ error: 'Book not found' });
  const existing = await prisma.purchase.findFirst({ where: { bookId: book.id, readerId: req.user.id, status: 'COMPLETED' } });
  if (existing) return res.status(409).json({ error: 'Book already belongs to your library', purchaseId: existing.id });
  const platformFee = Math.round(book.price * PLATFORM_FEE_PERCENT / 100);
  const purchase = await prisma.purchase.create({ data: { readerId: req.user.id, authorId: book.authorId, bookId: book.id, amount: book.price, platformFee, currency: book.currency, status: 'COMPLETED' } });
  res.status(201).json({ purchase: { id: purchase.id, bookId: purchase.bookId, amount: purchase.amount, platformFee: purchase.platformFee, authorNet: purchase.amount - purchase.platformFee, status: purchase.status } });
});

app.get('/api/reader/library', auth, requireRole('READER'), async (req, res) => {
  const purchases = await prisma.purchase.findMany({ where: { readerId: req.user.id, status: 'COMPLETED' }, include: { book: { select: { id: true, title: true, description: true, genre: true, format: true, author: { select: { name: true } } } } }, orderBy: { createdAt: 'desc' } });
  res.json({ purchases });
});

app.get('/api/books/:id/content', auth, requireRole('READER'), async (req, res) => {
  const purchase = await prisma.purchase.findFirst({ where: { readerId: req.user.id, bookId: req.params.id, status: 'COMPLETED' }, include: { book: { select: { id: true, format: true, objectKey: true } } } });
  if (!purchase) return res.status(403).json({ error: 'Purchase required' });
  try { res.json({ bookId: purchase.book.id, format: purchase.book.format, url: await signedDownloadUrl(purchase.book.objectKey, 300), expiresIn: 300 }); }
  catch { res.status(503).json({ error: 'Book storage is not configured' }); }
});

app.post('/api/books/:id/reviews', auth, requireRole('READER'), async (req, res) => {
  try {
    const input = reviewSchema.parse(req.body);
    const purchase = await prisma.purchase.findFirst({ where: { readerId: req.user.id, bookId: req.params.id, status: 'COMPLETED' } });
    if (!purchase) return res.status(403).json({ error: 'Only readers who own the book can review it' });
    const book = await prisma.book.findFirst({ where: { id: req.params.id, published: true }, select: { id: true } });
    if (!book) return res.status(404).json({ error: 'Book not found' });
    const review = await prisma.review.upsert({ where: { readerId_bookId: { readerId: req.user.id, bookId: book.id } }, create: { readerId: req.user.id, bookId: book.id, rating: input.rating, body: input.body }, update: { rating: input.rating, body: input.body } });
    res.status(201).json({ review });
  } catch (error) {
    if (error instanceof z.ZodError) return res.status(400).json({ error: 'Invalid review data', details: error.issues });
    res.status(500).json({ error: 'Unable to save review' });
  }
});

app.get('/api/author/dashboard', auth, requireRole('AUTHOR'), async (req, res) => {
  const [books, sales] = await Promise.all([prisma.book.findMany({ where: { authorId: req.user.id }, orderBy: { createdAt: 'desc' } }), prisma.purchase.findMany({ where: { authorId: req.user.id, status: 'COMPLETED' }, select: { amount: true, platformFee: true } })]);
  const gross = sales.reduce((sum, sale) => sum + sale.amount, 0);
  const fees = sales.reduce((sum, sale) => sum + sale.platformFee, 0);
  res.json({ books, salesCount: sales.length, gross, platformFees: fees, net: gross - fees, platformFeePercent: PLATFORM_FEE_PERCENT });
});

app.get('/api/admin/metrics', auth, requireRole('ADMIN'), async (_req, res) => {
  const [books, purchases, users, reviews] = await Promise.all([prisma.book.count(), prisma.purchase.findMany({ where: { status: 'COMPLETED' }, select: { amount: true, platformFee: true } }), prisma.user.groupBy({ by: ['role'], _count: { _all: true } }), prisma.review.count()]);
  const revenue = purchases.reduce((sum, p) => sum + p.amount, 0);
  const platformFees = purchases.reduce((sum, p) => sum + p.platformFee, 0);
  res.json({ booksListed: books, booksSold: purchases.length, revenue, platformFees, reviewCount: reviews, users: users.reduce((out, row) => ({ ...out, [row.role.toLowerCase()]: row._count._all }), {}) });
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: `Book file exceeds ${MAX_BOOK_BYTES / (1024 * 1024)}MB limit` });
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => console.log(`BOOKSPHERE API listening on :${PORT}`));
async function shutdown(signal) { console.log(`${signal}: shutting down BOOKSPHERE API`); await prisma.$disconnect(); server.close(() => process.exit(0)); }
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
