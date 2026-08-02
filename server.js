const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Log startup immediately
const startupLog = [];
function slog(msg) { startupLog.push(msg); console.log('[startup]', msg); }

try {
slog('Step 1: loading modules');
const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { createZipFromDir } = require('./ziputil');
slog('Step 2: modules OK');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

slog('Step 3: security headers');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

const rateLimitStore = new Map();
function rateLimit(key, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
  entry.count++;
  rateLimitStore.set(key, entry);
  if (entry.count > maxAttempts) {
    const err = new Error('Слишком много попыток. Попробуйте позже.');
    err.status = 429;
    throw err;
  }
}

slog('Step 4: database');
const db = new Database(path.join(__dirname, 'lensflow.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    gender TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS albums (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    password TEXT,
    slug TEXT UNIQUE,
    is_generated INTEGER DEFAULT 0,
    cover_photo_id INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS photos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    album_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    mime_type TEXT DEFAULT '',
    downloads INTEGER DEFAULT 0,
    drive_file_id TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (album_id) REFERENCES albums(id)
  );
  CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    photo_id INTEGER NOT NULL,
    ip_address TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (photo_id) REFERENCES photos(id),
    UNIQUE(photo_id, ip_address)
  );
`);

try { db.exec('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE albums ADD COLUMN cover_photo_id INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE photos ADD COLUMN drive_file_id TEXT DEFAULT ""'); } catch (e) {}
db.exec("UPDATE users SET avatar = 'man.webp' WHERE gender = 'male' AND (avatar IS NULL OR avatar = '')");
db.exec("UPDATE users SET avatar = 'women.webp' WHERE gender = 'female' AND (avatar IS NULL OR avatar = '')");

slog('Step 5: middleware');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'lensflow.sid',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const albumId = req.params.id;
    const dir = path.join(__dirname, 'uploads', 'albums', albumId);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = crypto.randomBytes(16).toString('hex') + ext;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|webp|avif|tiff|raw|cr2|nef|arw|dng)$/i;
    if (allowed.test(path.extname(file.originalname))) {
      cb(null, true);
    } else {
      cb(new Error('Только изображения разрешены'));
    }
  }
});

function generateSlug() { return crypto.randomBytes(6).toString('base64url').slice(0, 8); }

function generatePassword() {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower = 'abcdefghijklmnopqrstuvwxyz', digits = '0123456789';
  const all = upper + lower + digits;
  let pwd = upper[crypto.randomInt(upper.length)] + lower[crypto.randomInt(lower.length)] + digits[crypto.randomInt(digits.length)];
  for (let i = 0; i < 8; i++) pwd += all[crypto.randomInt(all.length)];
  return pwd.split('').sort(() => crypto.randomInt(-1, 2)).join('');
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Необходима авторизация' });
  next();
}

slog('Step 6: auth routes');
app.post('/api/register', (req, res) => {
  try { rateLimit(req.ip); } catch (e) { return res.status(e.status || 429).json({ error: e.message }); }
  const { username, password, name, gender } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'Заполните все обязательные поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
  if (username.length < 3 || username.length > 30) return res.status(400).json({ error: 'Логин должен быть от 3 до 30 символов' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Логин может содержать только латиницу, цифры и _' });
  if (name.length > 100) return res.status(400).json({ error: 'Имя слишком длинное' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'Пользователь с таким логином уже существует' });
  const hash = bcrypt.hashSync(password, 10);
  const avatar = gender === 'male' ? 'man.webp' : gender === 'female' ? 'women.webp' : '';
  const result = db.prepare('INSERT INTO users (username, password_hash, name, gender, avatar) VALUES (?, ?, ?, ?, ?)').run(username, hash, name, gender || '', avatar);
  const user = db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
  req.session.userId = user.id;
  res.json({ user });
});

app.post('/api/login', (req, res) => {
  try { rateLimit(req.ip); } catch (e) { return res.status(e.status || 429).json({ error: e.message }); }
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(400).json({ error: 'Неверный логин или пароль' });
  req.session.userId = user.id;
  res.json({ user: { id: user.id, username: user.username, name: user.name, gender: user.gender, avatar: user.avatar, created_at: user.created_at } });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  res.json({ user: db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(req.session.userId) });
});

slog('Step 7: account/admin routes');
app.put('/api/account', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Имя не может быть пустым' });
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.session.userId);
  res.json({ user: db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(req.session.userId) });
});

const ADMIN_USER = 'admin', ADMIN_PASS = 'admin123';
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) { req.session.isAdmin = true; return res.json({ ok: true }); }
  return res.status(400).json({ error: 'Неверный логин или пароль' });
});

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).json({ error: 'Требуется авторизация администратора' });
  next();
}

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const totalAlbums = db.prepare('SELECT COUNT(*) as c FROM albums').get().c;
  const totalPhotos = db.prepare('SELECT COUNT(*) as c FROM photos').get().c;
  const totalLikes = db.prepare('SELECT COUNT(*) as c FROM likes').get().c;
  const totalDownloads = db.prepare('SELECT COALESCE(SUM(downloads),0) as s FROM photos').get().s;
  const totalSize = db.prepare('SELECT COALESCE(SUM(size),0) as s FROM photos').get().s;
  const maleCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE gender='male'").get().c;
  const femaleCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE gender='female'").get().c;
  const users = db.prepare(`SELECT u.id, u.username, u.name, u.gender, u.created_at,
    (SELECT COUNT(*) FROM albums WHERE user_id = u.id) as album_count,
    (SELECT COUNT(*) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as photo_count,
    (SELECT COALESCE(SUM(p.downloads),0) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as total_downloads,
    (SELECT COALESCE(SUM(p.size),0) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as total_storage
    FROM users u ORDER BY u.created_at DESC`).all();
  res.json({ total_users: totalUsers, total_albums: totalAlbums, total_photos: totalPhotos, total_likes: totalLikes, total_downloads: totalDownloads, total_size: totalSize, male_count: maleCount, female_count: femaleCount, users });
});

app.post('/api/admin/logout', (req, res) => { req.session.isAdmin = false; res.json({ ok: true }); });

app.get('/admin', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'admin.html')); });

app.put('/api/account/gender', requireAuth, (req, res) => {
  const { gender, avatar } = req.body;
  db.prepare('UPDATE users SET gender = ?, avatar = ? WHERE id = ?').run(gender || '', avatar || '', req.session.userId);
  res.json({ user: db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(req.session.userId) });
});

slog('Step 8: album routes');
app.post('/api/albums', requireAuth, (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Укажите название альбома' });
  const slug = generateSlug();
  const result = db.prepare('INSERT INTO albums (user_id, title, description, slug) VALUES (?, ?, ?, ?)').run(req.session.userId, title, description || '', slug);
  res.json({ album: db.prepare('SELECT * FROM albums WHERE id = ?').get(result.lastInsertRowid) });
});

app.get('/api/albums', requireAuth, (req, res) => {
  const albums = db.prepare('SELECT * FROM albums WHERE user_id = ? ORDER BY created_at DESC').all(req.session.userId);
  const result = albums.map(album => {
    const pc = db.prepare('SELECT COUNT(*) as count FROM photos WHERE album_id = ?').get(album.id);
    const td = db.prepare('SELECT SUM(downloads) as total FROM photos WHERE album_id = ?').get(album.id);
    let cf = null;
    if (album.cover_photo_id) { const c = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id); if (c) cf = c.filename; }
    return { ...album, photo_count: pc.count, total_downloads: td.total || 0, cover_filename: cf };
  });
  res.json({ albums: result });
});

app.get('/api/albums/:id', requireAuth, (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) return res.status(404).json({ error: 'Альбом не найден' });
  const photos = db.prepare('SELECT * FROM photos WHERE album_id = ? ORDER BY created_at DESC').all(album.id);
  let cf = null;
  if (album.cover_photo_id) { const c = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id); if (c) cf = c.filename; }
  res.json({ album: { ...album, cover_filename: cf }, photos });
});

app.delete('/api/albums/:id', requireAuth, (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) return res.status(404).json({ error: 'Альбом не найден' });
  const dir = path.join(__dirname, 'uploads', 'albums', String(album.id));
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  db.prepare('DELETE FROM likes WHERE photo_id IN (SELECT id FROM photos WHERE album_id = ?)').run(album.id);
  db.prepare('DELETE FROM photos WHERE album_id = ?').run(album.id);
  db.prepare('DELETE FROM albums WHERE id = ?').run(album.id);
  res.json({ ok: true });
});

app.put('/api/albums/:id/cover', requireAuth, (req, res) => {
  const { photo_id } = req.body;
  if (!photo_id) return res.status(400).json({ error: 'Укажите photo_id' });
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) return res.status(404).json({ error: 'Альбом не найден' });
  const photo = db.prepare('SELECT * FROM photos WHERE id = ? AND album_id = ?').get(photo_id, album.id);
  if (!photo) return res.status(404).json({ error: 'Фото не найдено' });
  db.prepare('UPDATE albums SET cover_photo_id = ? WHERE id = ?').run(photo_id, album.id);
  res.json({ cover_photo_id: photo_id, filename: photo.filename });
});

app.post('/api/albums/:id/generate', requireAuth, (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) return res.status(404).json({ error: 'Альбом не найден' });
  const pc = db.prepare('SELECT COUNT(*) as count FROM photos WHERE album_id = ?').get(album.id);
  if (pc.count === 0) return res.status(400).json({ error: 'Добавьте хотя бы одно фото перед генерацией' });
  const password = generatePassword(), slug = generateSlug();
  db.prepare('UPDATE albums SET password = ?, slug = ?, is_generated = 1 WHERE id = ?').run(password, slug, album.id);
  res.json({ password, link: `${req.protocol}://${req.get('host')}/gallery/${slug}`, slug });
});

slog('Step 9: upload route');
app.post('/api/albums/:id/photos', requireAuth, upload.array('photos', 500), (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) return res.status(404).json({ error: 'Альбом не найден' });
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'Выберите файлы для загрузки' });
  const insert = db.prepare('INSERT INTO photos (album_id, filename, original_name, size, mime_type, drive_file_id) VALUES (?, ?, ?, ?, ?, ?)');
  const photos = [];
  for (const file of req.files) {
    const result = insert.run(album.id, file.filename, file.originalname, file.size, file.mimetype, '');
    if (!album.cover_photo_id) { db.prepare('UPDATE albums SET cover_photo_id = ? WHERE id = ?').run(result.lastInsertRowid, album.id); album.cover_photo_id = result.lastInsertRowid; }
    photos.push({ id: result.lastInsertRowid, filename: file.filename, original_name: file.originalname, size: file.size, mime_type: file.mimetype, drive_file_id: '' });
  }
  res.json({ photos });
});

app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const photo = db.prepare('SELECT p.* FROM photos p JOIN albums a ON p.album_id = a.id WHERE p.id = ? AND a.user_id = ?').get(req.params.id, req.session.userId);
  if (!photo) return res.status(404).json({ error: 'Фото не найдено' });
  const fp = path.join(__dirname, 'uploads', 'albums', String(photo.album_id), photo.filename);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  db.prepare('DELETE FROM likes WHERE photo_id = ?').run(photo.id);
  db.prepare('DELETE FROM photos WHERE id = ?').run(photo.id);
  res.json({ ok: true });
});

slog('Step 10: gallery routes');
app.get('/api/photo/:albumId/:filename', (req, res) => {
  const fp = path.join(__dirname, 'uploads', 'albums', req.params.albumId, req.params.filename);
  if (fs.existsSync(fp)) return res.sendFile(fp);
  res.status(404).send('Not found');
});

app.get('/api/gallery/:slug', (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE slug = ? AND is_generated = 1').get(req.params.slug);
  if (!album) return res.status(404).json({ error: 'Галерея не найдена' });
  let cf = null;
  if (album.cover_photo_id) { const c = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id); if (c) cf = c.filename; }
  res.json({ album: { id: album.id, title: album.title, description: album.description, slug: album.slug, cover_filename: cf } });
});

app.post('/api/gallery/:slug/verify', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Введите пароль' });
  const album = db.prepare('SELECT * FROM albums WHERE slug = ? AND is_generated = 1').get(req.params.slug);
  if (!album) return res.status(404).json({ error: 'Галерея не найдена' });
  if (password !== album.password) return res.status(400).json({ error: 'Неверный пароль' });
  const photos = db.prepare(`SELECT p.id, p.filename, p.original_name, p.size, p.downloads,
    (SELECT COUNT(*) FROM likes WHERE photo_id = p.id) as likes_count
    FROM photos p WHERE p.album_id = ? ORDER BY p.created_at ASC`).all(album.id);
  const likedPhotos = db.prepare('SELECT photo_id FROM likes WHERE ip_address = ?').all(req.ip).map(l => l.photo_id);
  let cf = null;
  if (album.cover_photo_id) { const c = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id); if (c) cf = c.filename; }
  res.json({ album: { id: album.id, title: album.title, description: album.description, slug: album.slug, cover_filename: cf }, photos, liked_photos: likedPhotos });
});

app.get('/api/gallery/:slug/download-all', (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE slug = ? AND is_generated = 1').get(req.params.slug);
  if (!album) return res.status(404).json({ error: 'Галерея не найдена' });
  const dir = path.join(__dirname, 'uploads', 'albums', String(album.id));
  if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Файлы не найдены' });
  const zipBuffer = createZipFromDir(dir, album.title.replace(/[^a-zA-Z0-9а-яА-ЯёЁ\s-]/g, '') + '/');
  const safeName = album.title.replace(/[^a-zA-Z0-9а-яА-ЯёЁ\s-]/g, '_') || 'album';
  res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${safeName}.zip"`, 'Content-Length': zipBuffer.length });
  res.send(zipBuffer);
});

app.post('/api/photos/:id/like', (req, res) => {
  const photo = db.prepare('SELECT * FROM photos WHERE id = ?').get(req.params.id);
  if (!photo) return res.status(404).json({ error: 'Фото не найдено' });
  try {
    db.prepare('INSERT INTO likes (photo_id, ip_address) VALUES (?, ?)').run(req.params.id, req.ip);
    const count = db.prepare('SELECT COUNT(*) as count FROM likes WHERE photo_id = ?').get(req.params.id);
    res.json({ liked: true, likes_count: count.count });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      db.prepare('DELETE FROM likes WHERE photo_id = ? AND ip_address = ?').run(req.params.id, req.ip);
      const count = db.prepare('SELECT COUNT(*) as count FROM likes WHERE photo_id = ?').get(req.params.id);
      res.json({ liked: false, likes_count: count.count });
    } else { res.status(500).json({ error: 'Ошибка' }); }
  }
});

app.get('/api/photos/:id/download', (req, res) => {
  const photo = db.prepare('SELECT p.*, a.slug FROM photos p JOIN albums a ON p.album_id = a.id WHERE p.id = ?').get(req.params.id);
  if (!photo) return res.status(404).json({ error: 'Фото не найдено' });
  db.prepare('UPDATE photos SET downloads = downloads + 1 WHERE id = ?').run(photo.id);
  const fp = path.join(__dirname, 'uploads', 'albums', String(photo.album_id), photo.filename);
  if (fs.existsSync(fp)) return res.download(fp, photo.original_name);
  res.status(404).json({ error: 'Файл не найден' });
});

slog('Step 11: health + pages');
app.get('/api/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime(), startup: startupLog }));
app.get('/account', (req, res) => { if (!req.session.userId) return res.redirect('/login.html'); res.sendFile(path.join(__dirname, 'public', 'account.html')); });
app.get('/gallery/:slug', (req, res) => res.sendFile(path.join(__dirname, 'public', 'gallery.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  if (err instanceof multer.MulterError) { if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Файл слишком большой (макс. 100MB)' }); return res.status(400).json({ error: err.message }); }
  if (err) return res.status(err.status || 400).json({ error: err.message });
  next();
});

process.on('unhandledRejection', (err) => { console.error('Unhandled Rejection:', err.message); });
process.on('uncaughtException', (err) => { console.error('Uncaught Exception:', err.message); });

app.listen({ port: PORT, host: '0.0.0.0' }, () => {
  console.log(`LensFlow сервер запущен на порту ${PORT}`);
});

} catch (err) {
  console.error('FATAL STARTUP ERROR:', err.message);
  console.error(err.stack);
  console.error(JSON.stringify(startupLog));
  process.exit(1);
}
