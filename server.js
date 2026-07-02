const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createZipFromDir } = require('./ziputil');
const drive = require('./drive');
const uploadQueue = require('./uploadqueue');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// Rate limiter for login/register
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

// --- Database ---
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

// Migration: add avatar and cover_photo_id columns if not exists
try { db.exec('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE albums ADD COLUMN cover_photo_id INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE photos ADD COLUMN drive_file_id TEXT DEFAULT ""'); } catch (e) {}
// Update existing users without avatar
db.exec("UPDATE users SET avatar = 'man.webp' WHERE gender = 'male' AND (avatar IS NULL OR avatar = '')");
db.exec("UPDATE users SET avatar = 'women.webp' WHERE gender = 'female' AND (avatar IS NULL OR avatar = '')");

// --- Middleware ---
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

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// --- File Upload ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const albumId = req.params.id;
    const dir = path.join(__dirname, 'uploads', 'albums', albumId);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
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

// --- Helpers ---
function generateSlug() {
  return crypto.randomBytes(6).toString('base64url').slice(0, 8);
}

function generatePassword() {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const all = upper + lower + digits;
  let pwd = '';
  pwd += upper[crypto.randomInt(upper.length)];
  pwd += lower[crypto.randomInt(lower.length)];
  pwd += digits[crypto.randomInt(digits.length)];
  for (let i = 0; i < 8; i++) {
    pwd += all[crypto.randomInt(all.length)];
  }
  return pwd.split('').sort(() => crypto.randomInt(-1, 2)).join('');
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Необходима авторизация' });
  }
  next();
}

// --- Auth Routes ---
app.post('/api/register', (req, res) => {
  try { rateLimit(req.ip); } catch (e) { return res.status(e.status || 429).json({ error: e.message }); }

  const { username, password, name, gender } = req.body;

  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Заполните все обязательные поля' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
  }
  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ error: 'Логин должен быть от 3 до 30 символов' });
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Логин может содержать только латиницу, цифры и _' });
  }
  if (name.length > 100) {
    return res.status(400).json({ error: 'Имя слишком длинное' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(400).json({ error: 'Пользователь с таким логином уже существует' });
  }

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

  if (!username || !password) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(400).json({ error: 'Неверный логин или пароль' });
  }

  req.session.userId = user.id;
  res.json({
    user: {
      id: user.id,
      username: user.username,
      name: user.name,
      gender: user.gender,
      avatar: user.avatar,
      created_at: user.created_at
    }
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Не авторизован' });
  }
  const user = db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user });
});

// --- Account Routes ---
app.put('/api/account', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Имя не может быть пустым' });
  }
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.session.userId);
  const user = db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user });
});

// --- Admin Routes ---
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  return res.status(400).json({ error: 'Неверный логин или пароль' });
});

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    return res.status(401).json({ error: 'Требуется авторизация администратора' });
  }
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

  const users = db.prepare(`
    SELECT u.id, u.username, u.name, u.gender, u.created_at,
      (SELECT COUNT(*) FROM albums WHERE user_id = u.id) as album_count,
      (SELECT COUNT(*) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as photo_count,
      (SELECT COALESCE(SUM(p.downloads),0) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as total_downloads,
      (SELECT COALESCE(SUM(p.size),0) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as total_storage
    FROM users u ORDER BY u.created_at DESC
  `).all();

  res.json({
    total_users: totalUsers,
    total_albums: totalAlbums,
    total_photos: totalPhotos,
    total_likes: totalLikes,
    total_downloads: totalDownloads,
    total_size: totalSize,
    male_count: maleCount,
    female_count: femaleCount,
    users
  });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.json({ ok: true });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.put('/api/account/gender', requireAuth, (req, res) => {
  const { gender, avatar } = req.body;
  db.prepare('UPDATE users SET gender = ?, avatar = ? WHERE id = ?').run(gender || '', avatar || '', req.session.userId);
  const user = db.prepare('SELECT id, username, name, gender, avatar, created_at FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user });
});

// --- Album Routes ---
app.post('/api/albums', requireAuth, (req, res) => {
  const { title, description } = req.body;
  if (!title) {
    return res.status(400).json({ error: 'Укажите название альбома' });
  }
  const slug = generateSlug();
  const result = db.prepare('INSERT INTO albums (user_id, title, description, slug) VALUES (?, ?, ?, ?)').run(req.session.userId, title, description || '', slug);
  const album = db.prepare('SELECT * FROM albums WHERE id = ?').get(result.lastInsertRowid);
  res.json({ album });
});

app.get('/api/albums', requireAuth, (req, res) => {
  const albums = db.prepare('SELECT * FROM albums WHERE user_id = ? ORDER BY created_at DESC').all(req.session.userId);

  const result = albums.map(album => {
    const photoCount = db.prepare('SELECT COUNT(*) as count FROM photos WHERE album_id = ?').get(album.id);
    const totalDownloads = db.prepare('SELECT SUM(downloads) as total FROM photos WHERE album_id = ?').get(album.id);
    let coverFilename = null;
    if (album.cover_photo_id) {
      const cover = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id);
      if (cover) coverFilename = cover.filename;
    }
    return {
      ...album,
      photo_count: photoCount.count,
      total_downloads: totalDownloads.total || 0,
      cover_filename: coverFilename
    };
  });

  res.json({ albums: result });
});

app.get('/api/albums/:id', requireAuth, (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) {
    return res.status(404).json({ error: 'Альбом не найден' });
  }
  const photos = db.prepare('SELECT * FROM photos WHERE album_id = ? ORDER BY created_at DESC').all(album.id);
  let coverFilename = null;
  if (album.cover_photo_id) {
    const cover = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id);
    if (cover) coverFilename = cover.filename;
  }
  res.json({ album: { ...album, cover_filename: coverFilename }, photos });
});

app.delete('/api/albums/:id', requireAuth, async (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) {
    return res.status(404).json({ error: 'Альбом не найден' });
  }

  const dir = path.join(__dirname, 'uploads', 'albums', String(album.id));
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  try {
    const folderId = await drive.findAlbumFolder(album.id, album.title);
    if (folderId) await drive.deleteFolder(folderId);
  } catch (e) { console.error('Drive folder delete:', e.message); }

  db.prepare('DELETE FROM likes WHERE photo_id IN (SELECT id FROM photos WHERE album_id = ?)').run(album.id);
  db.prepare('DELETE FROM photos WHERE album_id = ?').run(album.id);
  db.prepare('DELETE FROM albums WHERE id = ?').run(album.id);

  res.json({ ok: true });
});

// --- Set Cover Photo ---
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

// --- Generate Album (create password & link) ---
app.post('/api/albums/:id/generate', requireAuth, (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) {
    return res.status(404).json({ error: 'Альбом не найден' });
  }

  const photoCount = db.prepare('SELECT COUNT(*) as count FROM photos WHERE album_id = ?').get(album.id);
  if (photoCount.count === 0) {
    return res.status(400).json({ error: 'Добавьте хотя бы одно фото перед генерацией' });
  }

  const password = generatePassword();
  const slug = generateSlug();

  db.prepare('UPDATE albums SET password = ?, slug = ?, is_generated = 1 WHERE id = ?').run(password, slug, album.id);

  const link = `${req.protocol}://${req.get('host')}/gallery/${slug}`;

  res.json({
    password,
    link,
    slug
  });
});

// --- Google Drive OAuth2 Setup ---
function getDriveOAuthConfig() {
  const envId = process.env.DRIVE_CLIENT_ID;
  const envSecret = process.env.DRIVE_CLIENT_SECRET;
  if (envId && envSecret) return { client_id: envId, client_secret: envSecret };

  const files = fs.readdirSync(__dirname).filter(f => f.startsWith('client_secret_') && f.endsWith('.json'));
  if (files.length > 0) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(__dirname, files[0]), 'utf-8'));
      const web = data.web || data.installed || data;
      return { client_id: web.client_id, client_secret: web.client_secret };
    } catch (e) { console.error('Failed to read OAuth config:', e.message); }
  }
  return null;
}

const driveConfig = getDriveOAuthConfig();
const DRIVE_CLIENT_ID = driveConfig?.client_id || '';
const DRIVE_CLIENT_SECRET = driveConfig?.client_secret || '';
const DRIVE_REDIRECT = process.env.DRIVE_REDIRECT || 'http://localhost:3000/api/drive/callback';

app.get('/api/drive/setup', (req, res) => {
  if (!DRIVE_CLIENT_ID) {
    return res.send(`
      <html><body style="background:#111;color:#fff;font-family:sans-serif;padding:40px;text-align:center">
        <h1>Настройка Google Drive</h1>
        <p>Положи файл <code>client_secret_*.json</code> в корень папки lensflow</p>
        <p>или укажите переменные окружения:</p>
        <pre style="background:#222;padding:20px;border-radius:12px;display:inline-block;text-align:left">
DRIVE_CLIENT_ID=ваш-client-id
DRIVE_CLIENT_SECRET=ваш-client-secret
        </pre>
        <p><a href="/" style="color:#73503C">Вернуться на главную</a></p>
      </body></html>
    `);
  }
  res.redirect('/api/drive/auth');
});

app.get('/api/drive/auth', (req, res) => {
  if (!DRIVE_CLIENT_ID) return res.redirect('/api/drive/setup');
  const oauth = new (require('googleapis').google.auth.OAuth2)(DRIVE_CLIENT_ID, DRIVE_CLIENT_SECRET, DRIVE_REDIRECT);
  const url = oauth.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.file'],
    prompt: 'consent',
  });
  res.redirect(url);
});

app.get('/api/drive/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('No code');

  try {
    const oauth = new (require('googleapis').google.auth.OAuth2)(DRIVE_CLIENT_ID, DRIVE_CLIENT_SECRET, DRIVE_REDIRECT);
    const { tokens } = await oauth.getToken(code);
    require('./drive').saveTokens(tokens, DRIVE_CLIENT_ID, DRIVE_CLIENT_SECRET);
    res.send(`
      <html><body style="background:#111;color:#fff;font-family:sans-serif;padding:40px;text-align:center">
        <h1>✅ Google Drive подключён!</h1>
        <p>Теперь файлы будут загружаться в ваш Google Drive.</p>
        <p><a href="/" style="color:#73503C">Вернуться на главную</a></p>
      </body></html>
    `);
  } catch (e) {
    res.status(500).send('Ошибка авторизации: ' + e.message);
  }
});

// --- Upload Photos ---
app.post('/api/albums/:id/photos', requireAuth, upload.array('photos', 500), async (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!album) {
    return res.status(404).json({ error: 'Альбом не найден' });
  }

  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'Выберите файлы для загрузки' });
  }

  const insert = db.prepare('INSERT INTO photos (album_id, filename, original_name, size, mime_type, drive_file_id) VALUES (?, ?, ?, ?, ?, ?)');
  const photos = [];

  for (const file of req.files) {
    const filePath = path.join(__dirname, 'uploads', 'albums', String(album.id), file.filename);

    const result = insert.run(album.id, file.filename, file.originalname, file.size, file.mimetype, '');

    // Queue Drive upload (async — браузер не ждёт)
    uploadQueue.add({
      filePath,
      fileName: file.originalname,
      albumId: album.id,
      albumTitle: album.title,
      photoId: result.lastInsertRowid,
    });

    // Auto-set first photo as cover
    if (!album.cover_photo_id) {
      db.prepare('UPDATE albums SET cover_photo_id = ? WHERE id = ?').run(result.lastInsertRowid, album.id);
      album.cover_photo_id = result.lastInsertRowid;
    }

    photos.push({
      id: result.lastInsertRowid,
      filename: file.filename,
      original_name: file.originalname,
      size: file.size,
      mime_type: file.mimetype,
      drive_file_id: ''
    });
  }

  res.json({ photos });
});

// Delete photo
app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const photo = db.prepare('SELECT p.* FROM photos p JOIN albums a ON p.album_id = a.id WHERE p.id = ? AND a.user_id = ?').get(req.params.id, req.session.userId);
  if (!photo) {
    return res.status(404).json({ error: 'Фото не найдено' });
  }

  const filePath = path.join(__dirname, 'uploads', 'albums', String(photo.album_id), photo.filename);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  if (photo.drive_file_id) {
    try { drive.deleteFile(photo.drive_file_id); } catch (e) { console.error('Drive delete failed:', e.message); }
  }

  db.prepare('DELETE FROM likes WHERE photo_id = ?').run(photo.id);
  db.prepare('DELETE FROM photos WHERE id = ?').run(photo.id);

  res.json({ ok: true });
});

// --- Public Gallery Routes ---
// Serve gallery photos (with Drive fallback)
app.get('/api/photo/:albumId/:filename', async (req, res) => {
  const { albumId, filename } = req.params;
  const filePath = path.join(__dirname, 'uploads', 'albums', albumId, filename);

  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }

  const photo = db.prepare('SELECT drive_file_id, original_name FROM photos WHERE album_id = ? AND filename = ?').get(albumId, filename);
  if (photo && photo.drive_file_id) {
    try {
      const stream = await drive.getFileStream(photo.drive_file_id);
      res.setHeader('Content-Type', 'image/jpeg');
      stream.pipe(res);
      return;
    } catch (e) {}
  }

  res.status(404).send('Not found');
});

app.get('/api/gallery/:slug', (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE slug = ? AND is_generated = 1').get(req.params.slug);
  if (!album) {
    return res.status(404).json({ error: 'Галерея не найдена' });
  }
  let coverFilename = null;
  if (album.cover_photo_id) {
    const cover = db.prepare('SELECT filename FROM photos WHERE id = ?').get(album.cover_photo_id);
    if (cover) coverFilename = cover.filename;
  }
  res.json({ album: { id: album.id, title: album.title, description: album.description, slug: album.slug, cover_filename: coverFilename } });
});

app.post('/api/gallery/:slug/verify', (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: 'Введите пароль' });
  }

  const fullAlbum = db.prepare('SELECT * FROM albums WHERE slug = ? AND is_generated = 1').get(req.params.slug);
  if (!fullAlbum) {
    return res.status(404).json({ error: 'Галерея не найдена' });
  }

  if (password !== fullAlbum.password) {
    return res.status(400).json({ error: 'Неверный пароль' });
  }

  const photos = db.prepare(`
    SELECT p.id, p.filename, p.original_name, p.size, p.downloads,
      (SELECT COUNT(*) FROM likes WHERE photo_id = p.id) as likes_count
    FROM photos p
    WHERE p.album_id = ?
    ORDER BY p.created_at ASC
  `).all(fullAlbum.id);
  const likedPhotos = db.prepare('SELECT photo_id FROM likes WHERE ip_address = ?').all(req.ip).map(l => l.photo_id);

  let coverFilename = null;
  if (fullAlbum.cover_photo_id) {
    const cover = db.prepare('SELECT filename FROM photos WHERE id = ?').get(fullAlbum.cover_photo_id);
    if (cover) coverFilename = cover.filename;
  }

  res.json({
    album: {
      id: fullAlbum.id,
      title: fullAlbum.title,
      description: fullAlbum.description,
      slug: fullAlbum.slug,
      cover_filename: coverFilename
    },
    photos,
    liked_photos: likedPhotos
  });
});

// --- Download All as ZIP ---
app.get('/api/gallery/:slug/download-all', (req, res) => {
  const album = db.prepare('SELECT * FROM albums WHERE slug = ? AND is_generated = 1').get(req.params.slug);
  if (!album) return res.status(404).json({ error: 'Галерея не найдена' });

  const dir = path.join(__dirname, 'uploads', 'albums', String(album.id));
  if (!fs.existsSync(dir)) return res.status(404).json({ error: 'Файлы не найдены' });

  const zipBuffer = createZipFromDir(dir, album.title.replace(/[^a-zA-Z0-9а-яА-ЯёЁ\s-]/g, '') + '/');
  const safeName = album.title.replace(/[^a-zA-Z0-9а-яА-ЯёЁ\s-]/g, '_') || 'album';

  res.set({
    'Content-Type': 'application/zip',
    'Content-Disposition': `attachment; filename="${safeName}.zip"`,
    'Content-Length': zipBuffer.length
  });
  res.send(zipBuffer);
});

app.post('/api/photos/:id/like', (req, res) => {
  const photo = db.prepare('SELECT * FROM photos WHERE id = ?').get(req.params.id);
  if (!photo) {
    return res.status(404).json({ error: 'Фото не найдено' });
  }

  try {
    db.prepare('INSERT INTO likes (photo_id, ip_address) VALUES (?, ?)').run(req.params.id, req.ip);
    const count = db.prepare('SELECT COUNT(*) as count FROM likes WHERE photo_id = ?').get(req.params.id);
    res.json({ liked: true, likes_count: count.count });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      db.prepare('DELETE FROM likes WHERE photo_id = ? AND ip_address = ?').run(req.params.id, req.ip);
      const count = db.prepare('SELECT COUNT(*) as count FROM likes WHERE photo_id = ?').get(req.params.id);
      res.json({ liked: false, likes_count: count.count });
    } else {
      res.status(500).json({ error: 'Ошибка' });
    }
  }
});

app.get('/api/photos/:id/download', async (req, res) => {
  const photo = db.prepare('SELECT p.*, a.slug FROM photos p JOIN albums a ON p.album_id = a.id WHERE p.id = ?').get(req.params.id);
  if (!photo) {
    return res.status(404).json({ error: 'Фото не найдено' });
  }

  db.prepare('UPDATE photos SET downloads = downloads + 1 WHERE id = ?').run(photo.id);

  const filePath = path.join(__dirname, 'uploads', 'albums', String(photo.album_id), photo.filename);
  if (fs.existsSync(filePath)) {
    return res.download(filePath, photo.original_name);
  }

  if (photo.drive_file_id) {
    try {
      const stream = await drive.getFileStream(photo.drive_file_id);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(photo.original_name)}"`);
      stream.pipe(res);
      return;
    } catch (e) {
      return res.status(404).json({ error: 'Файл не найден' });
    }
  }

  return res.status(404).json({ error: 'Файл не найден' });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    queue: uploadQueue.getQueueLength(),
    queue_active: uploadQueue.isWorking()
  });
});

// --- Error handling ---
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Файл слишком большой (макс. 100MB)' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(err.status || 400).json({ error: err.message });
  }
  next();
});

// Account page
app.get('/account', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'account.html'));
});

// Gallery route
app.get('/gallery/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'gallery.html'));
});

// SPA fallback: serve index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Auto-cleanup: delete photos older than 10 days from Drive
async function cleanupOldPhotos() {
  const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
  const oldPhotos = db.prepare("SELECT id, drive_file_id, filename, album_id FROM photos WHERE drive_file_id != '' AND created_at < ?").all(tenDaysAgo);

  for (const photo of oldPhotos) {
    const filePath = path.join(__dirname, 'uploads', 'albums', String(photo.album_id), photo.filename);
    try {
      await drive.deleteFile(photo.drive_file_id);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      db.prepare('UPDATE photos SET drive_file_id = ? WHERE id = ?').run('', photo.id);
      console.log('Cleaned up photo', photo.id, 'from Drive');
    } catch (e) {
      console.error('Cleanup failed for photo', photo.id, e.message);
    }
  }
}

setInterval(cleanupOldPhotos, 60 * 60 * 1000);
cleanupOldPhotos();

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err.message);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.message);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`LensFlow сервер запущен на порту ${PORT}`);
});
