import os, sqlite3, random, string, zipfile, io, time, json
from datetime import datetime
from flask import Flask, request, session, jsonify, send_file, send_from_directory, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())

DB = 'lensflow.db'
UPLOADS = 'uploads'

os.makedirs(UPLOADS, exist_ok=True)

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db

def init_db():
    db = get_db()
    db.executescript('''
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
    ''')
    try: db.execute('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ""')
    except: pass
    try: db.execute('ALTER TABLE albums ADD COLUMN cover_photo_id INTEGER DEFAULT 0')
    except: pass
    try: db.execute('ALTER TABLE photos ADD COLUMN drive_file_id TEXT DEFAULT ""')
    except: pass
    db.execute("UPDATE users SET avatar='man.webp' WHERE gender='male' AND (avatar IS NULL OR avatar='')")
    db.execute("UPDATE users SET avatar='women.webp' WHERE gender='female' AND (avatar IS NULL OR avatar='')")
    db.commit()
    db.close()

init_db()

def gen_slug(): return ''.join(random.choices(string.ascii_letters + string.digits, k=8))
def gen_password():
    u,l,d = string.ascii_uppercase, string.ascii_lowercase, string.digits
    p = random.choice(u) + random.choice(l) + random.choice(d) + ''.join(random.choices(u+l+d, k=8))
    return ''.join(random.sample(p, len(p)))

def require_auth(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get('user_id'): return jsonify(error='Необходима авторизация'), 401
        return f(*a, **kw)
    return wrap

# --- Auth ---
@app.post('/api/register')
def register():
    d = request.json
    u, p, n, g = d.get('username',''), d.get('password',''), d.get('name',''), d.get('gender','')
    if not u or not p or not n: return jsonify(error='Заполните все поля'), 400
    if len(p) < 6: return jsonify(error='Пароль минимум 6 символов'), 400
    if len(u) < 3 or len(u) > 30: return jsonify(error='Логин 3-30 символов'), 400
    if not u.replace('_','').isalnum() or not u.isascii(): return jsonify(error='Логин: латиница, цифры, _'), 400
    db = get_db()
    if db.execute('SELECT id FROM users WHERE username=?', (u,)).fetchone():
        db.close(); return jsonify(error='Логин занят'), 400
    avatar = 'man.webp' if g == 'male' else 'women.webp' if g == 'female' else ''
    h = generate_password_hash(p)
    cur = db.execute('INSERT INTO users (username,password_hash,name,gender,avatar) VALUES (?,?,?,?,?)', (u,h,n,g,avatar))
    db.commit()
    user = dict(db.execute('SELECT id,username,name,gender,avatar,created_at FROM users WHERE id=?', (cur.lastrowid,)).fetchone())
    db.close()
    session['user_id'] = user['id']
    return jsonify(user=user)

@app.post('/api/login')
def login():
    d = request.json
    u, p = d.get('username',''), d.get('password','')
    if not u or not p: return jsonify(error='Заполните все поля'), 400
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
    if not row or not check_password_hash(row['password_hash'], p):
        db.close(); return jsonify(error='Неверный логин или пароль'), 400
    session['user_id'] = row['id']
    user = dict(row)
    del user['password_hash']
    db.close()
    return jsonify(user=user)

@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get('/api/me')
def me():
    uid = session.get('user_id')
    if not uid: return jsonify(error='Не авторизован'), 401
    db = get_db()
    row = db.execute('SELECT id,username,name,gender,avatar,created_at FROM users WHERE id=?', (uid,)).fetchone()
    db.close()
    return jsonify(user=dict(row)) if row else (jsonify(error=''), 404)

# --- Account ---
@app.put('/api/account')
@require_auth
def account():
    n = request.json.get('name','')
    if not n: return jsonify(error='Имя не может быть пустым'), 400
    db = get_db()
    db.execute('UPDATE users SET name=? WHERE id=?', (n, session['user_id']))
    db.commit()
    row = dict(db.execute('SELECT id,username,name,gender,avatar,created_at FROM users WHERE id=?', (session['user_id'],)).fetchone())
    db.close()
    return jsonify(user=row)

@app.put('/api/account/gender')
@require_auth
def account_gender():
    d = request.json
    g, a = d.get('gender',''), d.get('avatar','')
    db = get_db()
    db.execute('UPDATE users SET gender=?, avatar=? WHERE id=?', (g, a, session['user_id']))
    db.commit()
    row = dict(db.execute('SELECT id,username,name,gender,avatar,created_at FROM users WHERE id=?', (session['user_id'],)).fetchone())
    db.close()
    return jsonify(user=row)

# --- Admin ---
@app.post('/api/admin/login')
def admin_login():
    d = request.json
    if d.get('username')=='admin' and d.get('password')=='admin123':
        session['is_admin'] = True; return jsonify(ok=True)
    return jsonify(error='Неверный логин или пароль'), 400

def require_admin(f):
    @wraps(f)
    def wrap(*a,**kw):
        if not session.get('is_admin'): return jsonify(error='Требуется авторизация администратора'), 401
        return f(*a,**kw)
    return wrap

@app.get('/api/admin/stats')
@require_admin
def admin_stats():
    db = get_db()
    tu = db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    ta = db.execute('SELECT COUNT(*) as c FROM albums').fetchone()['c']
    tp = db.execute('SELECT COUNT(*) as c FROM photos').fetchone()['c']
    tl = db.execute('SELECT COUNT(*) as c FROM likes').fetchone()['c']
    td = db.execute('SELECT COALESCE(SUM(downloads),0) as s FROM photos').fetchone()['s']
    ts = db.execute('SELECT COALESCE(SUM(size),0) as s FROM photos').fetchone()['s']
    mc = db.execute("SELECT COUNT(*) as c FROM users WHERE gender='male'").fetchone()['c']
    fc = db.execute("SELECT COUNT(*) as c FROM users WHERE gender='female'").fetchone()['c']
    users = []
    for r in db.execute('''SELECT u.id, u.username, u.name, u.gender, u.created_at,
        (SELECT COUNT(*) FROM albums WHERE user_id = u.id) as album_count,
        (SELECT COUNT(*) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as photo_count,
        (SELECT COALESCE(SUM(p.downloads),0) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as total_downloads,
        (SELECT COALESCE(SUM(p.size),0) FROM photos p JOIN albums a ON p.album_id = a.id WHERE a.user_id = u.id) as total_storage
        FROM users u ORDER BY u.created_at DESC'''):
        users.append(dict(r))
    db.close()
    return jsonify(total_users=tu, total_albums=ta, total_photos=tp, total_likes=tl, total_downloads=td, total_size=ts,
                   male_count=mc, female_count=fc, users=users)

@app.post('/api/admin/logout')
def admin_logout():
    session['is_admin'] = False
    return jsonify(ok=True)

# --- Albums ---
@app.post('/api/albums')
@require_auth
def create_album():
    d = request.json
    t, desc = d.get('title',''), d.get('description','')
    if not t: return jsonify(error='Укажите название'), 400
    slug = gen_slug()
    db = get_db()
    cur = db.execute('INSERT INTO albums (user_id,title,description,slug) VALUES (?,?,?,?)',
                     (session['user_id'], t, desc, slug))
    db.commit()
    album = dict(db.execute('SELECT * FROM albums WHERE id=?', (cur.lastrowid,)).fetchone())
    db.close()
    return jsonify(album=album)

@app.get('/api/albums')
@require_auth
def list_albums():
    db = get_db()
    albums = []
    for a in db.execute('SELECT * FROM albums WHERE user_id=? ORDER BY created_at DESC', (session['user_id'],)):
        a = dict(a)
        a['photo_count'] = db.execute('SELECT COUNT(*) as c FROM photos WHERE album_id=?', (a['id'],)).fetchone()['c']
        td = db.execute('SELECT COALESCE(SUM(downloads),0) as s FROM photos WHERE album_id=?', (a['id'],)).fetchone()['s']
        a['total_downloads'] = td
        a['cover_filename'] = None
        if a['cover_photo_id']:
            c = db.execute('SELECT filename FROM photos WHERE id=?', (a['cover_photo_id'],)).fetchone()
            if c: a['cover_filename'] = c['filename']
        albums.append(a)
    db.close()
    return jsonify(albums=albums)

@app.get('/api/albums/<int:aid>')
@require_auth
def get_album(aid):
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE id=? AND user_id=?', (aid, session['user_id'])).fetchone()
    if not a: db.close(); return jsonify(error='Альбом не найден'), 404
    a = dict(a)
    photos = [dict(p) for p in db.execute('SELECT * FROM photos WHERE album_id=? ORDER BY created_at DESC', (aid,))]
    a['cover_filename'] = None
    if a['cover_photo_id']:
        c = db.execute('SELECT filename FROM photos WHERE id=?', (a['cover_photo_id'],)).fetchone()
        if c: a['cover_filename'] = c['filename']
    db.close()
    return jsonify(album=a, photos=photos)

@app.delete('/api/albums/<int:aid>')
@require_auth
def delete_album(aid):
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE id=? AND user_id=?', (aid, session['user_id'])).fetchone()
    if not a: db.close(); return jsonify(error='Альбом не найден'), 404
    adir = os.path.join(UPLOADS, 'albums', str(aid))
    if os.path.exists(adir):
        import shutil
        shutil.rmtree(adir, ignore_errors=True)
    db.execute('DELETE FROM likes WHERE photo_id IN (SELECT id FROM photos WHERE album_id=?)', (aid,))
    db.execute('DELETE FROM photos WHERE album_id=?', (aid,))
    db.execute('DELETE FROM albums WHERE id=?', (aid,))
    db.commit()
    db.close()
    return jsonify(ok=True)

@app.put('/api/albums/<int:aid>/cover')
@require_auth
def set_cover(aid):
    d = request.json
    pid = d.get('photo_id')
    if not pid: return jsonify(error='Укажите photo_id'), 400
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE id=? AND user_id=?', (aid, session['user_id'])).fetchone()
    if not a: db.close(); return jsonify(error='Альбом не найден'), 404
    p = db.execute('SELECT * FROM photos WHERE id=? AND album_id=?', (pid, aid)).fetchone()
    if not p: db.close(); return jsonify(error='Фото не найдено'), 404
    db.execute('UPDATE albums SET cover_photo_id=? WHERE id=?', (pid, aid))
    db.commit()
    db.close()
    return jsonify(cover_photo_id=pid, filename=p['filename'])

@app.post('/api/albums/<int:aid>/generate')
@require_auth
def generate_album(aid):
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE id=? AND user_id=?', (aid, session['user_id'])).fetchone()
    if not a: db.close(); return jsonify(error='Альбом не найден'), 404
    pc = db.execute('SELECT COUNT(*) as c FROM photos WHERE album_id=?', (aid,)).fetchone()['c']
    if pc == 0: db.close(); return jsonify(error='Добавьте хотя бы одно фото'), 400
    pwd = gen_password()
    slug = gen_slug()
    db.execute('UPDATE albums SET password=?, slug=?, is_generated=1 WHERE id=?', (pwd, slug, aid))
    db.commit()
    db.close()
    link = f"{request.host_url}gallery/{slug}"
    return jsonify(password=pwd, link=link, slug=slug)

# --- Upload Photos ---
ALLOWED = {'.jpg','.jpeg','.png','.gif','.webp','.avif','.tiff','.raw','.cr2','.nef','.arw','.dng'}

@app.post('/api/albums/<int:aid>/photos')
@require_auth
def upload_photos(aid):
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE id=? AND user_id=?', (aid, session['user_id'])).fetchone()
    if not a: db.close(); return jsonify(error='Альбом не найден'), 404

    files = request.files.getlist('photos')
    if not files or all(not f.filename for f in files):
        db.close(); return jsonify(error='Выберите файлы'), 400

    adir = os.path.join(UPLOADS, 'albums', str(aid))
    os.makedirs(adir, exist_ok=True)
    photos = []
    cover_id = a['cover_photo_id']

    for f in files:
        if not f.filename: continue
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in ALLOWED:
            return jsonify(error=f'Недопустимый формат: {ext}'), 400
        name = os.urandom(16).hex() + ext
        f.save(os.path.join(adir, name))
        cur = db.execute('INSERT INTO photos (album_id,filename,original_name,size,mime_type,drive_file_id) VALUES (?,?,?,?,?,?)',
                         (aid, name, f.filename, 0, f.content_type or '', ''))
        pid = cur.lastrowid
        if not cover_id:
            db.execute('UPDATE albums SET cover_photo_id=? WHERE id=?', (pid, aid))
            cover_id = pid
        photos.append({'id': pid, 'filename': name, 'original_name': f.filename, 'size': 0,
                       'mime_type': f.content_type or '', 'drive_file_id': ''})
    db.commit()
    db.close()
    return jsonify(photos=photos)

@app.delete('/api/photos/<int:pid>')
@require_auth
def delete_photo(pid):
    db = get_db()
    p = db.execute('SELECT p.* FROM photos p JOIN albums a ON p.album_id=a.id WHERE p.id=? AND a.user_id=?',
                   (pid, session['user_id'])).fetchone()
    if not p: db.close(); return jsonify(error='Фото не найдено'), 404
    fp = os.path.join(UPLOADS, 'albums', str(p['album_id']), p['filename'])
    if os.path.exists(fp): os.remove(fp)
    db.execute('DELETE FROM likes WHERE photo_id=?', (pid,))
    db.execute('DELETE FROM photos WHERE id=?', (pid,))
    db.commit()
    db.close()
    return jsonify(ok=True)

# --- Gallery ---
@app.get('/api/photo/<int:aid>/<filename>')
def serve_photo(aid, filename):
    fp = os.path.join(UPLOADS, 'albums', str(aid), filename)
    if os.path.exists(fp): return send_file(fp)
    return 'Not found', 404

@app.get('/api/gallery/<slug>')
def gallery_info(slug):
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE slug=? AND is_generated=1', (slug,)).fetchone()
    if not a: db.close(); return jsonify(error='Галерея не найдена'), 404
    a = dict(a)
    cf = None
    if a['cover_photo_id']:
        c = db.execute('SELECT filename FROM photos WHERE id=?', (a['cover_photo_id'],)).fetchone()
        if c: cf = c['filename']
    db.close()
    return jsonify(album={'id': a['id'], 'title': a['title'], 'description': a['description'],
                          'slug': a['slug'], 'cover_filename': cf})

@app.post('/api/gallery/<slug>/verify')
def gallery_verify(slug):
    d = request.json
    pwd = d.get('password','')
    if not pwd: return jsonify(error='Введите пароль'), 400
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE slug=? AND is_generated=1', (slug,)).fetchone()
    if not a: db.close(); return jsonify(error='Галерея не найдена'), 404
    if pwd != a['password']: db.close(); return jsonify(error='Неверный пароль'), 400

    photos = []
    for p in db.execute('''SELECT p.id, p.filename, p.original_name, p.size, p.downloads,
        (SELECT COUNT(*) FROM likes WHERE photo_id=p.id) as likes_count
        FROM photos p WHERE p.album_id=? ORDER BY p.created_at ASC''', (a['id'],)):
        photos.append(dict(p))

    ip = request.remote_addr
    liked = [r['photo_id'] for r in db.execute('SELECT photo_id FROM likes WHERE ip_address=?', (ip,))]
    cf = None
    if a['cover_photo_id']:
        c = db.execute('SELECT filename FROM photos WHERE id=?', (a['cover_photo_id'],)).fetchone()
        if c: cf = c['filename']
    db.close()
    return jsonify(album={'id': a['id'], 'title': a['title'], 'description': a['description'],
                          'slug': a['slug'], 'cover_filename': cf},
                   photos=photos, liked_photos=liked)

@app.get('/api/gallery/<slug>/download-all')
def gallery_download_all(slug):
    db = get_db()
    a = db.execute('SELECT * FROM albums WHERE slug=? AND is_generated=1', (slug,)).fetchone()
    db.close()
    if not a: return jsonify(error='Галерея не найдена'), 404
    adir = os.path.join(UPLOADS, 'albums', str(a['id']))
    if not os.path.exists(adir): return jsonify(error='Файлы не найдены'), 404

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fn in os.listdir(adir):
            if os.path.isfile(os.path.join(adir, fn)):
                zf.write(os.path.join(adir, fn), fn)
    buf.seek(0)
    safe = ''.join(c for c in a['title'] if c.isalnum() or c in ' _-') or 'album'
    return send_file(buf, mimetype='application/zip', as_attachment=True, download_name=f'{safe}.zip')

@app.post('/api/photos/<int:pid>/like')
def like_photo(pid):
    db = get_db()
    p = db.execute('SELECT * FROM photos WHERE id=?', (pid,)).fetchone()
    if not p: db.close(); return jsonify(error='Фото не найдено'), 404
    ip = request.remote_addr
    try:
        db.execute('INSERT INTO likes (photo_id, ip_address) VALUES (?,?)', (pid, ip))
        db.commit()
        c = db.execute('SELECT COUNT(*) as c FROM likes WHERE photo_id=?', (pid,)).fetchone()['c']
        db.close()
        return jsonify(liked=True, likes_count=c)
    except sqlite3.IntegrityError:
        db.execute('DELETE FROM likes WHERE photo_id=? AND ip_address=?', (pid, ip))
        db.commit()
        c = db.execute('SELECT COUNT(*) as c FROM likes WHERE photo_id=?', (pid,)).fetchone()['c']
        db.close()
        return jsonify(liked=False, likes_count=c)

@app.get('/api/photos/<int:pid>/download')
def download_photo(pid):
    db = get_db()
    p = db.execute('SELECT p.* FROM photos p WHERE p.id=?', (pid,)).fetchone()
    if not p: db.close(); return jsonify(error='Фото не найдено'), 404
    db.execute('UPDATE photos SET downloads=downloads+1 WHERE id=?', (pid,))
    db.commit()
    db.close()
    fp = os.path.join(UPLOADS, 'albums', str(p['album_id']), p['filename'])
    if os.path.exists(fp):
        return send_file(fp, as_attachment=True, download_name=p['original_name'])
    return jsonify(error='Файл не найден'), 404

# --- Pages ---
@app.get('/api/health')
def health():
    return jsonify(status='ok', uptime=time.time())

@app.get('/')
def index():
    return send_from_directory('public', 'index.html')

@app.get('/<path:name>')
def serve_static(name):
    fp = os.path.join('public', name)
    if os.path.isfile(fp): return send_file(fp)
    return send_from_directory('public', 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 80))
    print(f'LensFlow запущен на порту {port}')
    app.run(host='0.0.0.0', port=port, debug=False)
