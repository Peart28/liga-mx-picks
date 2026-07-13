const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

// ---------- DB ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

async function q(text, params) {
  const res = await pool.query(text, params);
  return res.rows;
}

// ---------- SCHEMA (se crea solo al arrancar) ----------
async function initSchema() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    apodo TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS jornadas (
    id TEXT PRIMARY KEY,
    matches JSONB DEFAULT '[]'
  )`);
  await q(`CREATE TABLE IF NOT EXISTS picks (
    username TEXT,
    jornada TEXT,
    match_id TEXT,
    pick TEXT,
    king BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (username, jornada, match_id)
  )`);
  await q(`CREATE TABLE IF NOT EXISTS teams (
    name TEXT PRIMARY KEY,
    logo_url TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS champions (
    id BIGSERIAL PRIMARY KEY,
    season TEXT NOT NULL,
    champion TEXT,
    runner_up TEXT,
    last_place TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS notifications (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS special_questions (
    id BIGSERIAL PRIMARY KEY,
    question TEXT NOT NULL,
    options JSONB DEFAULT '[]',
    points INT DEFAULT 1,
    correct_answer TEXT,
    sort_order INT DEFAULT 0
  )`);
  await q(`CREATE TABLE IF NOT EXISTS special_answers (
    username TEXT,
    question_id BIGINT,
    answer TEXT,
    PRIMARY KEY (username, question_id)
  )`);

  // Semillas
  const admins = await q(`SELECT username FROM users WHERE role='admin' LIMIT 1`);
  if (admins.length === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await q(`INSERT INTO users (username, password_hash, role) VALUES ($1,$2,'admin')
             ON CONFLICT (username) DO NOTHING`, ['admin', hash]);
    console.log('✓ Usuario admin creado (admin / admin123)');
  }
  await q(`INSERT INTO config (key, value) VALUES ('regCode','ligamx2026')
           ON CONFLICT (key) DO NOTHING`);
  await q(`INSERT INTO config (key, value) VALUES ('currentJornada', NULL)
           ON CONFLICT (key) DO NOTHING`);
  await q(`INSERT INTO config (key, value) VALUES ('specialDeadline', NULL)
           ON CONFLICT (key) DO NOTHING`);

  console.log('✓ Base de datos lista');
}

// ---------- AUTH ----------
async function auth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Sin sesión' });
  const rows = await q(`SELECT username FROM sessions WHERE token=$1`, [token]);
  if (!rows.length) return res.status(401).json({ error: 'Sesión expirada' });
  const users = await q(`SELECT username, role, apodo FROM users WHERE username=$1`, [rows[0].username]);
  if (!users.length) return res.status(401).json({ error: 'Usuario no existe' });
  req.user = users[0];
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  next();
}

const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e);
  res.status(500).json({ error: e.message });
});

// ---------- RUTAS PÚBLICAS ----------
app.post('/api/login', wrap(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!username || !password) return res.status(400).json({ error: 'Llena todos los campos' });

  const rows = await q(`SELECT * FROM users WHERE username=$1`, [username]);
  if (!rows.length) return res.status(401).json({ error: 'Usuario no encontrado' });

  const ok = await bcrypt.compare(password, rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });

  const token = crypto.randomBytes(24).toString('hex');
  await q(`INSERT INTO sessions (token, username) VALUES ($1,$2)`, [token, username]);
  res.json({ token, username, role: rows[0].role, apodo: rows[0].apodo || username });
}));

app.post('/api/register', wrap(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase().replace(/\s+/g, '_');
  const password = String(req.body.password || '');
  const code = String(req.body.code || '').trim();
  if (!username || !password || !code) return res.status(400).json({ error: 'Llena todos los campos' });

  const cfg = await q(`SELECT value FROM config WHERE key='regCode'`);
  if (!cfg.length || code !== cfg[0].value) return res.status(403).json({ error: 'Código de acceso incorrecto' });

  const exists = await q(`SELECT username FROM users WHERE username=$1`, [username]);
  if (exists.length) return res.status(409).json({ error: 'Ese usuario ya existe' });

  const hash = await bcrypt.hash(password, 10);
  await q(`INSERT INTO users (username, password_hash, role) VALUES ($1,$2,'user')`, [username, hash]);

  const token = crypto.randomBytes(24).toString('hex');
  await q(`INSERT INTO sessions (token, username) VALUES ($1,$2)`, [token, username]);
  res.json({ token, username, role: 'user', apodo: username });
}));

app.post('/api/logout', auth, wrap(async (req, res) => {
  await q(`DELETE FROM sessions WHERE token=$1`, [req.headers['x-auth-token']]);
  res.json({ ok: true });
}));

// ---------- DATOS ----------
app.get('/api/data', auth, wrap(async (req, res) => {
  const [jornadas, config, picks, users, teams, champions, specialQuestions, specialAnswers] = await Promise.all([
    q(`SELECT id, matches FROM jornadas ORDER BY id::int`),
    q(`SELECT key, value FROM config`),
    q(`SELECT username, jornada, match_id, pick, king FROM picks`),
    q(`SELECT username, role, apodo FROM users ORDER BY username`),
    q(`SELECT name, logo_url FROM teams ORDER BY name`),
    q(`SELECT * FROM champions ORDER BY id DESC`),
    q(`SELECT * FROM special_questions ORDER BY sort_order, id`),
    q(`SELECT username, question_id, answer FROM special_answers`)
  ]);
  const cfg = {};
  config.forEach(c => cfg[c.key] = c.value);

  // Ocultar respuestas de otros hasta que cierre el plazo
  const deadline = cfg.specialDeadline ? new Date(cfg.specialDeadline) : null;
  const specialsLocked = deadline ? new Date() >= deadline : false;
  const visibleAnswers = specialsLocked
    ? specialAnswers
    : specialAnswers.filter(a => a.username === req.user.username);

  res.json({
    jornadas, config: cfg, picks, users, teams, champions,
    specialQuestions, specialAnswers: visibleAnswers, specialsLocked
  });
}));

// ---------- PICKS ----------
app.post('/api/pick', auth, wrap(async (req, res) => {
  const { jornada, match_id, pick, king } = req.body;
  const username = req.user.username;

  // Bloquear si la jornada ya arrancó
  const jr = await q(`SELECT matches FROM jornadas WHERE id=$1`, [jornada]);
  if (jr.length) {
    const matches = jr[0].matches || [];
    const times = matches.map(m => m.datetime ? new Date(m.datetime) : null).filter(Boolean);
    if (times.length) {
      const first = times.reduce((a, b) => a < b ? a : b);
      if (new Date() >= first) return res.status(403).json({ error: 'La jornada ya cerró' });
    }
    const m = matches.find(x => x.id === match_id);
    if (m && m.result) return res.status(403).json({ error: 'Ese partido ya tiene resultado' });
  }

  await q(`INSERT INTO picks (username, jornada, match_id, pick, king)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (username, jornada, match_id)
           DO UPDATE SET pick=EXCLUDED.pick, king=EXCLUDED.king`,
    [username, jornada, match_id, pick, !!king]);
  res.json({ ok: true });
}));

// ---------- PREGUNTAS ESPECIALES ----------
async function specialsAreLocked() {
  const rows = await q(`SELECT value FROM config WHERE key='specialDeadline'`);
  if (!rows.length || !rows[0].value) return false;
  return new Date() >= new Date(rows[0].value);
}

app.post('/api/special/answer', auth, wrap(async (req, res) => {
  const { question_id, answer } = req.body;
  if (await specialsAreLocked()) {
    return res.status(403).json({ error: 'Las preguntas especiales ya cerraron' });
  }
  const qq = await q(`SELECT correct_answer FROM special_questions WHERE id=$1`, [question_id]);
  if (!qq.length) return res.status(404).json({ error: 'Pregunta no existe' });
  if (qq[0].correct_answer) return res.status(403).json({ error: 'Esa pregunta ya fue calificada' });

  await q(`INSERT INTO special_answers (username, question_id, answer)
           VALUES ($1,$2,$3)
           ON CONFLICT (username, question_id)
           DO UPDATE SET answer=EXCLUDED.answer`,
    [req.user.username, question_id, answer]);
  res.json({ ok: true });
}));

app.post('/api/admin/special', auth, adminOnly, wrap(async (req, res) => {
  const question = String(req.body.question || '').trim();
  const options = Array.isArray(req.body.options) ? req.body.options : [];
  const points = parseInt(req.body.points, 10) || 1;
  if (!question) return res.status(400).json({ error: 'Escribe la pregunta' });
  if (options.length < 2) return res.status(400).json({ error: 'Necesitas al menos 2 opciones' });
  await q(`INSERT INTO special_questions (question, options, points) VALUES ($1,$2,$3)`,
    [question, JSON.stringify(options), points]);
  res.json({ ok: true });
}));

app.post('/api/admin/special/correct', auth, adminOnly, wrap(async (req, res) => {
  const { id, correct_answer } = req.body;
  await q(`UPDATE special_questions SET correct_answer=$1 WHERE id=$2`,
    [correct_answer || null, id]);
  res.json({ ok: true });
}));

app.delete('/api/admin/special/:id', auth, adminOnly, wrap(async (req, res) => {
  await q(`DELETE FROM special_answers WHERE question_id=$1`, [req.params.id]);
  await q(`DELETE FROM special_questions WHERE id=$1`, [req.params.id]);
  res.json({ ok: true });
}));

// ---------- PERFIL ----------
app.post('/api/profile/apodo', auth, wrap(async (req, res) => {
  const apodo = String(req.body.apodo || '').trim().slice(0, 20);
  if (!apodo) return res.status(400).json({ error: 'Escribe un apodo' });
  await q(`UPDATE users SET apodo=$1 WHERE username=$2`, [apodo, req.user.username]);
  res.json({ ok: true, apodo });
}));

app.post('/api/profile/password', auth, wrap(async (req, res) => {
  const current = String(req.body.current || '');
  const nw = String(req.body.new || '');
  if (nw.length < 4) return res.status(400).json({ error: 'Mínimo 4 caracteres' });
  const rows = await q(`SELECT password_hash FROM users WHERE username=$1`, [req.user.username]);
  const ok = await bcrypt.compare(current, rows[0].password_hash);
  if (!ok) return res.status(403).json({ error: 'Contraseña actual incorrecta' });
  const hash = await bcrypt.hash(nw, 10);
  await q(`UPDATE users SET password_hash=$1 WHERE username=$2`, [hash, req.user.username]);
  res.json({ ok: true });
}));

// ---------- NOTIFICACIONES ----------
app.get('/api/notifications', auth, wrap(async (req, res) => {
  const rows = await q(
    `SELECT * FROM notifications WHERE username=$1 ORDER BY created_at DESC LIMIT 50`,
    [req.user.username]
  );
  res.json(rows);
}));

app.post('/api/notifications/self', auth, wrap(async (req, res) => {
  const message = String(req.body.message || '').slice(0, 300);
  if (!message) return res.status(400).json({ error: 'Mensaje vacío' });
  await q(`INSERT INTO notifications (username, message) VALUES ($1,$2)`, [req.user.username, message]);
  res.json({ ok: true });
}));

app.post('/api/notifications/read/:id', auth, wrap(async (req, res) => {
  await q(`UPDATE notifications SET read=TRUE WHERE id=$1 AND username=$2`,
    [req.params.id, req.user.username]);
  res.json({ ok: true });
}));

app.post('/api/notifications/read-all', auth, wrap(async (req, res) => {
  await q(`UPDATE notifications SET read=TRUE WHERE username=$1`, [req.user.username]);
  res.json({ ok: true });
}));

// ---------- ADMIN ----------
app.post('/api/admin/config', auth, adminOnly, wrap(async (req, res) => {
  const { key, value } = req.body;
  await q(`INSERT INTO config (key, value) VALUES ($1,$2)
           ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [key, value]);
  res.json({ ok: true });
}));

app.post('/api/admin/team', auth, adminOnly, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const logo_url = String(req.body.logo_url || '').trim() || null;
  if (!name) return res.status(400).json({ error: 'Nombre requerido' });
  await q(`INSERT INTO teams (name, logo_url) VALUES ($1,$2)
           ON CONFLICT (name) DO UPDATE SET logo_url=EXCLUDED.logo_url`, [name, logo_url]);
  res.json({ ok: true });
}));

app.delete('/api/admin/team/:name', auth, adminOnly, wrap(async (req, res) => {
  await q(`DELETE FROM teams WHERE name=$1`, [req.params.name]);
  res.json({ ok: true });
}));

app.post('/api/admin/jornada', auth, adminOnly, wrap(async (req, res) => {
  const { id, matches } = req.body;
  await q(`INSERT INTO jornadas (id, matches) VALUES ($1,$2)
           ON CONFLICT (id) DO UPDATE SET matches=EXCLUDED.matches`,
    [String(id), JSON.stringify(matches || [])]);
  res.json({ ok: true });
}));

app.delete('/api/admin/jornada/:id', auth, adminOnly, wrap(async (req, res) => {
  await q(`DELETE FROM jornadas WHERE id=$1`, [req.params.id]);
  await q(`DELETE FROM picks WHERE jornada=$1`, [req.params.id]);
  res.json({ ok: true });
}));

// Guardar resultado + generar notificaciones de Rey Pick fallado
app.post('/api/admin/result', auth, adminOnly, wrap(async (req, res) => {
  const { jornada, match_id, result } = req.body;

  const jr = await q(`SELECT matches FROM jornadas WHERE id=$1`, [jornada]);
  if (!jr.length) return res.status(404).json({ error: 'Jornada no existe' });

  const matches = jr[0].matches || [];
  const m = matches.find(x => x.id === match_id);
  if (!m) return res.status(404).json({ error: 'Partido no existe' });

  const wasEmpty = !m.result;
  m.result = result || null;
  await q(`UPDATE jornadas SET matches=$1 WHERE id=$2`, [JSON.stringify(matches), jornada]);

  // Notificar Rey Picks fallados (solo la primera vez que se guarda)
  if (result && wasEmpty) {
    const kings = await q(
      `SELECT username, pick FROM picks
       WHERE jornada=$1 AND match_id=$2 AND king=TRUE AND pick IS NOT NULL`,
      [jornada, match_id]
    );
    const allUsers = await q(`SELECT username, apodo FROM users`);

    for (const k of kings) {
      if (k.pick === result) continue;
      const team = k.pick === 'W' ? m.home : m.away;
      const apodo = (allUsers.find(u => u.username === k.username) || {}).apodo || k.username;

      await q(`INSERT INTO notifications (username, message) VALUES ($1,$2)`,
        [k.username, `💀 Fallaste tu Rey Pick con ${team} en la Jornada ${jornada}. −1 punto.`]);

      for (const u of allUsers) {
        if (u.username === k.username) continue;
        await q(`INSERT INTO notifications (username, message) VALUES ($1,$2)`,
          [u.username, `👑 ${apodo} falló su Rey Pick con ${team} en la Jornada ${jornada}.`]);
      }
    }
  }
  res.json({ ok: true });
}));

app.post('/api/admin/champion', auth, adminOnly, wrap(async (req, res) => {
  const { season, champion, runner_up, last_place } = req.body;
  if (!season || !champion) return res.status(400).json({ error: 'Temporada y campeón requeridos' });
  await q(`INSERT INTO champions (season, champion, runner_up, last_place) VALUES ($1,$2,$3,$4)`,
    [season, champion, runner_up || null, last_place || null]);
  res.json({ ok: true });
}));

app.delete('/api/admin/champion/:id', auth, adminOnly, wrap(async (req, res) => {
  await q(`DELETE FROM champions WHERE id=$1`, [req.params.id]);
  res.json({ ok: true });
}));

app.delete('/api/admin/user/:username', auth, adminOnly, wrap(async (req, res) => {
  const target = req.params.username;
  if (target === req.user.username) return res.status(400).json({ error: 'No puedes eliminarte' });
  const rows = await q(`SELECT role FROM users WHERE username=$1`, [target]);
  if (rows.length && rows[0].role === 'admin') return res.status(400).json({ error: 'No puedes eliminar a un admin' });
  await q(`DELETE FROM sessions WHERE username=$1`, [target]);
  await q(`DELETE FROM notifications WHERE username=$1`, [target]);
  await q(`DELETE FROM picks WHERE username=$1`, [target]);
  await q(`DELETE FROM users WHERE username=$1`, [target]);
  res.json({ ok: true });
}));

// ---------- SPA fallback ----------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- ARRANQUE ----------
initSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`⚽ Liga MX Picks corriendo en el puerto ${PORT}`));
  })
  .catch(e => {
    console.error('Error al iniciar la base de datos:', e);
    process.exit(1);
  });
