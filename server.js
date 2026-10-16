/* =========================================================
   NVINH NOVA — KEY SERVER (ALL-IN-ONE)
   Bao gồm: DB, JWT, API, Admin Panel (nhúng inline)
   Chạy: npm start
   ========================================================= */
require('dotenv').config();

const crypto    = require('crypto');
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const morgan    = require('morgan');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool }  = require('pg');

/* =========================================================
   1. DATABASE
   ========================================================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys (
      id SERIAL PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      label TEXT DEFAULT '',
      duration_days INTEGER DEFAULT 30,
      max_devices INTEGER DEFAULT 1,
      is_active INTEGER DEFAULT 1,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      expires_at BIGINT,
      activated_at BIGINT,
      used_count INTEGER DEFAULT 0,
      last_used_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,
      key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      first_seen BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      last_seen BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      user_agent TEXT,
      ip TEXT,
      UNIQUE(key_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      key_id INTEGER REFERENCES keys(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      device_id TEXT,
      ip TEXT,
      detail TEXT,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
    );

    CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
    CREATE INDEX IF NOT EXISTS idx_devices_key_id ON devices(key_id);
    CREATE INDEX IF NOT EXISTS idx_logs_key_id ON logs(key_id);
  `);
  console.log('✅ Database khởi tạo xong');
}

/* =========================================================
   2. HELPERS
   ========================================================= */
function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 4 }, () =>
    chars[crypto.randomInt(0, chars.length)]
  ).join('');
  return [seg(), seg(), seg(), seg()].join('-');
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  });
}

function verifyToken(token) {
  try { return jwt.verify(token, process.env.JWT_SECRET); }
  catch { return null; }
}

async function logAction(keyId, action, deviceId, ip, detail) {
  try {
    await pool.query(
      `INSERT INTO logs (key_id, action, device_id, ip, detail)
       VALUES ($1, $2, $3, $4, $5)`,
      [keyId, action, deviceId, ip, detail]
    );
  } catch (_) {}
}

/* =========================================================
   3. APP
   ========================================================= */
const app = express();
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));

// CORS
const origins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (origins.includes(origin) || origins.includes('*')) return cb(null, true);
    cb(new Error('CORS blocked: ' + origin));
  },
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id', 'X-Admin-Secret']
}));

if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'));

/* =========================================================
   4. RATE LIMIT
   ========================================================= */
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  skipSuccessfulRequests: true
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200
});

app.use('/api/', generalLimiter);

/* =========================================================
   5. MIDDLEWARE
   ========================================================= */
function requireAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ ok: false, message: 'Không có quyền' });
  }
  next();
}

function requireToken(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, message: 'Thiếu token' });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ ok: false, message: 'Token không hợp lệ' });

  req.user = payload;
  next();
}

/* =========================================================
   6. PUBLIC ROUTES
   ========================================================= */
app.get('/', (req, res) => {
  res.json({ ok: true, service: 'NVINH NOVA Key Server', version: '1.0.0' });
});

app.get('/health', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// POST /api/verify-key
app.post('/api/verify-key', verifyLimiter, async (req, res) => {
  const { key } = req.body || {};
  const deviceId = String(req.headers['x-device-id'] || '').trim();
  const ip = req.ip;
  const ua = req.headers['user-agent'] || '';

  if (!key || typeof key !== 'string') {
    return res.status(400).json({ ok: false, valid: false, message: 'Thiếu key' });
  }

  const cleanKey = key.trim().toUpperCase();

  try {
    const { rows } = await pool.query('SELECT * FROM keys WHERE key = $1', [cleanKey]);
    const row = rows[0];

    if (!row) {
      await logAction(null, 'verify_fail', deviceId, ip, 'Key không tồn tại');
      return res.status(404).json({ ok: false, valid: false, message: 'Key không tồn tại' });
    }

    if (!row.is_active) {
      await logAction(row.id, 'verify_fail', deviceId, ip, 'Key bị vô hiệu');
      return res.status(403).json({ ok: false, valid: false, message: 'Key đã bị vô hiệu hoá' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && Number(row.expires_at) < now) {
      await logAction(row.id, 'verify_fail', deviceId, ip, 'Key hết hạn');
      return res.status(403).json({ ok: false, valid: false, message: 'Key đã hết hạn' });
    }

    // Device lock
    const deviceLock = process.env.DEVICE_LOCK_ENABLED === 'true';
    if (deviceLock && deviceId) {
      const { rows: devs } = await pool.query(
        'SELECT device_id FROM devices WHERE key_id = $1', [row.id]
      );
      const isKnown = devs.some(d => d.device_id === deviceId);

      if (!isKnown) {
        if (devs.length >= row.max_devices) {
          await logAction(row.id, 'verify_fail', deviceId, ip, 'Vượt số thiết bị');
          return res.status(403).json({
            ok: false, valid: false,
            message: `Key đã dùng trên ${row.max_devices} thiết bị khác`
          });
        }
        await pool.query(
          `INSERT INTO devices (key_id, device_id, user_agent, ip)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (key_id, device_id) DO NOTHING`,
          [row.id, deviceId, ua, ip]
        );
      } else {
        await pool.query(
          'UPDATE devices SET last_seen = $1 WHERE key_id = $2 AND device_id = $3',
          [now, row.id, deviceId]
        );
      }
    }

    // Kích hoạt lần đầu
    if (!row.activated_at && row.duration_days > 0) {
      const expires = now + row.duration_days * 86400;
      await pool.query(
        'UPDATE keys SET activated_at = $1, expires_at = $2 WHERE id = $3',
        [now, expires, row.id]
      );
      row.activated_at = now;
      row.expires_at = expires;
    }

    await pool.query(
      'UPDATE keys SET used_count = used_count + 1, last_used_at = $1 WHERE id = $2',
      [now, row.id]
    );

    await logAction(row.id, 'verify_ok', deviceId, ip, 'Thành công');

    const token = signToken({ keyId: row.id, key: row.key, label: row.label });

    res.json({
      ok: true,
      valid: true,
      token,
      expires_at: row.expires_at,
      label: row.label
    });
  } catch (e) {
    console.error('[verify-key]', e);
    res.status(500).json({ ok: false, valid: false, message: 'Lỗi server' });
  }
});

// POST /api/heartbeat
app.post('/api/heartbeat', requireToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM keys WHERE id = $1', [req.user.keyId]);
    const row = rows[0];

    if (!row || !row.is_active) {
      return res.status(403).json({ ok: false, valid: false, message: 'Key bị vô hiệu' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && Number(row.expires_at) < now) {
      return res.status(403).json({ ok: false, valid: false, message: 'Key hết hạn' });
    }

    res.json({ ok: true, valid: true, expires_at: row.expires_at });
  } catch (e) {
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

/* =========================================================
   7. ADMIN ROUTES
   ========================================================= */
const adminRouter = express.Router();
adminRouter.use(requireAdmin);
adminRouter.use(adminLimiter);

// Tạo key
adminRouter.post('/create-key', async (req, res) => {
  const {
    label = '',
    duration_days = 30,
    max_devices = 1,
    count = 1
  } = req.body || {};

  const n = Math.min(100, Math.max(1, parseInt(count) || 1));
  const created = [];

  try {
    for (let i = 0; i < n; i++) {
      let newKey, attempts = 0;
      do {
        newKey = generateKey();
        if (++attempts > 10) throw new Error('Không sinh được key unique');
        const { rows } = await pool.query('SELECT 1 FROM keys WHERE key = $1', [newKey]);
        if (rows.length === 0) break;
      } while (true);

      await pool.query(
        `INSERT INTO keys (key, label, duration_days, max_devices)
         VALUES ($1, $2, $3, $4)`,
        [newKey, label, duration_days, max_devices]
      );
      created.push(newKey);
    }

    res.json({ ok: true, keys: created });
  } catch (e) {
    console.error('[create-key]', e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Danh sách key
adminRouter.get('/keys', async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 50));
  const offset = (page - 1) * limit;
  const search = (req.query.search || '').trim().toUpperCase();

  try {
    let whereClause = '';
    let params = [];

    if (search) {
      whereClause = 'WHERE key LIKE $1 OR label LIKE $1';
      params.push(`%${search}%`);
    }

    const totalQ = await pool.query(
      `SELECT COUNT(*) AS c FROM keys ${whereClause}`, params
    );
    const total = parseInt(totalQ.rows[0].c);

    const rowsQ = await pool.query(
      `SELECT k.*,
        (SELECT COUNT(*) FROM devices d WHERE d.key_id = k.id) AS device_count
       FROM keys k
       ${whereClause}
       ORDER BY k.created_at DESC
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    res.json({
      ok: true,
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
      keys: rowsQ.rows
    });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Thống kê
adminRouter.get('/stats', async (req, res) => {
  try {
    const totalQ = await pool.query('SELECT COUNT(*) AS c FROM keys');
    const activeQ = await pool.query('SELECT COUNT(*) AS c FROM keys WHERE is_active = 1');
    const usedQ = await pool.query('SELECT COUNT(*) AS c FROM keys WHERE used_count > 0');
    const expiringQ = await pool.query(
      `SELECT COUNT(*) AS c FROM keys
       WHERE expires_at IS NOT NULL
       AND expires_at > EXTRACT(EPOCH FROM NOW())
       AND expires_at < EXTRACT(EPOCH FROM NOW()) + 86400 * 7`
    );

    res.json({
      ok: true,
      stats: {
        total: parseInt(totalQ.rows[0].c),
        active: parseInt(activeQ.rows[0].c),
        used: parseInt(usedQ.rows[0].c),
        expiring_soon: parseInt(expiringQ.rows[0].c)
      }
    });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Thu hồi
adminRouter.post('/revoke', async (req, res) => {
  try {
    const r = await pool.query(
      'UPDATE keys SET is_active = 0 WHERE key = $1',
      [String(req.body?.key || '').toUpperCase()]
    );
    if (r.rowCount === 0) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Bỏ thu hồi
adminRouter.post('/unrevoke', async (req, res) => {
  try {
    const r = await pool.query(
      'UPDATE keys SET is_active = 1 WHERE key = $1',
      [String(req.body?.key || '').toUpperCase()]
    );
    if (r.rowCount === 0) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Reset thiết bị
adminRouter.post('/reset-devices', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id FROM keys WHERE key = $1',
      [String(req.body?.key || '').toUpperCase()]
    );
    if (!rows[0]) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    await pool.query('DELETE FROM devices WHERE key_id = $1', [rows[0].id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Xoá 1 key
adminRouter.delete('/delete', async (req, res) => {
  try {
    const r = await pool.query(
      'DELETE FROM keys WHERE key = $1',
      [String(req.body?.key || '').toUpperCase()]
    );
    if (r.rowCount === 0) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Xoá nhiều key
adminRouter.post('/delete-batch', async (req, res) => {
  const { keys = [] } = req.body || {};
  if (!Array.isArray(keys) || keys.length === 0) {
    return res.status(400).json({ ok: false, message: 'Danh sách rỗng' });
  }
  try {
    const clean = keys.map(k => String(k).toUpperCase());
    const r = await pool.query(
      'DELETE FROM keys WHERE key = ANY($1::text[])',
      [clean]
    );
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Xoá toàn bộ key đã dùng
adminRouter.post('/delete-used', async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM keys WHERE used_count > 0');
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Xoá key hết hạn
adminRouter.post('/delete-expired', async (req, res) => {
  try {
    const r = await pool.query(
      `DELETE FROM keys
       WHERE expires_at IS NOT NULL
       AND expires_at < EXTRACT(EPOCH FROM NOW())`
    );
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Logs
adminRouter.get('/logs', async (req, res) => {
  const limit = Math.min(500, parseInt(req.query.limit) || 100);
  try {
    let rows;
    if (req.query.key) {
      const r = await pool.query(
        'SELECT id FROM keys WHERE key = $1',
        [String(req.query.key).toUpperCase()]
      );
      if (!r.rows[0]) return res.json({ ok: true, logs: [] });
      const l = await pool.query(
        'SELECT * FROM logs WHERE key_id = $1 ORDER BY created_at DESC LIMIT $2',
        [r.rows[0].id, limit]
      );
      rows = l.rows;
    } else {
      const l = await pool.query(
        'SELECT * FROM logs ORDER BY created_at DESC LIMIT $1',
        [limit]
      );
      rows = l.rows;
    }
    res.json({ ok: true, logs: rows });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

app.use('/api/admin', adminRouter);

/* =========================================================
   8. ADMIN PANEL (nhúng inline)
   ========================================================= */
const ADMIN_HTML = `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>NOVA ADMIN — Key Manager</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(circle at top,#1a0308,#050103 60%,#000);color:#fff;min-height:100vh;padding:20px}
.wrap{max-width:1200px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:center;padding-bottom:20px;border-bottom:1px solid rgba(255,48,70,.3);margin-bottom:24px;flex-wrap:wrap;gap:12px}
h1{font-size:24px;font-weight:900;font-style:italic;letter-spacing:.08em;color:#fff;text-shadow:0 0 8px rgba(255,40,20,.6)}
h1 b{color:#ff3d55}
.badge{font-size:11px;padding:6px 12px;border-radius:999px;background:rgba(255,40,60,.1);border:1px solid rgba(255,50,70,.4);color:#ff8d9a;font-weight:700;letter-spacing:.1em}
.login-card{max-width:400px;margin:80px auto;padding:32px;background:linear-gradient(155deg,rgba(30,3,10,.96),rgba(8,0,3,.98));border:1px solid rgba(255,48,70,.35);border-radius:20px;box-shadow:0 0 40px rgba(255,20,45,.2)}
.login-card h2{text-align:center;margin-bottom:20px;font-size:18px;color:#ff5265}
.login-card input{width:100%;padding:14px;margin-bottom:12px;background:linear-gradient(145deg,#13050a,#050103);border:1px solid rgba(255,48,70,.45);border-radius:10px;color:#fff;font-size:14px;letter-spacing:.1em;outline:none}
.login-card input:focus{border-color:#ff0044;box-shadow:0 0 12px rgba(255,0,68,.3)}
.login-card button{width:100%;padding:14px;border:0;border-radius:10px;cursor:pointer;background:linear-gradient(105deg,#b00020,#ff0044,#b00020);background-size:200% 100%;color:#fff;font-weight:900;letter-spacing:.15em;font-size:13px;box-shadow:0 0 22px rgba(255,0,68,.45)}
#panel{display:none}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat{padding:16px;border-radius:14px;text-align:center;background:linear-gradient(145deg,rgba(30,4,7,.95),rgba(7,2,3,.96));border:1px solid rgba(255,35,35,.35)}
.stat .label{font-size:10px;letter-spacing:.15em;color:#ff7d82;font-weight:800}
.stat .value{font-size:26px;font-weight:900;color:#fff;margin-top:6px;text-shadow:0 0 10px rgba(255,40,40,.6)}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;padding:14px;border-radius:14px;background:linear-gradient(145deg,rgba(18,0,0,.6),rgba(4,4,4,.6));border:1px solid rgba(255,0,0,.2)}
.toolbar input{padding:10px 14px;border-radius:10px;background:#050103;border:1px solid rgba(255,48,70,.4);color:#fff;font-size:13px;outline:none}
.toolbar input:focus{border-color:#ff0044}
.toolbar button{padding:10px 18px;border:0;border-radius:10px;cursor:pointer;font-weight:800;font-size:12px;letter-spacing:.08em;transition:.2s}
.btn-primary{background:linear-gradient(105deg,#b00020,#ff0044);color:#fff;box-shadow:0 0 14px rgba(255,0,68,.4)}
.btn-primary:hover{filter:brightness(1.15)}
.btn-danger{background:linear-gradient(105deg,#3a0008,#7a0015);color:#fff;border:1px solid #ff3d55}
.btn-danger:hover{filter:brightness(1.2)}
.btn-ghost{background:transparent;border:1px solid rgba(255,48,70,.4);color:#ff8d9a}
.btn-ghost:hover{background:rgba(255,40,60,.08);color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px;background:rgba(0,0,0,.2);border-radius:14px;overflow:hidden}
th{padding:12px;text-align:left;font-size:11px;letter-spacing:.12em;color:#ff8d9a;font-weight:800;background:rgba(0,0,0,.4);border-bottom:1px solid rgba(255,48,70,.3)}
td{padding:12px;border-bottom:1px solid rgba(255,0,0,.1)}
tr:hover{background:rgba(255,0,0,.04)}
.key-cell{font-family:'Consolas',monospace;font-weight:700;letter-spacing:.08em;color:#fff}
.status{display:inline-block;padding:4px 10px;border-radius:999px;font-size:10px;font-weight:900;letter-spacing:.08em}
.status.on{background:rgba(74,222,128,.15);color:#4ade80;border:1px solid rgba(74,222,128,.4)}
.status.off{background:rgba(255,80,80,.15);color:#ff5566;border:1px solid rgba(255,80,80,.4)}
.status.expired{background:rgba(255,180,60,.15);color:#ffb43c;border:1px solid rgba(255,180,60,.4)}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.actions button{padding:6px 10px;border-radius:8px;border:1px solid rgba(255,48,70,.4);background:rgba(20,0,5,.6);color:#ff8d9a;font-size:11px;font-weight:800;cursor:pointer;transition:.15s}
.actions button:hover{background:rgba(255,40,60,.15);color:#fff;border-color:#ff3d55}
.pagination{display:flex;justify-content:center;gap:8px;margin-top:20px;padding-top:20px;border-top:1px solid rgba(255,0,0,.15)}
.pagination button{padding:8px 14px;border-radius:8px;background:rgba(20,0,5,.6);border:1px solid rgba(255,48,70,.4);color:#ff8d9a;font-weight:700;cursor:pointer}
.pagination button.active{background:linear-gradient(105deg,#b00020,#ff0044);color:#fff}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);background:linear-gradient(145deg,#050505,#120000);color:#fff;padding:14px 24px;border-radius:12px;font-weight:700;font-size:13px;border:1px solid rgba(255,0,0,.5);box-shadow:0 0 20px rgba(255,0,0,.4);opacity:0;transition:.3s;pointer-events:none;z-index:9999}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{border-color:rgba(255,80,80,.6);box-shadow:0 0 20px rgba(255,80,80,.5)}
@media(max-width:640px){.stats{grid-template-columns:repeat(2,1fr)}table{font-size:11px}th,td{padding:8px}.toolbar{flex-direction:column}.toolbar > *{width:100%!important;min-width:0!important}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>N <b>VINH</b> NOVA <span style="font-style:normal;font-size:14px;color:#ff7d82;letter-spacing:.15em">ADMIN</span></h1>
    <span class="badge" id="serverStatus">● CONNECTING...</span>
  </header>

  <div class="login-card" id="loginCard">
    <h2>🔐 NHẬP ADMIN SECRET</h2>
    <input type="password" id="secretInput" placeholder="ADMIN_SECRET..." autocomplete="off" />
    <button onclick="doLogin()">ĐĂNG NHẬP</button>
  </div>

  <div id="panel">
    <div class="stats">
      <div class="stat"><div class="label">TỔNG KEY</div><div class="value" id="stTotal">0</div></div>
      <div class="stat"><div class="label">HOẠT ĐỘNG</div><div class="value" id="stActive">0</div></div>
      <div class="stat"><div class="label">ĐÃ DÙNG</div><div class="value" id="stUsed">0</div></div>
      <div class="stat"><div class="label">SẮP HẾT HẠN</div><div class="value" id="stExpiring">0</div></div>
    </div>

    <div class="toolbar">
      <input type="text" id="searchInput" placeholder="🔍 Tìm key hoặc label..." style="flex:1;min-width:200px" />
      <input type="number" id="createCount" value="1" min="1" max="100" style="width:80px" placeholder="SL" />
      <input type="number" id="createDays" value="30" min="0" style="width:100px" placeholder="Ngày" />
      <input type="number" id="createDevices" value="1" min="1" style="width:80px" placeholder="TB" />
      <input type="text" id="createLabel" placeholder="Label" style="width:140px" />
      <button class="btn-primary" onclick="createKeys()">+ TẠO KEY</button>
    </div>

    <div class="toolbar">
      <button class="btn-ghost" onclick="selectAll(true)">Chọn tất cả</button>
      <button class="btn-ghost" onclick="selectAll(false)">Bỏ chọn</button>
      <button class="btn-danger" onclick="deleteSelected()">🗑 Xoá đã chọn</button>
      <button class="btn-danger" onclick="deleteUsed()">Xoá key đã dùng</button>
      <button class="btn-danger" onclick="deleteExpired()">Xoá key hết hạn</button>
      <button class="btn-ghost" onclick="exportKeys()">⬇ Export CSV</button>
      <button class="btn-ghost" onclick="copySelected()">📋 Copy đã chọn</button>
    </div>

    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th style="width:36px"><input type="checkbox" id="checkAll" onchange="selectAll(this.checked)" /></th>
            <th>KEY</th><th>LABEL</th><th>TB</th><th>HẠN</th><th>DÙNG</th><th>TRẠNG THÁI</th><th>THAO TÁC</th>
          </tr>
        </thead>
        <tbody id="keyTable"></tbody>
      </table>
    </div>

    <div class="pagination" id="pagination"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const API = location.origin;
let SECRET = '', PAGE = 1, TOTAL_PAGES = 1;
const $ = id => document.getElementById(id);

function toast(t, type='ok'){
  const el = $('toast');
  el.textContent = t;
  el.className = 'toast show' + (type==='err' ? ' err' : '');
  setTimeout(() => el.className = 'toast', 2500);
}

function daysLeft(e){
  if (!e) return '∞';
  const s = Number(e) - Math.floor(Date.now()/1000);
  if (s < 0) return 'HẾT';
  const d = Math.floor(s/86400);
  return d > 0 ? d + ' ngày' : Math.floor(s/3600) + ' giờ';
}

async function api(path, opt = {}){
  const r = await fetch(API + path, {
    ...opt,
    headers: { 'Content-Type':'application/json', 'X-Admin-Secret': SECRET, ...(opt.headers||{}) }
  });
  return r.json();
}

async function doLogin(){
  SECRET = $('secretInput').value.trim();
  if (!SECRET) return toast('Nhập secret', 'err');
  try {
    const d = await api('/api/admin/stats');
    if (!d.ok) throw new Error(d.message || 'Sai secret');
    localStorage.setItem('nova_admin_secret', SECRET);
    $('loginCard').style.display = 'none';
    $('panel').style.display = 'block';
    $('serverStatus').textContent = '● ONLINE';
    $('serverStatus').style.color = '#4ade80';
    loadStats(); loadKeys();
    toast('Đăng nhập thành công');
  } catch(e) { toast('❌ ' + e.message, 'err'); }
}

async function loadStats(){
  const d = await api('/api/admin/stats');
  if (!d.ok) return;
  $('stTotal').textContent = d.stats.total;
  $('stActive').textContent = d.stats.active;
  $('stUsed').textContent = d.stats.used;
  $('stExpiring').textContent = d.stats.expiring_soon;
}

async function loadKeys(){
  const search = $('searchInput').value.trim();
  const d = await api('/api/admin/keys?page=' + PAGE + '&limit=50&search=' + encodeURIComponent(search));
  if (!d.ok) return toast('Lỗi tải', 'err');
  TOTAL_PAGES = d.pages;
  const tb = $('keyTable');
  tb.innerHTML = '';
  if (!d.keys.length){
    tb.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:#8d4d55">Không có key</td></tr>';
    $('pagination').innerHTML = '';
    return;
  }
  const now = Math.floor(Date.now()/1000);
  for (const k of d.keys){
    const isExp = k.expires_at && Number(k.expires_at) < now;
    const st = !k.is_active ? '<span class="status off">REVOKED</span>'
      : isExp ? '<span class="status expired">EXPIRED</span>'
      : '<span class="status on">ACTIVE</span>';
    const tr = document.createElement('tr');
    tr.innerHTML = '<td><input type="checkbox" class="row-check" data-key="' + k.key + '" /></td>' +
      '<td class="key-cell">' + k.key + '</td>' +
      '<td>' + (k.label || '—') + '</td>' +
      '<td style="text-align:center">' + k.device_count + '/' + k.max_devices + '</td>' +
      '<td>' + daysLeft(k.expires_at) + '</td>' +
      '<td style="text-align:center">' + k.used_count + '</td>' +
      '<td>' + st + '</td>' +
      '<td><div class="actions">' +
        '<button onclick="copyKey(\\'' + k.key + '\\')">Copy</button>' +
        (k.is_active
          ? '<button onclick="revokeKey(\\'' + k.key + '\\')">Thu hồi</button>'
          : '<button onclick="unrevokeKey(\\'' + k.key + '\\')">Bỏ</button>') +
        '<button onclick="resetDevices(\\'' + k.key + '\\')">Reset</button>' +
        '<button onclick="deleteKey(\\'' + k.key + '\\')" style="color:#ff5566;border-color:#ff5566">Xoá</button>' +
      '</div></td>';
    tb.appendChild(tr);
  }
  renderPagination();
}

function renderPagination(){
  const p = $('pagination');
  p.innerHTML = '';
  if (TOTAL_PAGES <= 1) return;
  const mk = (txt, cb, active) => {
    const b = document.createElement('button');
    b.textContent = txt;
    if (active) b.classList.add('active');
    b.onclick = cb;
    return b;
  };
  if (PAGE > 1) p.appendChild(mk('‹', () => { PAGE--; loadKeys(); }));
  for (let i = Math.max(1, PAGE-2); i <= Math.min(TOTAL_PAGES, PAGE+2); i++)
    p.appendChild(mk(i, () => { PAGE=i; loadKeys(); }, i===PAGE));
  if (PAGE < TOTAL_PAGES) p.appendChild(mk('›', () => { PAGE++; loadKeys(); }));
}

async function createKeys(){
  const body = {
    count: +$('createCount').value || 1,
    duration_days: +$('createDays').value || 30,
    max_devices: +$('createDevices').value || 1,
    label: $('createLabel').value.trim()
  };
  const d = await api('/api/admin/create-key', { method:'POST', body: JSON.stringify(body) });
  if (!d.ok) return toast('Lỗi: ' + d.message, 'err');
  try { await navigator.clipboard.writeText(d.keys.join('\\n')); } catch (e) {}
  toast('✅ Tạo ' + d.keys.length + ' key (đã copy)');
  PAGE = 1; loadKeys(); loadStats();
}

async function copyKey(k){ try { await navigator.clipboard.writeText(k); toast('📋 ' + k); } catch(e) { toast('Không copy được','err'); } }
async function revokeKey(k){ if (!confirm('Thu hồi ' + k + '?')) return; const d = await api('/api/admin/revoke', {method:'POST',body:JSON.stringify({key:k})}); if (d.ok){toast('Đã thu hồi');loadKeys();} else toast(d.message,'err'); }
async function unrevokeKey(k){ const d = await api('/api/admin/unrevoke', {method:'POST',body:JSON.stringify({key:k})}); if (d.ok){toast('Đã bỏ');loadKeys();} else toast(d.message,'err'); }
async function resetDevices(k){ if (!confirm('Reset TB cho ' + k + '?')) return; const d = await api('/api/admin/reset-devices', {method:'POST',body:JSON.stringify({key:k})}); if (d.ok){toast('Đã reset');loadKeys();} else toast(d.message,'err'); }
async function deleteKey(k){ if (!confirm('XÓA ' + k + '?')) return; const d = await api('/api/admin/delete', {method:'DELETE',body:JSON.stringify({key:k})}); if (d.ok){toast('Đã xóa');loadKeys();loadStats();} else toast(d.message,'err'); }

function getSelected(){ return [...document.querySelectorAll('.row-check:checked')].map(c => c.dataset.key); }
function selectAll(c){ document.querySelectorAll('.row-check').forEach(x => x.checked = c); $('checkAll').checked = c; }

async function deleteSelected(){
  const keys = getSelected();
  if (!keys.length) return toast('Chưa chọn', 'err');
  if (!confirm('Xóa ' + keys.length + ' key?')) return;
  const d = await api('/api/admin/delete-batch', {method:'POST',body:JSON.stringify({keys})});
  if (d.ok){toast('Xóa ' + d.deleted + ' key');loadKeys();loadStats();}
}

async function deleteUsed(){ if (!confirm('Xóa TẤT CẢ key đã dùng?')) return; const d = await api('/api/admin/delete-used',{method:'POST'}); if (d.ok){toast('Xóa ' + d.deleted);loadKeys();loadStats();} }
async function deleteExpired(){ if (!confirm('Xóa TẤT CẢ key hết hạn?')) return; const d = await api('/api/admin/delete-expired',{method:'POST'}); if (d.ok){toast('Xóa ' + d.deleted);loadKeys();loadStats();} }

async function copySelected(){
  const keys = getSelected();
  if (!keys.length) return toast('Chưa chọn', 'err');
  try { await navigator.clipboard.writeText(keys.join('\\n')); toast('📋 Copy ' + keys.length + ' key'); } catch(e) { toast('Lỗi copy','err'); }
}

async function exportKeys(){
  const d = await api('/api/admin/keys?page=1&limit=200');
  if (!d.ok) return toast('Lỗi', 'err');
  const rows = [['key','label','devices','max_devices','expires_at','used_count','is_active']];
  for (const k of d.keys) {
    rows.push([k.key, k.label, k.device_count, k.max_devices,
      k.expires_at ? new Date(Number(k.expires_at)*1000).toISOString() : '', k.used_count, k.is_active]);
  }
  const csv = rows.map(r => r.map(v => '"' + v + '"').join(',')).join('\\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], {type:'text/csv'}));
  a.download = 'nova-keys-' + Date.now() + '.csv';
  a.click();
  toast('⬇ Đã export');
}

window.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('nova_admin_secret');
  if (saved){ $('secretInput').value = saved; doLogin(); }
  $('searchInput').addEventListener('input', (() => {
    let t; return () => { clearTimeout(t); t = setTimeout(() => { PAGE=1; loadKeys(); }, 400); };
  })());
});

$('secretInput').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
</script>
</body>
</html>`;

app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(ADMIN_HTML);
});

app.get('/admin.html', (req, res) => {
  res.redirect('/admin');
});

/* =========================================================
   9. 404 + ERROR
   ========================================================= */
app.use((req, res) => {
  res.status(404).json({ ok: false, message: 'Không tìm thấy endpoint' });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ ok: false, message: 'Lỗi server' });
});

/* =========================================================
   10. START
   ========================================================= */
const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log('✅ Server chạy tại http://localhost:' + PORT);
      console.log('✅ Admin panel: http://localhost:' + PORT + '/admin');
    });
  })
  .catch(err => {
    console.error('❌ Không khởi tạo được DB:', err);
    process.exit(1);
  });
