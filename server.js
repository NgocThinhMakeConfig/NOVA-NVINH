/* =========================================================
   NVINH NOVA — KEY SERVER v5.4.0 (FULL COMPATIBLE WITH PANEL VIP IN KEY.html)
   - Đã bổ sung đầy đủ GET /api/admin/stats, /api/admin/logs, /api/admin/devices
   - Tương thích 100% với file PANEL VIP IN KEY.html gốc của bạn
   ========================================================= */
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_change_me';

// Chấp nhận mật khẩu 'nvinhnova123' và các biến môi trường trên Render
const VALID_ADMIN_SECRETS = new Set([
  'nvinhnova123',
  process.env.ADMIN_TOKEN ? process.env.ADMIN_TOKEN.trim() : null,
  process.env.ADMIN_SECRET ? process.env.ADMIN_SECRET.trim() : null,
  process.env.ADMIN_PASSWORD ? process.env.ADMIN_PASSWORD.trim() : null
].filter(Boolean));

app.use(helmet({ crossOriginResourcePolicy: false, contentSecurityPolicy: false }));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-token', 'x-admin-secret', 'admin-secret']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);

app.use((req, res, next) => {
  req.url = req.url.replace(/\/+/g, '/');
  next();
});

// --- CẤU HÌNH DATABASE POOL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => console.error('⚠️ Lỗi ngầm Database Pool:', err.message));

async function initDb() {
  console.log('⏳ Đang kiểm tra Database...');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS keys_nova (
      id SERIAL PRIMARY KEY,
      key_code TEXT UNIQUE NOT NULL,
      label TEXT DEFAULT '',
      max_devices INTEGER DEFAULT 1,
      duration_days INTEGER DEFAULT 0,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      activated_at BIGINT,
      expires_at BIGINT,
      is_active INTEGER DEFAULT 1,
      used_count INTEGER DEFAULT 0,
      last_used_at BIGINT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices_nova (
      id SERIAL PRIMARY KEY,
      key_id INTEGER NOT NULL REFERENCES keys_nova(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      first_seen BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      last_seen BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      user_agent TEXT,
      ip TEXT,
      UNIQUE(key_id, device_id)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs_nova (
      id SERIAL PRIMARY KEY,
      key_id INTEGER REFERENCES keys_nova(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      device_id TEXT,
      ip TEXT,
      detail TEXT,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_keys_nova_key_code ON keys_nova(key_code);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_devices_nova_key_id ON devices_nova(key_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_logs_nova_key_id ON logs_nova(key_id);`);
  console.log('✅ Database khởi tạo thành công! (Bảng keys_nova đã sẵn sàng)');
}

/* ---------- HELPERS ---------- */
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (_) { return null; }
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function generateKey(prefix = 'NOVA') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = `${prefix}-`;
  for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 4; j++) key += chars.charAt(Math.floor(Math.random() * chars.length));
    if (i < 2) key += '-';
  }
  return key;
}

async function logAction(keyId, action, deviceId, ip, detail) {
  try {
    await pool.query(
      `INSERT INTO logs_nova (key_id, action, device_id, ip, detail) VALUES ($1, $2, $3, $4, $5)`,
      [keyId, action, deviceId, ip, detail]
    );
  } catch (_) {}
}

function extractAdminSecret(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return authHeader.slice(7).trim();
  if (authHeader.trim()) return authHeader.trim();
  const customHeader = req.headers['x-admin-token'] || req.headers['x-admin-secret'] || req.headers['admin-secret'];
  if (customHeader) return String(customHeader).trim();
  if (req.body && (req.body.secret || req.body.admin_secret || req.body.token || req.body.password)) {
    return String(req.body.secret || req.body.admin_secret || req.body.token || req.body.password).trim();
  }
  if (req.query && (req.query.secret || req.query.admin_secret || req.query.token)) {
    return String(req.query.secret || req.query.admin_secret || req.query.token).trim();
  }
  return '';
}

const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 150 });

function requireToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ ok: false, message: 'Thiếu token xác thực' });
  }
  const decoded = verifyToken(authHeader.split(' ')[1]);
  if (!decoded) return res.status(401).json({ ok: false, message: 'Token không hợp lệ hoặc hết hạn' });
  req.user = decoded;
  next();
}

function requireAdmin(req, res, next) {
  const providedSecret = extractAdminSecret(req);
  if (!providedSecret || !VALID_ADMIN_SECRETS.has(providedSecret)) {
    return res.status(403).json({ ok: false, message: 'Quyền truy cập Admin bị từ chối' });
  }
  next();
}

/* ---------- PUBLIC ROUTES ---------- */
const healthHandler = (req, res) => res.json({
  ok: true,
  status: 'online',
  service: 'NVINH NOVA',
  version: '5.4.0',
  table: 'keys_nova',
  time: Date.now()
});

app.get('/', healthHandler);
app.get('/health', healthHandler);
app.get('/api/health', healthHandler);
app.get('/api/status', healthHandler);
app.get('/api/ping', healthHandler);

app.post('/api/verify-key', verifyLimiter, async (req, res) => {
  const { key, device_id: deviceId, user_agent: ua } = req.body || {};
  const ip = req.ip;
  const now = Math.floor(Date.now() / 1000);

  if (!key) return res.status(400).json({ ok: false, valid: false, message: 'Thiếu key' });
  const cleanKey = String(key).trim().toUpperCase();

  try {
    const { rows } = await pool.query('SELECT * FROM keys_nova WHERE key_code = $1', [cleanKey]);
    const row = rows[0];

    if (!row) {
      await logAction(null, 'verify_fail', deviceId, ip, 'Key không tồn tại');
      return res.status(404).json({ ok: false, valid: false, message: 'Key không tồn tại' });
    }
    if (!row.is_active) return res.status(403).json({ ok: false, valid: false, message: 'Key đã bị thu hồi' });
    if (row.expires_at && now > row.expires_at) return res.status(403).json({ ok: false, valid: false, message: 'Key đã hết hạn' });
    if (!deviceId) return res.status(400).json({ ok: false, valid: false, message: 'Thiếu thông tin thiết bị' });

    const { rows: devs } = await pool.query('SELECT device_id FROM devices_nova WHERE key_id = $1', [row.id]);
    const isKnown = devs.some(d => d.device_id === deviceId);

    if (!isKnown) {
      if (devs.length >= row.max_devices) {
        await logAction(row.id, 'verify_fail', deviceId, ip, 'Vượt số thiết bị');
        return res.status(403).json({ ok: false, valid: false, message: `Key đã kích hoạt trên ${row.max_devices} thiết bị khác.` });
      }
      await pool.query(
        `INSERT INTO devices_nova (key_id, device_id, user_agent, ip) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        [row.id, deviceId, ua || '', ip]
      );
      await logAction(row.id, 'device_new', deviceId, ip, `Thiết bị mới #${devs.length + 1}`);
    } else {
      await pool.query('UPDATE devices_nova SET last_seen = $1 WHERE key_id = $2 AND device_id = $3', [now, row.id, deviceId]);
    }

    let expires_at = row.expires_at;
    if (!row.activated_at && row.duration_days > 0) {
      expires_at = now + row.duration_days * 86400;
      await pool.query('UPDATE keys_nova SET activated_at = $1, expires_at = $2 WHERE id = $3', [now, expires_at, row.id]);
      await logAction(row.id, 'activated', deviceId, ip, `Kích hoạt lần đầu, hạn ${row.duration_days} ngày`);
    }

    await pool.query('UPDATE keys_nova SET used_count = used_count + 1, last_used_at = $1 WHERE id = $2', [now, row.id]);
    await logAction(row.id, 'verify_ok', deviceId, ip, 'Xác thực thành công');

    const token = signToken({ keyId: row.id, key_code: row.key_code, deviceId });
    res.json({ ok: true, valid: true, message: 'Xác thực thành công', token, expires_at: expires_at ? expires_at * 1000 : null });
  } catch (err) {
    res.status(500).json({ ok: false, valid: false, message: 'Lỗi Server: ' + err.message });
  }
});

app.post('/api/heartbeat', requireToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM keys_nova WHERE id = $1', [req.user.keyId]);
    const row = rows[0];
    if (!row || !row.is_active) return res.status(403).json({ ok: false, valid: false, message: 'Key bị khóa hoặc không tồn tại' });
    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && now > row.expires_at) return res.status(403).json({ ok: false, valid: false, message: 'Key đã hết hạn' });
    res.json({ ok: true, valid: true, message: 'Heartbeat OK' });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Lỗi Server' });
  }
});

/* ---------- ADMIN API ROUTES (KHỚP 100% VỚI PANEL VIP IN KEY.html) ---------- */
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

// 1. Route /api/admin/stats mà file HTML của bạn đang gọi!
adminRouter.get('/stats', async (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const totalQ = await pool.query('SELECT COUNT(*)::int AS c FROM keys_nova');
    const activeQ = await pool.query('SELECT COUNT(*)::int AS c FROM keys_nova WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > $1)', [now]);
    const expiredQ = await pool.query('SELECT COUNT(*)::int AS c FROM keys_nova WHERE expires_at IS NOT NULL AND expires_at <= $1', [now]);
    const revokedQ = await pool.query('SELECT COUNT(*)::int AS c FROM keys_nova WHERE is_active = 0');
    const devicesQ = await pool.query('SELECT COUNT(*)::int AS c FROM devices_nova');
    const logsQ = await pool.query('SELECT COUNT(*)::int AS c FROM logs_nova');

    const total = totalQ.rows[0].c || 0;
    const active = activeQ.rows[0].c || 0;
    const expired = expiredQ.rows[0].c || 0;
    const revoked = revokedQ.rows[0].c || 0;
    const devices = devicesQ.rows[0].c || 0;
    const logs = logsQ.rows[0].c || 0;

    // Trả về mọi tên biến có thể có để tương thích 100% với giao diện HTML
    res.json({
      ok: true,
      total,
      active,
      expired,
      revoked,
      locked: revoked,
      devices,
      total_keys: total,
      active_keys: active,
      expired_keys: expired,
      revoked_keys: revoked,
      locked_keys: revoked,
      total_devices: devices,
      total_logs: logs,
      stats: { total, active, expired, revoked, devices, logs }
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// 2. Route kiểm tra đăng nhập
adminRouter.all('/login', (req, res) => res.json({ ok: true, message: 'Đăng nhập Admin thành công' }));
adminRouter.all('/verify', (req, res) => res.json({ ok: true, message: 'Admin hợp lệ' }));

// 3. Tạo Key mới (Hỗ trợ cả /create-key, /create, /keys, /generate)
const createKeyHandler = async (req, res) => {
  const {
    label = '',
    note = '',
    duration_days,
    days,
    duration,
    max_devices = 1,
    devices,
    amount = 1,
    count,
    custom_key = '',
    key = '',
    prefix = 'NOVA'
  } = req.body || {};

  try {
    const finalLabel = label || note || '';
    const numAmount = Math.min(Math.max(parseInt(amount || count) || 1, 1), 100);
    const rawDays = duration_days !== undefined ? duration_days : (days !== undefined ? days : duration);
    const numDuration = Math.max(parseInt(rawDays) || 0, 0);
    const numDevices = Math.max(parseInt(max_devices || devices) || 1, 1);

    let created = [];
    let createdObjects = [];

    for (let i = 0; i < numAmount; i++) {
      let newKey = (numAmount === 1 && (custom_key || key)) ? String(custom_key || key).trim().toUpperCase() : '';
      if (!newKey) {
        let attempts = 0;
        do {
          newKey = generateKey(prefix || 'NOVA');
          const { rows } = await pool.query('SELECT 1 FROM keys_nova WHERE key_code = $1', [newKey]);
          if (rows.length === 0) break;
        } while (++attempts < 10);
      }

      const { rows } = await pool.query(
        `INSERT INTO keys_nova (key_code, label, duration_days, max_devices) VALUES ($1, $2, $3, $4) RETURNING *`,
        [newKey, finalLabel, numDuration, numDevices]
      );
      created.push(newKey);
      createdObjects.push(rows[0]);
    }
    res.json({ ok: true, keys: created, key: created[0], data: createdObjects });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
};
adminRouter.post('/create-key', createKeyHandler);
adminRouter.post('/create', createKeyHandler);
adminRouter.post('/generate', createKeyHandler);
adminRouter.post('/keys', createKeyHandler);

// 4. Lấy danh sách Key
adminRouter.get('/keys', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * limit;
    const search = (req.query.search || req.query.q || '').trim();

    let whereClause = '';
    let params = [limit, offset];
    if (search) {
      whereClause = `WHERE k.key_code ILIKE $3 OR k.label ILIKE $3`;
      params.push(`%${search}%`);
    }

    const totalQ = await pool.query(`SELECT COUNT(*)::int AS c FROM keys_nova k ${whereClause}`, search ? [`%${search}%`] : []);
    const total = totalQ.rows[0].c || 0;

    const rowsQ = await pool.query(`
      SELECT k.*, (SELECT COUNT(*)::int FROM devices_nova d WHERE d.key_id = k.id) AS device_count
      FROM keys_nova k
      ${whereClause}
      ORDER BY k.created_at DESC LIMIT $1 OFFSET $2
    `, params);

    res.json({ ok: true, total, page, pages: Math.ceil(total / limit) || 1, keys: rowsQ.rows, data: rowsQ.rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// 5. Lấy lịch sử Logs (/api/admin/logs)
adminRouter.get('/logs', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const { rows } = await pool.query(`
      SELECT l.*, k.key_code
      FROM logs_nova l
      LEFT JOIN keys_nova k ON l.key_id = k.id
      ORDER BY l.created_at DESC LIMIT $1
    `, [limit]);
    res.json({ ok: true, logs: rows, data: rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// 6. Lấy danh sách thiết bị (/api/admin/devices)
adminRouter.get('/devices', async (req, res) => {
  try {
    const keyCode = (req.query.key || req.query.key_code || '').trim().toUpperCase();
    if (keyCode) {
      const { rows } = await pool.query(`
        SELECT d.*, k.key_code FROM devices_nova d
        JOIN keys_nova k ON d.key_id = k.id
        WHERE k.key_code = $1 ORDER BY d.last_seen DESC
      `, [keyCode]);
      return res.json({ ok: true, devices: rows, data: rows });
    }
    const { rows } = await pool.query(`
      SELECT d.*, k.key_code FROM devices_nova d
      JOIN keys_nova k ON d.key_id = k.id
      ORDER BY d.last_seen DESC LIMIT 200
    `);
    res.json({ ok: true, devices: rows, data: rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// 7. Khóa / Thu hồi Key
const revokeHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.params?.key || '').trim().toUpperCase();
    const r = await pool.query('UPDATE keys_nova SET is_active = 0 WHERE key_code = $1 OR id::text = $1', [targetKey]);
    res.json({ ok: true, modified: r.rowCount, message: 'Đã thu hồi key' });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.post('/revoke', revokeHandler);
adminRouter.post('/revoke-key', revokeHandler);
adminRouter.post('/lock', revokeHandler);

// 8. Mở khóa Key
const activateHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.params?.key || '').trim().toUpperCase();
    const r = await pool.query('UPDATE keys_nova SET is_active = 1 WHERE key_code = $1 OR id::text = $1', [targetKey]);
    res.json({ ok: true, modified: r.rowCount, message: 'Đã kích hoạt lại key' });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.post('/activate', activateHandler);
adminRouter.post('/unrevoke', activateHandler);
adminRouter.post('/unlock', activateHandler);

// 9. Reset Thiết bị (HWID)
const resetDevicesHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.params?.key || '').trim().toUpperCase();
    const { rows } = await pool.query('SELECT id FROM keys_nova WHERE key_code = $1 OR id::text = $1', [targetKey]);
    if (!rows[0]) return res.status(404).json({ ok: false, message: 'Không tìm thấy key' });
    const r = await pool.query('DELETE FROM devices_nova WHERE key_id = $1', [rows[0].id]);
    res.json({ ok: true, reset: r.rowCount, deleted: r.rowCount, message: 'Đã reset thiết bị' });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.post('/reset-devices', resetDevicesHandler);
adminRouter.post('/reset-hwid', resetDevicesHandler);
adminRouter.post('/reset', resetDevicesHandler);
adminRouter.delete('/devices/:key', resetDevicesHandler);

// 10. Xóa Key
const deleteKeyHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.query?.key || req.params?.key || '').trim().toUpperCase();
    const r = await pool.query('DELETE FROM keys_nova WHERE key_code = $1 OR id::text = $1', [targetKey]);
    res.json({ ok: true, deleted: r.rowCount, message: 'Đã xóa key' });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.delete('/delete', deleteKeyHandler);
adminRouter.post('/delete', deleteKeyHandler);
adminRouter.post('/delete-key', deleteKeyHandler);
adminRouter.delete('/keys/:key', deleteKeyHandler);

app.use('/api/admin', adminRouter);
app.use('/admin', adminRouter);

app.use((req, res) => {
  console.log(`⚠️ Route chưa có: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ ok: false, message: `Đường dẫn API không tồn tại: ${req.method} ${req.originalUrl}` });
});

initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ NOVA Server v5.4.0 đang chạy tại http://0.0.0.0:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ Lỗi Database:', err);
    process.exit(1);
  });
