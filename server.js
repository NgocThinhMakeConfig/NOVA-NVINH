/* =========================================================
   NVINH NOVA — KEY SERVER v3.0.0 (FINAL - TẮT AUTO-CLEAN)
   - Device lock cứng (mỗi key 1 máy)
   - KHÔNG BAO GIỜ TỰ ĐỘNG XÓA KEY
   - Đã đồng bộ 100% tên cột (key_code)
   ========================================================= */
require('dotenv').config();

const crypto    = require('crypto');
const path      = require('path');
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const morgan    = require('morgan');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool }  = require('pg');

/* ---------- 1. DATABASE ---------- */
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
      key_code TEXT UNIQUE NOT NULL,
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

    CREATE INDEX IF NOT EXISTS idx_keys_key_code ON keys(key_code);
    CREATE INDEX IF NOT EXISTS idx_devices_key_id ON devices(key_id);
    CREATE INDEX IF NOT EXISTS idx_logs_key_id ON logs(key_id);
  `);
  console.log('✅ Database khởi tạo xong');
  console.log('✅ DEVICE LOCK: BẬT CỨNG (mỗi key chỉ dùng 1 máy)');
  console.log('✅ AUTO-CLEAN: ĐÃ TẮT HOÀN TOÀN');
}

/* ---------- 2. HELPERS ---------- */
function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () => Array.from({ length: 4 }, () =>
    chars[crypto.randomInt(0, chars.length)]
  ).join('');
  return [seg(), seg(), seg(), seg()].join('-');
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET || 'nvinh_secret', {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  });
}

function verifyToken(token) {
  try { return jwt.verify(token, process.env.JWT_SECRET || 'nvinh_secret'); }
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

function getStatusCondition(status){
  switch(status){
    case 'active':
      return `is_active = 1 AND (expires_at IS NULL OR expires_at > EXTRACT(EPOCH FROM NOW()))`;
    case 'used':
      return `used_count > 0`;
    case 'expiring':
      return `is_active = 1 AND expires_at IS NOT NULL AND expires_at > EXTRACT(EPOCH FROM NOW()) AND expires_at < EXTRACT(EPOCH FROM NOW()) + 86400 * 3`;
    case 'expired':
      return `expires_at IS NOT NULL AND expires_at < EXTRACT(EPOCH FROM NOW())`;
    default:
      return '1=1';
  }
}

/* ---------- 3. APP ---------- */
const app = express();
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));

// CORS
const origins = (process.env.ALLOWED_ORIGINS || '*')
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

app.use(express.static(path.join(__dirname, 'public')));

/* ---------- 4. RATE LIMIT ---------- */
const generalLimiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
const verifyLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 30, skipSuccessfulRequests: true });
const adminLimiter = rateLimit({ windowMs: 60 * 1000, max: 200 });

app.use('/api/', generalLimiter);

/* ---------- 5. MIDDLEWARE ---------- */
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

/* ---------- 6. PUBLIC ROUTES ---------- */
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'NVINH NOVA Key Server',
    version: '3.0.0',
    device_lock: true,
    auto_clean: false,
    time: Date.now()
  });
});

app.get('/health', (req, res) => {
  res.json({ ok: true, time: Date.now(), version: '3.0.0' });
});

// =========================================================
// POST /api/verify-key
// =========================================================
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
    const { rows } = await pool.query('SELECT * FROM keys WHERE key_code = $1', [cleanKey]);
    const row = rows[0];

    // 1. Key không tồn tại
    if (!row) {
      await logAction(null, 'verify_fail', deviceId, ip, 'Key không tồn tại');
      return res.status(404).json({ ok: false, valid: false, message: 'Key không tồn tại' });
    }

    // 2. Key bị vô hiệu
    if (!row.is_active) {
      await logAction(row.id, 'verify_fail', deviceId, ip, 'Key bị vô hiệu');
      return res.status(403).json({ ok: false, valid: false, message: 'Key đã bị vô hiệu hoá' });
    }

    // 3. Key hết hạn
    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && Number(row.expires_at) < now) {
      const daysExpired = Math.floor((now - Number(row.expires_at)) / 86400);
      await logAction(row.id, 'verify_fail', deviceId, ip, `Key hết hạn ${daysExpired} ngày`);
      return res.status(403).json({ ok: false, valid: false, message: `Key đã hết hạn ${daysExpired} ngày trước` });
    }

    // 4. DEVICE LOCK
    if (!deviceId) {
      await logAction(row.id, 'verify_fail', '', ip, 'Thiếu device_id');
      return res.status(400).json({ ok: false, valid: false, message: 'Thiếu thông tin thiết bị' });
    }

    const { rows: devs } = await pool.query('SELECT device_id, first_seen FROM devices WHERE key_id = $1', [row.id]);
    const isKnown = devs.some(d => d.device_id === deviceId);

    if (!isKnown) {
      if (devs.length >= row.max_devices) {
        await logAction(row.id, 'verify_fail', deviceId, ip, `Vượt số thiết bị (${devs.length}/${row.max_devices})`);
        return res.status(403).json({
          ok: false, valid: false,
          message: `Key đã được kích hoạt trên ${row.max_devices} thiết bị khác. Vui lòng liên hệ admin để reset.`
        });
      }

      await pool.query(
        `INSERT INTO devices (key_id, device_id, user_agent, ip) VALUES ($1, $2, $3, $4) ON CONFLICT (key_id, device_id) DO NOTHING`,
        [row.id, deviceId, ua, ip]
      );
      await logAction(row.id, 'device_new', deviceId, ip, `Thiết bị mới #${devs.length + 1}`);
    } else {
      await pool.query('UPDATE devices SET last_seen = $1 WHERE key_id = $2 AND device_id = $3', [now, row.id, deviceId]);
    }

    // 5. Kích hoạt lần đầu
    if (!row.activated_at && row.duration_days > 0) {
      const expires = now + row.duration_days * 86400;
      await pool.query('UPDATE keys SET activated_at = $1, expires_at = $2 WHERE id = $3', [now, expires, row.id]);
      row.activated_at = now;
      row.expires_at = expires;
      await logAction(row.id, 'activated', deviceId, ip, `Kích hoạt lần đầu, hạn ${row.duration_days} ngày`);
    }

    // 6. Tăng used_count
    await pool.query('UPDATE keys SET used_count = used_count + 1, last_used_at = $1 WHERE id = $2', [now, row.id]);
    await logAction(row.id, 'verify_ok', deviceId, ip, 'Xác thực thành công');

    // 7. Token
    const token = signToken({
      keyId: row.id,
      key_code: row.key_code,
      label: row.label,
      deviceId: deviceId
    });

    res.json({
      ok: true, valid: true, token,
      expires_at: row.expires_at, label: row.label,
      device_lock: true, max_devices: row.max_devices,
      device_count: isKnown ? devs.length : devs.length + 1
    });
  } catch (e) {
    console.error('[verify-key]', e);
    res.status(500).json({ ok: false, valid: false, message: 'Lỗi server' });
  }
});

// =========================================================
// POST /api/heartbeat
// =========================================================
app.post('/api/heartbeat', requireToken, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM keys WHERE id = $1', [req.user.keyId]);
    const row = rows[0];

    if (!row) return res.status(404).json({ ok: false, valid: false, message: 'Key không tồn tại' });
    if (!row.is_active) return res.status(403).json({ ok: false, valid: false, message: 'Key đã bị thu hồi' });

    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at && Number(row.expires_at) < now) {
      return res.status(403).json({ ok: false, valid: false, message: 'Key đã hết hạn', expired: true });
    }

    res.json({ ok: true, valid: true, expires_at: row.expires_at, label: row.label });
  } catch (e) {
    console.error('[heartbeat]', e);
    res.status(500).json({ ok: false, message: 'Lỗi server' });
  }
});

/* ---------- 7. ADMIN ROUTES ---------- */
const adminRouter = express.Router();
adminRouter.use(requireAdmin);
adminRouter.use(adminLimiter);

// Tạo key
adminRouter.post('/create-key', async (req, res) => {
  const { label = '', duration_days = 30, max_devices = 1, count = 1 } = req.body || {};
  const n = Math.min(100, Math.max(1, parseInt(count) || 1));
  const created = [];

  try {
    for (let i = 0; i < n; i++) {
      let newKey, attempts = 0;
      do {
        newKey = generateKey();
        if (++attempts > 10) throw new Error('Không sinh được key unique');
        const { rows } = await pool.query('SELECT 1 FROM keys WHERE key_code = $1', [newKey]);
        if (rows.length === 0) break;
      } while (true);

      await pool.query(
        `INSERT INTO keys (key_code, label, duration_days, max_devices) VALUES ($1, $2, $3, $4)`,
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
  const status = (req.query.status || '').trim();

  try {
    let whereParts = [];
    let params = [];

    if (search) {
      params.push(`%${search}%`);
      whereParts.push(`(key_code LIKE $${params.length} OR label LIKE $${params.length})`);
    }
    if (status) whereParts.push(getStatusCondition(status));

    const whereClause = whereParts.length > 0 ? 'WHERE ' + whereParts.join(' AND ') : '';

    const totalQ = await pool.query(`SELECT COUNT(*) AS c FROM keys ${whereClause}`, params);
    const total = parseInt(totalQ.rows[0].c);

    const rowsQ = await pool.query(
      `SELECT k.*, (SELECT COUNT(*) FROM devices d WHERE d.key_id = k.id) AS device_count
       FROM keys k ${whereClause} ORDER BY k.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    res.json({ ok: true, total, page, limit, pages: Math.ceil(total / limit), keys: rowsQ.rows });
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
    const expiringQ = await pool.query(`SELECT COUNT(*) AS c FROM keys WHERE expires_at IS NOT NULL AND expires_at > EXTRACT(EPOCH FROM NOW()) AND expires_at < EXTRACT(EPOCH FROM NOW()) + 86400 * 7`);
    const expiredQ = await pool.query(`SELECT COUNT(*) AS c FROM keys WHERE expires_at IS NOT NULL AND expires_at < EXTRACT(EPOCH FROM NOW())`);

    res.json({
      ok: true,
      stats: {
        total: parseInt(totalQ.rows[0].c),
        active: parseInt(activeQ.rows[0].c),
        used: parseInt(usedQ.rows[0].c),
        expiring_soon: parseInt(expiringQ.rows[0].c),
        expired: parseInt(expiredQ.rows[0].c)
      }
    });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// Thu hồi
adminRouter.post('/revoke', async (req, res) => {
  try {
    const r = await pool.query('UPDATE keys SET is_active = 0 WHERE key_code = $1', [String(req.body?.key || '').toUpperCase()]);
    if (r.rowCount === 0) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Bỏ thu hồi
adminRouter.post('/unrevoke', async (req, res) => {
  try {
    const r = await pool.query('UPDATE keys SET is_active = 1 WHERE key_code = $1', [String(req.body?.key || '').toUpperCase()]);
    if (r.rowCount === 0) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Reset thiết bị
adminRouter.post('/reset-devices', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id FROM keys WHERE key_code = $1', [String(req.body?.key || '').toUpperCase()]);
    if (!rows[0]) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    const r = await pool.query('DELETE FROM devices WHERE key_id = $1', [rows[0].id]);
    await logAction(rows[0].id, 'reset_devices', null, req.ip, `Xóa ${r.rowCount} thiết bị`);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Xem thiết bị
adminRouter.get('/devices/:key', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id FROM keys WHERE key_code = $1', [String(req.params.key || '').toUpperCase()]);
    if (!rows[0]) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    const d = await pool.query('SELECT * FROM devices WHERE key_id = $1 ORDER BY first_seen ASC', [rows[0].id]);
    res.json({ ok: true, devices: d.rows });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Xoá 1 key
adminRouter.delete('/delete', async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM keys WHERE key_code = $1', [String(req.body?.key || '').toUpperCase()]);
    if (r.rowCount === 0) return res.status(404).json({ ok: false, message: 'Không tìm thấy' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Xoá nhiều key
adminRouter.post('/delete-batch', async (req, res) => {
  const { keys = [] } = req.body || {};
  if (!Array.isArray(keys) || keys.length === 0) return res.status(400).json({ ok: false, message: 'Danh sách rỗng' });
  try {
    const clean = keys.map(k => String(k).toUpperCase());
    const r = await pool.query('DELETE FROM keys WHERE key_code = ANY($1::text[])', [clean]);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Xoá toàn bộ key đã dùng
adminRouter.post('/delete-used', async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM keys WHERE used_count > 0');
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Xoá key hết hạn (Thủ công - Không tự động)
adminRouter.post('/delete-expired', async (req, res) => {
  try {
    const r = await pool.query(`DELETE FROM keys WHERE expires_at IS NOT NULL AND expires_at < EXTRACT(EPOCH FROM NOW())`);
    if (r.rowCount > 0) console.log(`🧹 Manual clean: Đã xóa ${r.rowCount} key hết hạn`);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// Logs
adminRouter.get('/logs', async (req, res) => {
  const limit = Math.min(500, parseInt(req.query.limit) || 100);
  try {
    let rows;
    if (req.query.key) {
      const r = await pool.query('SELECT id FROM keys WHERE key_code = $1', [String(req.query.key).toUpperCase()]);
      if (!r.rows[0]) return res.json({ ok: true, logs: [] });
      const l = await pool.query('SELECT * FROM logs WHERE key_id = $1 ORDER BY created_at DESC LIMIT $2', [r.rows[0].id, limit]);
      rows = l.rows;
    } else {
      const l = await pool.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT $1', [limit]);
      rows = l.rows;
    }
    res.json({ ok: true, logs: rows });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

app.use('/api/admin', adminRouter);

/* ---------- 8. 404 + ERROR ---------- */
app.use((req, res) => res.status(404).json({ ok: false, message: 'Không tìm thấy endpoint' }));
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ ok: false, message: 'Lỗi server' });
});

/* ---------- 9. START ---------- */
const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log('========================================');
      console.log(`✅ Server chạy tại http://localhost:${PORT}`);
      console.log(`✅ Version: 3.0.0 (FINAL)`);
      console.log(`✅ Device lock: BẬT CỨNG (mỗi key 1 máy)`);
      console.log(`✅ Auto-clean: ĐÃ TẮT HOÀN TOÀN (Không bao giờ tự xóa key)`);
      console.log('========================================');
    });
  })
  .catch(err => {
    console.error('❌ Không khởi tạo được DB:', err);
    process.exit(1);
  });
