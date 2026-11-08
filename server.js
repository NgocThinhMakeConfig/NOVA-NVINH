/* =========================================================
   NVINH NOVA — KEY SERVER v5.1.0 (STABLE & PRODUCTION READY)
   - Tương thích 100% với Panel HTML mở trực tiếp (file://)
   - Hỗ trợ đa phương thức xác thực Admin (Bearer, Header, Body, Query)
   - Quản lý Database an toàn, không bao giờ DROP TABLE
   - Bắt lỗi Runtime toàn cục (không bị crash đột ngột)
   ========================================================= */
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// --- CẤU HÌNH CƠ BẢN ---
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_change_me';

// Chấp nhận cả ADMIN_TOKEN, ADMIN_SECRET trên Render và luôn cho phép 'nvinhnova123'
const VALID_ADMIN_Secrets = new Set([
  'nvinhnova123',
  process.env.ADMIN_TOKEN ? process.env.ADMIN_TOKEN.trim() : null,
  process.env.ADMIN_SECRET ? process.env.ADMIN_SECRET.trim() : null,
  process.env.ADMIN_PASSWORD ? process.env.ADMIN_PASSWORD.trim() : null
].filter(Boolean));

// Cấu hình Helmet và CORS mở hoàn toàn cho phép gọi từ file:// trên máy tính
app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-token', 'x-admin-secret', 'admin-secret']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1); // Cần thiết khi chạy sau Proxy của Render

// --- CẤU HÌNH DATABASE POOL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && (process.env.DATABASE_URL.includes('render.com') || process.env.NODE_ENV === 'production')
       ? { rejectUnauthorized: false }
       : { rejectUnauthorized: false }, // An toàn cho cả internal/external DB trên Render
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('⚠️ Lỗi kết nối ngầm Database Pool (đã tự động xử lý):', err.message);
});

// --- HÀM KHỞI TẠO DATABASE (AN TOÀN) ---
async function initDb() {
  try {
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
    console.log('✅ DEVICE LOCK: BẬT CỨNG');
    console.log('✅ AUTO-CLEAN: ĐÃ TẮT HOÀN TOÀN');
  } catch (err) {
    console.error('❌ Lỗi khởi tạo Database:', err.message);
    throw err;
  }
}

/* ---------- HELPERS ---------- */
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (_) { return null; }
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = 'NOVA-';
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
  } catch (_) { /* Bỏ qua lỗi log để không ảnh hưởng luồng chính */ }
}

// Hàm lấy mã Admin từ mọi vị trí có thể trong Request
function extractAdminSecret(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (authHeader.trim()) {
    return authHeader.trim();
  }
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

/* ---------- MIDDLEWARES ---------- */
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false,
});

function requireToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ ok: false, message: 'Thiếu token xác thực' });
  }
  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ ok: false, message: 'Token không hợp lệ hoặc hết hạn' });
  req.user = decoded;
  next();
}

function requireAdmin(req, res, next) {
  const providedSecret = extractAdminSecret(req);
  if (!providedSecret || !VALID_ADMIN_Secrets.has(providedSecret)) {
    console.warn(`⚠️ Từ chối đăng nhập Admin. Mã nhận được: "${providedSecret}"`);
    return res.status(403).json({ ok: false, message: 'Quyền truy cập Admin bị từ chối' });
  }
  next();
}

/* ---------- PUBLIC ROUTES ---------- */
app.get('/', (req, res) => res.json({
  ok: true,
  status: 'online',
  service: 'NVINH NOVA',
  version: '5.1.0',
  table: 'keys_nova',
  time: Date.now()
}));

app.get('/health', (req, res) => res.json({ ok: true, status: 'online', time: Date.now() }));
app.get('/api/health', (req, res) => res.json({ ok: true, status: 'online', time: Date.now() }));
app.get('/api/status', (req, res) => res.json({ ok: true, status: 'online', time: Date.now() }));

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
        await logAction(row.id, 'verify_fail', deviceId, ip, `Vượt số thiết bị`);
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

    const token = signToken({ keyId: row.id, key_code: row.key_code, deviceId: deviceId });
    res.json({ ok: true, valid: true, message: 'Xác thực thành công', token, expires_at: expires_at ? expires_at * 1000 : null });
  } catch (err) {
    console.error('Verify Error:', err);
    res.status(500).json({ ok: false, valid: false, message: 'Lỗi Server' });
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

/* ---------- ADMIN ROUTES ---------- */
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

// Các route kiểm tra đăng nhập Admin từ Panel HTML
adminRouter.get('/verify', (req, res) => res.json({ ok: true, message: 'Admin hợp lệ' }));
adminRouter.post('/verify', (req, res) => res.json({ ok: true, message: 'Admin hợp lệ' }));
adminRouter.post('/login', (req, res) => res.json({ ok: true, message: 'Đăng nhập Admin thành công' }));

// Tạo Key mới
adminRouter.post('/create-key', async (req, res) => {
  const { label = '', duration_days = 0, max_devices = 1, amount = 1, custom_key = '' } = req.body || {};
  try {
    const numAmount = Math.min(Math.max(parseInt(amount) || 1, 1), 100);
    const numDuration = Math.max(parseInt(duration_days) || 0, 0);
    const numDevices = Math.max(parseInt(max_devices) || 1, 1);

    let created = [];
    for (let i = 0; i < numAmount; i++) {
      let newKey = (numAmount === 1 && custom_key) ? String(custom_key).trim().toUpperCase() : '';

      if (!newKey) {
        let attempts = 0;
        do {
          newKey = generateKey();
          const { rows } = await pool.query('SELECT 1 FROM keys_nova WHERE key_code = $1', [newKey]);
          if (rows.length === 0) break;
        } while (++attempts < 10);
      }

      await pool.query(
        `INSERT INTO keys_nova (key_code, label, duration_days, max_devices) VALUES ($1, $2, $3, $4)`,
        [newKey, label, numDuration, numDevices]
      );
      created.push(newKey);
    }
    res.json({ ok: true, keys: created, key: created[0] });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// Lấy danh sách Key & Thống kê
adminRouter.get('/keys', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * limit;

    const totalQ = await pool.query('SELECT COUNT(*) AS c FROM keys_nova');
    const total = parseInt(totalQ.rows[0].c);

    const rowsQ = await pool.query(`
      SELECT k.*, (SELECT COUNT(*)::int FROM devices_nova d WHERE d.key_id = k.id) AS device_count
      FROM keys_nova k
      ORDER BY k.created_at DESC LIMIT $1 OFFSET $2
    `, [limit, offset]);

    res.json({ ok: true, total, page, pages: Math.ceil(total / limit), keys: rowsQ.rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// Thu hồi (Khóa) Key
adminRouter.post('/revoke', async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || '').trim().toUpperCase();
    const r = await pool.query('UPDATE keys_nova SET is_active = 0 WHERE key_code = $1', [targetKey]);
    res.json({ ok: true, modified: r.rowCount });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// Mở khóa lại Key (Unrevoke)
adminRouter.post('/activate', async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || '').trim().toUpperCase();
    const r = await pool.query('UPDATE keys_nova SET is_active = 1 WHERE key_code = $1', [targetKey]);
    res.json({ ok: true, modified: r.rowCount });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// Reset thiết bị của Key
adminRouter.post('/reset-devices', async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || '').trim().toUpperCase();
    const { rows } = await pool.query('SELECT id FROM keys_nova WHERE key_code = $1', [targetKey]);
    if (!rows[0]) return res.status(404).json({ ok: false, message: 'Không tìm thấy key' });

    const r = await pool.query('DELETE FROM devices_nova WHERE key_id = $1', [rows[0].id]);
    res.json({ ok: true, reset: r.rowCount, message: 'Đã reset thiết bị thành công' });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// Xóa Key (Hỗ trợ cả DELETE và POST để tránh lỗi từ các bản HTML khác nhau)
const handleDeleteKey = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.query?.key || '').trim().toUpperCase();
    const r = await pool.query('DELETE FROM keys_nova WHERE key_code = $1', [targetKey]);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
};
adminRouter.delete('/delete', handleDeleteKey);
adminRouter.post('/delete', handleDeleteKey);

app.use('/api/admin', adminRouter);

/* ---------- KHỞI ĐỘNG SERVER ---------- */
initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log('========================================');
      console.log(`✅ NOVA Server đang chạy tại http://0.0.0.0:${PORT}`);
      console.log(`✅ Version: 5.1.0 (Stable)`);
      console.log('========================================');
    });
  })
  .catch(err => {
    console.error('❌ Không thể khởi động Server do lỗi Database:', err);
    process.exit(1);
  });

// Bắt các lỗi không mong muốn để server không bị crash đột ngột
process.on('unhandledRejection', (err) => {
  console.error('🔥 Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('🔥 Uncaught Exception:', err);
});
