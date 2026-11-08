/* =========================================================
   NVINH NOVA — KEY SERVER v5.0.0 (STABLE & PRODUCTION READY)
   - Khắc phục lỗi bind port trên Render (0.0.0.0)
   - Quản lý Database an toàn, không bao giờ DROP TABLE
   - Tối ưu Connection Pool cho việc dùng chung DB
   - Bắt lỗi Runtime toàn cục (không bị crash đột ngột)
   ========================================================= */
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// --- CẤU HÌNH CƠ BẢN ---
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_change_me';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin123';

app.use(cors());
app.use(express.json());
app.set('trust proxy', 1); // Cần thiết khi chạy sau Proxy của Render

// --- CẤU HÌNH DATABASE POOL ---
// Giới hạn max: 20 để tránh sập DB khi dùng chung với project AIMLOCK
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com') 
       ? { rejectUnauthorized: false } : false,
  max: 20, 
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// --- HÀM KHỞI TẠO DATABASE (AN TOÀN) ---
async function initDb() {
  try {
    console.log('⏳ Đang kiểm tra Database...');
    
    // Sử dụng IF NOT EXISTS để không bao giờ xóa dữ liệu cũ
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

/* ---------- MIDDLEWARES ---------- */
const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

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
  const authHeader = req.headers.authorization;
  if (authHeader !== `Bearer ${ADMIN_TOKEN}`) {
    return res.status(403).json({ ok: false, message: 'Quyền truy cập Admin bị từ chối' });
  }
  next();
}

/* ---------- PUBLIC ROUTES ---------- */
app.get('/', (req, res) => res.json({ ok: true, service: 'NVINH NOVA', version: '5.0.0', table: 'keys_nova', time: Date.now() }));
app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

app.post('/api/verify-key', verifyLimiter, async (req, res) => {
  const { key, device_id: deviceId, user_agent: ua } = req.body;
  const ip = req.ip;
  const now = Math.floor(Date.now() / 1000);

  if (!key) return res.status(400).json({ ok: false, valid: false, message: 'Thiếu key' });
  const cleanKey = key.trim().toUpperCase();

  try {
    const { rows } = await pool.query('SELECT * FROM keys_nova WHERE key_code = $1', [cleanKey]);
    const row = rows[0];

    if (!row) { await logAction(null, 'verify_fail', deviceId, ip, 'Key không tồn tại'); return res.status(404).json({ ok: false, valid: false, message: 'Key không tồn tại' }); }
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
      await pool.query(`INSERT INTO devices_nova (key_id, device_id, user_agent, ip) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, [row.id, deviceId, ua, ip]);
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
    res.json({ ok: true, valid: true, message: 'Xác thực thành công', token, expires_at: expires_at * 1000 });
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

adminRouter.post('/create-key', async (req, res) => {
  const { label = '', duration_days = 0, max_devices = 1, amount = 1 } = req.body;
  try {
    let created = [];
    for (let i = 0; i < amount; i++) {
      let newKey, attempts = 0;
      do {
        newKey = generateKey();
        const { rows } = await pool.query('SELECT 1 FROM keys_nova WHERE key_code = $1', [newKey]);
        if (rows.length === 0) break;
      } while (++attempts < 10);
      
      await pool.query(`INSERT INTO keys_nova (key_code, label, duration_days, max_devices) VALUES ($1, $2, $3, $4)`, [newKey, label, duration_days, max_devices]);
      created.push(newKey);
    }
    res.json({ ok: true, keys: created });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

adminRouter.get('/keys', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const page = parseInt(req.query.page) || 1;
    const offset = (page - 1) * limit;

    const totalQ = await pool.query('SELECT COUNT(*) AS c FROM keys_nova');
    const total = parseInt(totalQ.rows[0].c);
    
    const rowsQ = await pool.query(`
      SELECT k.*, (SELECT COUNT(*) FROM devices_nova d WHERE d.key_id = k.id) AS device_count 
      FROM keys_nova k 
      ORDER BY k.created_at DESC LIMIT $1 OFFSET $2
    `, [limit, offset]);

    res.json({ ok: true, total, page, pages: Math.ceil(total / limit), keys: rowsQ.rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

adminRouter.post('/revoke', async (req, res) => {
  try {
    const r = await pool.query('UPDATE keys_nova SET is_active = 0 WHERE key_code = $1', [String(req.body?.key || '').toUpperCase()]);
    res.json({ ok: true, modified: r.rowCount });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

adminRouter.delete('/delete', async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM keys_nova WHERE key_code = $1', [String(req.body?.key || '').toUpperCase()]);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

app.use('/api/admin', adminRouter);

/* ---------- KHỞI ĐỘNG SERVER ---------- */
initDb()
  .then(() => {
    // QUAN TRỌNG: Bind vào 0.0.0.0 để Render có thể truy cập
    app.listen(PORT, '0.0.0.0', () => {
      console.log('========================================');
      console.log(`✅ NOVA Server đang chạy tại http://0.0.0.0:${PORT}`);
      console.log(`✅ Version: 5.0.0 (Stable)`);
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
