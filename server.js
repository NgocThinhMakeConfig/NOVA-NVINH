/* =========================================================
   NVINH NOVA — KEY SERVER v5.6.0 (ULTIMATE & AUTO-FALLBACK)
   - Tự động sinh device_id nếu app không truyền lên (Chống lỗi Database)
   - Tích hợp sẵn trang Web Admin tại /admin
   - Đầy đủ API cho mọi loại Panel / App Key
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
  allowedHeaders: ['*']
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
      [keyId, action, deviceId || 'UNKNOWN', ip, detail]
    );
  } catch (_) {}
}

function extractAdminSecret(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return authHeader.slice(7).trim();
  if (authHeader.trim()) return authHeader.trim();
  const customHeader =
    req.headers['x-admin-token'] ||
    req.headers['x-admin-secret'] ||
    req.headers['admin-secret'] ||
    req.headers['x-api-key'];
  if (customHeader) return String(customHeader).trim();
  if (req.body && (req.body.secret || req.body.admin_secret || req.body.token || req.body.password)) {
    return String(req.body.secret || req.body.admin_secret || req.body.token || req.body.password).trim();
  }
  if (req.query && (req.query.secret || req.query.admin_secret || req.query.token)) {
    return String(req.query.secret || req.query.admin_secret || req.query.token).trim();
  }
  return '';
}

const verifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });

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

/* ---------- GIAO DIỆN WEB ADMIN TRỰC TIẾP TRÊN SERVER (/admin) ---------- */
const ADMIN_HTML_PAGE = `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>N VINH NOVA ADMIN — KEY PANEL</title>
  <style>
    :root { --bg:#080204; --card:#120609; --border:#3d0e18; --red:#e11d48; --red-glow:rgba(225,29,72,0.35); --green:#10b981; --text:#f8fafc; --muted:#94a3b8; }
    * { box-sizing:border-box; margin:0; padding:0; font-family:'Segoe UI',system-ui,sans-serif; }
    body { background:radial-gradient(circle at center,#1f050a 0%,#060102 100%); color:var(--text); min-height:100vh; display:flex; flex-direction:column; }
    header { display:flex; justify-content:space-between; align-items:center; padding:18px 8%; border-bottom:1px solid var(--border); background:rgba(10,2,4,0.85); }
    .brand { font-size:18px; font-weight:800; letter-spacing:1.5px; }
    .brand span { color:var(--red); font-size:13px; margin-left:4px; }
    .status-badge { padding:6px 14px; border-radius:20px; font-size:11px; font-weight:700; border:1px solid rgba(16,185,129,0.4); background:rgba(16,185,129,0.1); color:var(--green); }
    #loginView { flex:1; display:flex; justify-content:center; align-items:center; padding:20px; }
    .login-card { background:var(--card); border:1px solid var(--border); box-shadow:0 0 40px var(--red-glow); padding:32px; border-radius:16px; width:100%; max-width:390px; text-align:center; }
    .login-card h3 { color:var(--red); font-size:14px; letter-spacing:1px; margin-bottom:20px; }
    input { width:100%; padding:12px 14px; background:#090204; border:1px solid var(--border); border-radius:8px; color:#fff; font-size:14px; outline:none; margin-bottom:14px; }
    input:focus { border-color:var(--red); }
    .btn { width:100%; padding:12px; background:var(--red); border:none; border-radius:8px; color:#fff; font-weight:700; cursor:pointer; letter-spacing:0.8px; transition:0.2s; }
    .btn:hover { filter:brightness(1.15); box-shadow:0 0 18px var(--red-glow); }
    .btn-sm { width:auto; padding:6px 10px; font-size:12px; margin-right:4px; }
    .btn-outline { background:transparent; border:1px solid var(--border); color:var(--muted); }
    .btn-outline:hover { border-color:var(--red); color:#fff; }
    #adminView { display:none; padding:28px 8%; gap:24px; flex-direction:column; }
    .stats-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; }
    .stat-card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px; text-align:center; }
    .stat-card .num { font-size:24px; font-weight:800; color:var(--red); margin-top:4px; }
    .grid-top { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:20px; }
    .panel-box { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; }
    .panel-box h4 { color:var(--red); margin-bottom:16px; font-size:14px; text-transform:uppercase; letter-spacing:1px; }
    .form-row { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
    table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
    th, td { padding:12px 10px; border-bottom:1px solid #24080e; text-align:left; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; }
    .key-badge { font-family:monospace; font-weight:700; color:#fda4af; background:#26070e; padding:4px 8px; border-radius:6px; cursor:pointer; }
    .tag-active { color:var(--green); font-weight:700; }
    .tag-locked { color:var(--red); font-weight:700; }
    #toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%); background:#140508; border:1px solid var(--red); box-shadow:0 0 20px var(--red-glow); color:#fff; padding:10px 22px; border-radius:30px; font-size:13px; display:none; z-index:9999; }
  </style>
</head>
<body>
  <header>
    <div class="brand">N VINH NOVA <span>ADMIN</span></div>
    <div class="status-badge">• SERVER ONLINE (v5.6)</div>
  </header>

  <div id="loginView">
    <div class="login-card">
      <h3>🔐 NHẬP ADMIN SECRET</h3>
      <input type="password" id="adminSecretInput" placeholder="Nhập mật khẩu (Mặc định: nvinhnova123)" onkeypress="if(event.key==='Enter') loginAdmin()" />
      <button class="btn" onclick="loginAdmin()">ĐĂNG NHẬP</button>
    </div>
  </div>

  <div id="adminView">
    <div class="stats-row">
      <div class="stat-card"><div style="font-size:12px;color:var(--muted)">TỔNG SỐ KEY</div><div class="num" id="stTotal">0</div></div>
      <div class="stat-card"><div style="font-size:12px;color:var(--muted)">ĐANG HOẠT ĐỘNG</div><div class="num" id="stActive" style="color:var(--green)">0</div></div>
      <div class="stat-card"><div style="font-size:12px;color:var(--muted)">ĐÃ KHÓA / HẾT HẠN</div><div class="num" id="stLocked">0</div></div>
      <div class="stat-card"><div style="font-size:12px;color:var(--muted)">THIẾT BỊ KẾT NỐI</div><div class="num" id="stDevs" style="color:#38bdf8">0</div></div>
    </div>

    <div class="grid-top">
      <div class="panel-box">
        <h4>⚡ Tạo Key Mới</h4>
        <input type="text" id="keyLabel" placeholder="Ghi chú / Tên khách hàng" />
        <input type="text" id="customKey" placeholder="Key tùy chỉnh (Để trống = Tự tạo NOVA-XXXX)" />
        <div class="form-row">
          <div>
            <label style="font-size:12px;color:var(--muted)">Thời hạn (Ngày - 0 = Vĩnh viễn)</label>
            <input type="number" id="keyDays" value="30" min="0" />
          </div>
          <div>
            <label style="font-size:12px;color:var(--muted)">Số thiết bị tối đa</label>
            <input type="number" id="keyDevs" value="1" min="1" />
          </div>
        </div>
        <label style="font-size:12px;color:var(--muted)">Số lượng Key muốn tạo</label>
        <input type="number" id="keyAmount" value="1" min="1" max="100" />
        <button class="btn" onclick="createNewKeys()">+ TẠO KEY NGAY</button>
      </div>

      <div class="panel-box" style="display:flex;flex-direction:column;">
        <h4>📋 Key Vừa Tạo</h4>
        <textarea id="createdOutput" readonly style="flex:1;width:100%;background:#090204;border:1px solid var(--border);border-radius:8px;color:#10b981;padding:12px;font-family:monospace;resize:none;" placeholder="Danh sách key mới tạo sẽ hiện tại đây..."></textarea>
        <div style="display:flex;gap:10px;margin-top:12px;">
          <button class="btn" onclick="copyCreatedKeys()">SAO CHÉP TẤT CẢ</button>
          <button class="btn btn-outline" onclick="logoutAdmin()">ĐĂNG XUẤT</button>
        </div>
      </div>
    </div>

    <div class="panel-box">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <h4>🗂️ Danh Sách Key (<span id="totalKeysCount">0</span>)</h4>
        <button class="btn btn-sm" onclick="loadAll()">🔄 Làm mới</button>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Mã Key (Click để copy)</th>
              <th>Ghi chú</th>
              <th>Thiết bị</th>
              <th>Thời hạn</th>
              <th>Trạng thái</th>
              <th>Hành động</th>
            </tr>
          </thead>
          <tbody id="keyTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    let ADMIN_SECRET = localStorage.getItem('NOVA_ADMIN_SECRET') || '';

    function showToast(msg, ok = false) {
      const t = document.getElementById('toast');
      t.style.borderColor = ok ? '#10b981' : '#e11d48';
      t.innerHTML = (ok ? '✅ ' : '❌ ') + msg;
      t.style.display = 'block';
      clearTimeout(window.toastTimer);
      window.toastTimer = setTimeout(() => { t.style.display = 'none'; }, 3500);
    }

    async function apiCall(endpoint, method = 'GET', bodyObj = null) {
      const options = {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + ADMIN_SECRET,
          'x-admin-secret': ADMIN_SECRET
        }
      };
      if (bodyObj) options.body = JSON.stringify(bodyObj);
      const res = await fetch(endpoint, options);
      const data = await res.json();
      if (!res.ok || data.ok === false) throw new Error(data.message || 'Lỗi xác thực');
      return data;
    }

    async function loginAdmin() {
      const val = document.getElementById('adminSecretInput').value.trim();
      if (!val) return showToast('Vui lòng nhập mật khẩu Admin!');
      ADMIN_SECRET = val;
      try {
        await apiCall('/api/admin/stats', 'GET');
        localStorage.setItem('NOVA_ADMIN_SECRET', ADMIN_SECRET);
        document.getElementById('loginView').style.display = 'none';
        document.getElementById('adminView').style.display = 'flex';
        showToast('Đăng nhập Admin thành công!', true);
        loadAll();
      } catch (e) { showToast(e.message); }
    }

    function logoutAdmin() {
      localStorage.removeItem('NOVA_ADMIN_SECRET');
      ADMIN_SECRET = '';
      document.getElementById('adminView').style.display = 'none';
      document.getElementById('loginView').style.display = 'flex';
    }

    async function loadAll() {
      try {
        const st = await apiCall('/api/admin/stats', 'GET');
        document.getElementById('stTotal').textContent = st.total || 0;
        document.getElementById('stActive').textContent = st.active || 0;
        document.getElementById('stLocked').textContent = (st.revoked || 0) + (st.expired || 0);
        document.getElementById('stDevs').textContent = st.devices || 0;
      } catch (_) {}
      loadKeys();
    }

    async function createNewKeys() {
      const label = document.getElementById('keyLabel').value.trim();
      const custom_key = document.getElementById('customKey').value.trim();
      const duration_days = parseInt(document.getElementById('keyDays').value) || 0;
      const max_devices = parseInt(document.getElementById('keyDevs').value) || 1;
      const amount = parseInt(document.getElementById('keyAmount').value) || 1;
      try {
        const data = await apiCall('/api/admin/create-key', 'POST', { label, custom_key, duration_days, max_devices, amount });
        document.getElementById('createdOutput').value = (data.keys || []).join('\\n');
        showToast('Đã tạo ' + data.keys.length + ' key!', true);
        loadAll();
      } catch (e) { showToast(e.message); }
    }

    function copyCreatedKeys() {
      const box = document.getElementById('createdOutput');
      if (!box.value) return showToast('Chưa có key nào!');
      navigator.clipboard.writeText(box.value);
      showToast('Đã sao chép tất cả!', true);
    }

    function copySingleKey(k) {
      navigator.clipboard.writeText(k);
      showToast('Đã copy: ' + k, true);
    }

    async function loadKeys() {
      try {
        const data = await apiCall('/api/admin/keys?limit=200', 'GET');
        document.getElementById('totalKeysCount').textContent = data.total || 0;
        const tbody = document.getElementById('keyTableBody');
        if (!data.keys || !data.keys.length) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted)">Chưa có key nào</td></tr>';
          return;
        }
        tbody.innerHTML = data.keys.map(k => {
          const exp = k.duration_days === 0 ? 'Vĩnh viễn' : (k.expires_at ? new Date(k.expires_at * 1000).toLocaleDateString('vi-VN') : k.duration_days + ' ngày (Chưa dùng)');
          const st = k.is_active ? '<span class="tag-active">Hoạt động</span>' : '<span class="tag-locked">Đã khóa</span>';
          return '<tr>' +
            '<td><span class="key-badge" onclick="copySingleKey(\\'' + k.key_code + '\\')">' + k.key_code + '</span></td>' +
            '<td>' + (k.label || '-') + '</td>' +
            '<td>' + (k.device_count || 0) + ' / ' + k.max_devices + '</td>' +
            '<td>' + exp + '</td>' +
            '<td>' + st + '</td>' +
            '<td>' +
              '<button class="btn btn-sm btn-outline" onclick="resetDevices(\\'' + k.key_code + '\\')">Reset Thiết Bị</button>' +
              (k.is_active
                ? '<button class="btn btn-sm btn-outline" onclick="toggleKey(\\'' + k.key_code + '\\', false)">Khóa</button>'
                : '<button class="btn btn-sm btn-outline" onclick="toggleKey(\\'' + k.key_code + '\\', true)">Mở</button>') +
              '<button class="btn btn-sm" style="background:#9f1239" onclick="deleteKey(\\'' + k.key_code + '\\')">Xóa</button>' +
            '</td></tr>';
        }).join('');
      } catch (e) { showToast(e.message); }
    }

    async function toggleKey(key, activate) {
      try {
        await apiCall(activate ? '/api/admin/activate' : '/api/admin/revoke', 'POST', { key });
        showToast('Đã cập nhật ' + key, true);
        loadAll();
      } catch (e) { showToast(e.message); }
    }

    async function resetDevices(key) {
      try {
        await apiCall('/api/admin/reset-devices', 'POST', { key });
        showToast('Đã reset thiết bị cho ' + key, true);
        loadAll();
      } catch (e) { showToast(e.message); }
    }

    async function deleteKey(key) {
      if (!confirm('Xóa vĩnh viễn key ' + key + '?')) return;
      try {
        await apiCall('/api/admin/delete', 'POST', { key });
        showToast('Đã xóa ' + key, true);
        loadAll();
      } catch (e) { showToast(e.message); }
    }

    window.addEventListener('DOMContentLoaded', () => {
      if (ADMIN_SECRET) {
        document.getElementById('adminSecretInput').value = ADMIN_SECRET;
        loginAdmin();
      }
    });
  </script>
</body>
</html>`;

app.get('/admin', (req, res) => res.send(ADMIN_HTML_PAGE));
app.get('/panel', (req, res) => res.send(ADMIN_HTML_PAGE));

/* ---------- PUBLIC ROUTES ---------- */
const healthHandler = (req, res) => res.json({
  ok: true,
  status: 'online',
  service: 'NVINH NOVA',
  version: '5.6.0',
  admin_panel: 'https://nova-nvinh.onrender.com/admin',
  time: Date.now()
});

app.get('/', healthHandler);
app.get('/health', healthHandler);
app.get('/api/health', healthHandler);
app.get('/api/status', healthHandler);

// API XÁC THỰC KEY (Đã tự động tạo device_id nếu client không gửi lên)
app.post('/api/verify-key', verifyLimiter, async (req, res) => {
  let { key, device_id: deviceId, user_agent: ua } = req.body || {};
  const ip = req.ip;
  const now = Math.floor(Date.now() / 1000);

  if (!key) return res.status(400).json({ ok: false, valid: false, message: 'Thiếu key' });
  const cleanKey = String(key).trim().toUpperCase();

  // Tự động sinh device_id tạm thời nếu app của khách không truyền lên để chống lỗi Database
  if (!deviceId || deviceId === 'null' || deviceId === 'undefined') {
    deviceId = 'AUTO-DEV-' + ip.replace(/[^a-zA-Z0-9]/g, '');
  }

  try {
    const { rows } = await pool.query('SELECT * FROM keys_nova WHERE key_code = $1', [cleanKey]);
    const row = rows[0];

    if (!row) {
      await logAction(null, 'verify_fail', deviceId, ip, 'Key không tồn tại');
      return res.status(404).json({ ok: false, valid: false, message: 'Key không tồn tại' });
    }
    if (!row.is_active) return res.status(403).json({ ok: false, valid: false, message: 'Key đã bị thu hồi' });
    if (row.expires_at && now > row.expires_at) return res.status(403).json({ ok: false, valid: false, message: 'Key đã hết hạn' });

    const { rows: devs } = await pool.query('SELECT device_id FROM devices_nova WHERE key_id = $1', [row.id]);
    const isKnown = devs.some(d => d.device_id === deviceId);

    if (!isKnown) {
      if (devs.length >= row.max_devices) {
        await logAction(row.id, 'verify_fail', deviceId, ip, 'Vượt số thiết bị');
        return res.status(403).json({ ok: false, valid: false, message: `Key đã kích hoạt tối đa ${row.max_devices} thiết bị.` });
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
    console.error('Verify Error:', err);
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

/* ---------- ADMIN API ROUTES ---------- */
const adminRouter = express.Router();
adminRouter.use(requireAdmin);

const statsHandler = async (req, res) => {
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

    res.json({
      ok: true,
      total, active, expired, revoked, locked: revoked, devices, logs,
      total_keys: total, active_keys: active, expired_keys: expired, revoked_keys: revoked, locked_keys: revoked, total_devices: devices, total_logs: logs,
      stats: { total, active, expired, revoked, devices, logs }
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
};

adminRouter.get('/stats', statsHandler);
adminRouter.get('/dashboard', statsHandler);
adminRouter.all('/login', statsHandler);
adminRouter.all('/verify', statsHandler);

const createKeyHandler = async (req, res) => {
  const { label = '', note = '', duration_days, days, duration, max_devices = 1, devices, amount = 1, count, custom_key = '', key = '', prefix = 'NOVA' } = req.body || {};
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

adminRouter.get('/keys', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const offset = (page - 1) * limit;
    const totalQ = await pool.query('SELECT COUNT(*)::int AS c FROM keys_nova');
    const total = totalQ.rows[0].c || 0;
    const rowsQ = await pool.query(`
      SELECT k.*, (SELECT COUNT(*)::int FROM devices_nova d WHERE d.key_id = k.id) AS device_count
      FROM keys_nova k
      ORDER BY k.created_at DESC LIMIT $1 OFFSET $2
    `, [limit, offset]);
    res.json({ ok: true, total, page, pages: Math.ceil(total / limit) || 1, keys: rowsQ.rows, data: rowsQ.rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

adminRouter.get('/logs', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const { rows } = await pool.query(`
      SELECT l.*, k.key_code FROM logs_nova l
      LEFT JOIN keys_nova k ON l.key_id = k.id
      ORDER BY l.created_at DESC LIMIT $1
    `, [limit]);
    res.json({ ok: true, logs: rows, data: rows });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

adminRouter.get('/devices', async (req, res) => {
  try {
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

const revokeHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.params?.key || '').trim().toUpperCase();
    const r = await pool.query('UPDATE keys_nova SET is_active = 0 WHERE key_code = $1 OR id::text = $1', [targetKey]);
    res.json({ ok: true, modified: r.rowCount });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.post('/revoke', revokeHandler);
adminRouter.post('/lock', revokeHandler);

const activateHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.params?.key || '').trim().toUpperCase();
    const r = await pool.query('UPDATE keys_nova SET is_active = 1 WHERE key_code = $1 OR id::text = $1', [targetKey]);
    res.json({ ok: true, modified: r.rowCount });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.post('/activate', activateHandler);
adminRouter.post('/unlock', activateHandler);

const resetDevicesHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.params?.key || '').trim().toUpperCase();
    const { rows } = await pool.query('SELECT id FROM keys_nova WHERE key_code = $1 OR id::text = $1', [targetKey]);
    if (!rows[0]) return res.status(404).json({ ok: false, message: 'Không tìm thấy key' });
    const r = await pool.query('DELETE FROM devices_nova WHERE key_id = $1', [rows[0].id]);
    res.json({ ok: true, reset: r.rowCount, deleted: r.rowCount });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.post('/reset-devices', resetDevicesHandler);
adminRouter.post('/reset', resetDevicesHandler);

const deleteKeyHandler = async (req, res) => {
  try {
    const targetKey = String(req.body?.key || req.body?.key_code || req.query?.key || req.params?.key || '').trim().toUpperCase();
    const r = await pool.query('DELETE FROM keys_nova WHERE key_code = $1 OR id::text = $1', [targetKey]);
    res.json({ ok: true, deleted: r.rowCount });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
};
adminRouter.delete('/delete', deleteKeyHandler);
adminRouter.post('/delete', deleteKeyHandler);

app.use('/api/admin', adminRouter);
app.use('/admin/api', adminRouter);

app.use((req, res) => {
  res.status(404).json({ ok: false, message: `Đường dẫn không tồn tại: ${req.method} ${req.originalUrl}` });
});

initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ NOVA Server v5.6.0 đang chạy tại http://0.0.0.0:${PORT}`);
      console.log(`👉 Truy cập Web Admin tại: https://nova-nvinh.onrender.com/admin`);
    });
  })
  .catch(err => {
    console.error('❌ Lỗi Database:', err);
    process.exit(1);
  });
