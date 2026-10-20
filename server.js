/* =========================================================
   NVINH NOVA — KEY SERVER v3.1.0 (Auto-Fix DB)
   ========================================================= */
require('dotenv').config();
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDb() {
  try {
    console.log('⏳ Đang kiểm tra Database...');
    // 1. Thử tìm cột is_active. Nếu lỗi -> Bảng cũ bị thiếu cột -> Xóa và tạo lại
    await pool.query('SELECT is_active FROM keys LIMIT 1');
    console.log('✅ Bảng keys đã tồn tại và đầy đủ cột.');
  } catch (err) {
    if (err.code === '42P01' || err.code === '42703') {
      console.log('⚠️ Bảng keys bị lỗi hoặc thiếu cột. Đang tự động xóa và tạo lại...');
      await pool.query('DROP TABLE IF EXISTS keys CASCADE');
      await pool.query(`
        CREATE TABLE keys (
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
      `);
      console.log('✅ Đã tạo lại bảng keys thành công!');
    } else {
      throw err;
    }
  }

  // Tạo các bảng phụ (nếu chưa có)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY, key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL, first_seen BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
      last_seen BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()), user_agent TEXT, ip TEXT,
      UNIQUE(key_id, device_id)
    );
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY, key_id INTEGER REFERENCES keys(id) ON DELETE SET NULL,
      action TEXT NOT NULL, device_id TEXT, ip TEXT, detail TEXT,
      created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())
    );
  `);
  console.log('✅ Database khởi tạo xong hoàn toàn!');
}

// (Các phần code API bên dưới giữ nguyên như bản v3.0)
// ...
