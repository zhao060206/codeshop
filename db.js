const crypto = require('node:crypto');

// Turso 云数据库连接配置
const TURSO_URL = (process.env.TURSO_DATABASE_URL || 'https://codes-zhao060206.aws-ap-northeast-1.turso.io')
  .replace(/^libsql:\/\//, 'https://') + '/v2/pipeline';

const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN || 
  'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODg0MDM2OTgsImlkIjoiMDFhMDY1MmEtYTcwMS03MjY4LWI3NTItNmE2MzJkNTE0ODlkIiwia2lkIjoiSkk4bkptWUhMMWZHV1VVRko1cnprYUdraWhodlVCQmFmWDhoM2dUdXo3TSIsInJpZCI6IjFlN2Q4ZTFiLWYxNDYtNDZkOC1iMDAwLWFkY2NlNWJhZTdkZiJ9.UAWRKu7Aqjztd9tNWeE4wyuYRUI0og4tlwCK3T3ENrka4aMdESyB6wdaRBYuBMyUEAAj1N9ludFbnc2MDSSMBQ';

// 密码单向不可逆哈希加密 (scrypt + 盐)
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return check === hash;
}

// 敏感代办数据强加密 (AES-256-GCM)
const DATA_ENCRYPT_KEY = crypto.scryptSync('spark-shop-privacy-secret-key-2026', 'salt-pepper', 32);

function encryptText(plainText) {
  if (!plainText) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', DATA_ENCRYPT_KEY, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `ENC:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptText(cipherText) {
  if (!cipherText) return '';
  if (!cipherText.startsWith('ENC:')) return cipherText;
  try {
    const parts = cipherText.split(':');
    if (parts.length !== 4) return cipherText;
    const iv = Buffer.from(parts[1], 'hex');
    const authTag = Buffer.from(parts[2], 'hex');
    const encrypted = parts[3];
    const decipher = crypto.createDecipheriv('aes-256-gcm', DATA_ENCRYPT_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return '【解密失败或数据损坏】';
  }
}

// ==================== Turso 原生 HTTP Pipeline 驱动封装 ====================
async function executeSql(sql, args = []) {
  const rawArgs = args.map(a => {
    if (a === null || a === undefined) return { type: 'null' };
    if (typeof a === 'number') {
      return Number.isInteger(a) ? { type: 'integer', value: a.toString() } : { type: 'float', value: a };
    }
    return { type: 'text', value: a.toString() };
  });

  const res = await fetch(TURSO_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${TURSO_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      requests: [
        {
          type: 'execute',
          stmt: { sql, args: rawArgs }
        },
        { type: 'close' }
      ]
    })
  });

  const data = await res.json();
  if (data.results && data.results[0] && data.results[0].type === 'ok') {
    const r = data.results[0].response.result;
    const cols = r.cols.map(c => c.name);
    const rows = r.rows.map(row => {
      const obj = {};
      row.forEach((cell, idx) => {
        let val = cell.value;
        if (cell.type === 'integer') val = parseInt(val, 10);
        else if (cell.type === 'float') val = parseFloat(val);
        else if (cell.type === 'null') val = null;
        obj[cols[idx]] = val;
      });
      return obj;
    });
    return {
      rows,
      rowsAffected: r.affected_row_count || 0,
      lastInsertRowid: r.last_insert_rowid ? Number(r.last_insert_rowid) : null
    };
  } else {
    const err = data.results?.[0]?.error?.message || JSON.stringify(data);
    throw new Error(err);
  }
}

// 类似 SQLite 的便携 API 封装
const db = {
  // 查询单条
  async get(sql, params = []) {
    const res = await executeSql(sql, params);
    return res.rows.length > 0 ? res.rows[0] : null;
  },
  // 查询多条
  async all(sql, params = []) {
    const res = await executeSql(sql, params);
    return res.rows;
  },
  // 执行增删改
  async run(sql, params = []) {
    const res = await executeSql(sql, params);
    return {
      changes: res.rowsAffected,
      lastInsertRowid: res.lastInsertRowid
    };
  },
  // 事务批量执行
  async batch(stmts) {
    const requests = stmts.map(s => {
      const sql = typeof s === 'string' ? s : s.sql;
      const rawArgs = (s.args || []).map(a => {
        if (a === null || a === undefined) return { type: 'null' };
        if (typeof a === 'number') {
          return Number.isInteger(a) ? { type: 'integer', value: a.toString() } : { type: 'float', value: a };
        }
        return { type: 'text', value: a.toString() };
      });
      return { type: 'execute', stmt: { sql, args: rawArgs } };
    });
    requests.push({ type: 'close' });

    const res = await fetch(TURSO_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TURSO_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ requests })
    });
    return await res.json();
  }
};

module.exports = {
  db,
  hashPassword,
  verifyPassword,
  encryptText,
  decryptText
};
