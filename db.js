const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');

// 数据持久化目录
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'shop.db');
const db = new DatabaseSync(dbPath);

// 启用 WAL 模式提高并发性能
db.exec('PRAGMA journal_mode = WAL;');

// 初始化表结构
db.exec(`
  -- 用户表 (密码全部使用 scrypt + 独立随机盐值哈希加密)
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT COLLATE NOCASE UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    balance REAL DEFAULT 0.00,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 卡密表
  CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    amount REAL NOT NULL,
    status INTEGER DEFAULT 0,
    used_by INTEGER,
    used_username TEXT,
    used_at DATETIME,
    batch_no TEXT,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 商品表
  CREATE TABLE IF NOT EXISTS goods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    category TEXT DEFAULT '虚拟服务',
    description TEXT,
    cover_url TEXT,
    require_input INTEGER DEFAULT 1,
    input_placeholder TEXT DEFAULT '请填写您的充值账号/区服信息/联系方式',
    stock INTEGER DEFAULT 9999,
    status INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 订单表 (user_inputs 和 admin_reply 支持 AES-256-GCM 强加密存储，保护买家隐私)
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_no TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    goods_id INTEGER NOT NULL,
    goods_name TEXT NOT NULL,
    price REAL NOT NULL,
    quantity INTEGER DEFAULT 1,
    total_price REAL NOT NULL,
    user_inputs TEXT,
    status INTEGER DEFAULT 0,
    admin_reply TEXT,
    finish_time DATETIME,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 余额流水日志
  CREATE TABLE IF NOT EXISTS balance_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    balance_after REAL NOT NULL,
    remark TEXT,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 系统设置
  CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// ==================== 1. 密码单向不可逆加密 (scrypt + 盐) ====================
// scrypt 是目前防范彩虹表与超级计算机/GPU暴力破解的工业最高级别密码哈希算法
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return check === hash;
}

// ==================== 2. 敏感数据对称加密 (AES-256-GCM) ====================
// 用于将买家填写的账号、密码或代办隐私信息加密入库，即便数据库被盗取也绝无法解密明文
const DATA_ENCRYPT_KEY = crypto.scryptSync('spark-shop-privacy-secret-key-2026', 'salt-pepper', 32);

function encryptText(plainText) {
  if (!plainText) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', DATA_ENCRYPT_KEY, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  // 密文结构：iv:authTag:encrypted
  return `ENC:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptText(cipherText) {
  if (!cipherText) return '';
  if (!cipherText.startsWith('ENC:')) return cipherText; // 兼容非密文历史数据
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

// 初始化默认数据
function initDefaultData() {
  const adminStmt = db.prepare('SELECT id FROM users WHERE is_admin = 1 LIMIT 1');
  const admin = adminStmt.get();
  if (!admin) {
    // 默认新创建管理员，密码设置为 Zy060206
    const { hash, salt } = hashPassword('Zy060206');
    const insertAdmin = db.prepare(`
      INSERT INTO users (username, password_hash, salt, balance, is_admin)
      VALUES (?, ?, ?, 0.00, 1)
    `);
    insertAdmin.run('admin', hash, salt);
    console.log('[系统提示] 管理员账号已初始化，密码已设为强加密的指定密码');
  }

  // 示例商品
  const goodsCountStmt = db.prepare('SELECT COUNT(*) as count FROM goods');
  const { count } = goodsCountStmt.get();
  if (count === 0) {
    const insertGood = db.prepare(`
      INSERT INTO goods (name, price, category, description, cover_url, require_input, input_placeholder, stock, sort_order)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertGood.run(
      '游戏月卡/点卡人工直充',
      30.00,
      '游戏代充',
      '请在下单时务必填写您的游戏平台（安卓/苹果）、游戏ID及账号。站长后台接单后会在15分钟内代充到账！',
      'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=500&auto=format&fit=crop&q=60',
      1,
      '请填写【游戏名称 + 渠道 + 游戏账号/ID】',
      999,
      1
    );
    insertGood.run(
      '网盘VIP会员人工激活代办',
      15.00,
      '软件会员',
      '支持官方直冲，下单请留下您的绑定手机号。完成充值后可在本站“我的订单”查看充值到账回执。',
      'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=500&auto=format&fit=crop&q=60',
      1,
      '请填写【需要开通会员的手机号】',
      999,
      2
    );
    insertGood.run(
      '专属定制技术咨询服务（1对1）',
      50.00,
      '咨询代办',
      '站长1对1提供技术支持与咨询，下单请填写您的联系QQ或微信及咨询的具体问题概要。',
      'https://images.unsplash.com/photo-1551836022-d5d88e9218df?w=500&auto=format&fit=crop&q=60',
      1,
      '请填写【您的微信/QQ号 + 问题简要说明】',
      999,
      3
    );
  }

  // 示例体验卡密
  const cardCountStmt = db.prepare('SELECT COUNT(*) as count FROM cards');
  if (cardCountStmt.get().count === 0) {
    const insertCard = db.prepare(`
      INSERT INTO cards (code, amount, status, batch_no)
      VALUES (?, ?, 0, 'INITIAL_BATCH')
    `);
    insertCard.run('TEST-100RMB-AAAA-BBBB', 100.00);
    insertCard.run('TEST-50RMB-CCCC-DDDD', 50.00);
    insertCard.run('TEST-30RMB-EEEE-FFFF', 30.00);
  }

  // 站点配置
  const getSetting = db.prepare('SELECT value FROM system_settings WHERE key = ?');
  if (!getSetting.get('site_name')) {
    db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)').run('site_name', '星火卡密商城与代办服务');
  }
  if (!getSetting.get('site_announcement')) {
    db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)').run(
      'site_announcement',
      '欢迎光临！请在“联动小铺”购买专属充值卡密，并在本站右上角输入卡密兑换余额后下单。'
    );
  }
  if (!getSetting.get('contact_info')) {
    db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)').run(
      'contact_info',
      '客服微信：ShopAdmin'
    );
  }
}

initDefaultData();

module.exports = {
  db,
  hashPassword,
  verifyPassword,
  encryptText,
  decryptText
};
