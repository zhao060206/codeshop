const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');

// 数据持久化目录，确保存在
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'shop.db');
const db = new DatabaseSync(dbPath);

// 启用 WAL 模式提高并发与性能
db.exec('PRAGMA journal_mode = WAL;');

// 初始化表结构
db.exec(`
  -- 用户表
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
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
    status INTEGER DEFAULT 0, -- 0: 未使用, 1: 已使用, 2: 已作废
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
    require_input INTEGER DEFAULT 1, -- 是否需要买家填写指定定制信息
    input_placeholder TEXT DEFAULT '请填写您的充值账号/区服信息/联系方式',
    stock INTEGER DEFAULT 9999,
    status INTEGER DEFAULT 1, -- 1 上架, 0 下架
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 订单表
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
    user_inputs TEXT, -- 买家填写的账号或需求信息
    status INTEGER DEFAULT 0, -- 0: 待处理/接单中, 1: 已完成, 2: 已退款/已取消
    admin_reply TEXT, -- 站长处理结果/回执
    finish_time DATETIME,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 余额明细流水表
  CREATE TABLE IF NOT EXISTS balance_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    type TEXT NOT NULL, -- 'redeem' 卡密兑换, 'purchase' 购买商品, 'admin_adjust' 管理员操作
    amount REAL NOT NULL,
    balance_after REAL NOT NULL,
    remark TEXT,
    created_at DATETIME DEFAULT (datetime('now', 'localtime'))
  );

  -- 系统设置表
  CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// 密码加密辅助函数 (基于原生 crypto.scryptSync)
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return check === hash;
}

// 初始化默认数据
function initDefaultData() {
  // 1. 检查是否存在管理员，若无则创建
  const adminStmt = db.prepare('SELECT id FROM users WHERE is_admin = 1 LIMIT 1');
  const admin = adminStmt.get();
  if (!admin) {
    const { hash, salt } = hashPassword('admin123');
    const insertAdmin = db.prepare(`
      INSERT INTO users (username, password_hash, salt, balance, is_admin)
      VALUES (?, ?, ?, 0.00, 1)
    `);
    insertAdmin.run('admin', hash, salt);
    console.log('[系统提示] 默认管理员已创建：账号 admin 密码 admin123');
  }

  // 2. 检查是否有示例商品
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
    console.log('[系统提示] 已初始化 3 个示例商品');
  }

  // 3. 检查是否有测试卡密，若无生成几张体验卡密
  const cardCountStmt = db.prepare('SELECT COUNT(*) as count FROM cards');
  const cardRes = cardCountStmt.get();
  if (cardRes.count === 0) {
    const insertCard = db.prepare(`
      INSERT INTO cards (code, amount, status, batch_no)
      VALUES (?, ?, 0, 'INITIAL_BATCH')
    `);
    insertCard.run('TEST-100RMB-AAAA-BBBB', 100.00);
    insertCard.run('TEST-50RMB-CCCC-DDDD', 50.00);
    insertCard.run('TEST-30RMB-EEEE-FFFF', 30.00);
    insertCard.run('TEST-10RMB-GGGG-HHHH', 10.00);
    console.log('[系统提示] 已初始化 4 张测试体验卡密（如：TEST-100RMB-AAAA-BBBB 价值100元）');
  }

  // 4. 初始化系统设置
  const getSetting = db.prepare('SELECT value FROM system_settings WHERE key = ?');
  if (!getSetting.get('site_name')) {
    db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)').run('site_name', '星火卡密商城与代办服务');
  }
  if (!getSetting.get('site_announcement')) {
    db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)').run(
      'site_announcement',
      '欢迎光临！请在“联动小铺”或站长指定渠道购买充值卡密，并在本站右上角兑换余额后下单。下单后站长将在后台极速处理！'
    );
  }
  if (!getSetting.get('contact_info')) {
    db.prepare('INSERT INTO system_settings (key, value) VALUES (?, ?)').run(
      'contact_info',
      '客服微信：ShopAdmin / 联动小铺店铺号：888888'
    );
  }
}

initDefaultData();

module.exports = {
  db,
  hashPassword,
  verifyPassword
};
