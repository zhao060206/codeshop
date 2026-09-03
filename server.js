const express = require('express');
const cors = require('cors');
const path = require('node:path');
const crypto = require('node:crypto');
const { db, hashPassword, verifyPassword } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'spark-card-shop-ultra-secure-key-2026';

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静态文件托管
app.use(express.static(path.join(__dirname, 'public')));

// ==================== 安全 Token 机制 ====================
function generateToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      username: user.username,
      is_admin: user.is_admin,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7天有效
    })
  ).toString('base64url');
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');
  if (signature !== expectedSig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// 身份校验中间件
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ code: 401, message: '请先登录' });
  }
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ code: 401, message: '登录状态已失效，请重新登录' });
  }
  req.user = decoded;
  next();
}

// 管理员权限中间件
function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.is_admin) {
      return res.status(403).json({ code: 403, message: '无管理员访问权限' });
    }
    next();
  });
}

// ==================== 1. 用户认证模块 ====================

// 注册
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ code: 400, message: '用户名和密码不能为空' });
  }
  if (username.length < 3 || username.length > 20) {
    return res.status(400).json({ code: 400, message: '用户名长度需在 3 到 20 位之间' });
  }
  if (password.length < 6) {
    return res.status(400).json({ code: 400, message: '密码长度不能少于 6 位' });
  }

  // 检查是否重名
  const existUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existUser) {
    return res.status(400).json({ code: 400, message: '该用户名已被注册，请更换一个' });
  }

  const { hash, salt } = hashPassword(password);
  try {
    const insertStmt = db.prepare(`
      INSERT INTO users (username, password_hash, salt, balance, is_admin)
      VALUES (?, ?, ?, 0.00, 0)
    `);
    const result = insertStmt.run(username, hash, salt);
    const userId = Number(result.lastInsertRowid);
    const user = { id: userId, username, balance: 0.00, is_admin: 0 };
    const token = generateToken(user);
    res.json({
      code: 200,
      message: '注册成功',
      data: { token, user }
    });
  } catch (err) {
    console.error('注册错误:', err);
    res.status(500).json({ code: 500, message: '注册失败，请稍后重试' });
  }
});

// 登录
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ code: 400, message: '请输入用户名和密码' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !verifyPassword(password, user.password_hash, user.salt)) {
    return res.status(400).json({ code: 400, message: '用户名或密码错误' });
  }

  const userData = {
    id: user.id,
    username: user.username,
    balance: user.balance,
    is_admin: user.is_admin
  };
  const token = generateToken(userData);

  res.json({
    code: 200,
    message: '登录成功',
    data: { token, user: userData }
  });
});

// 获取当前用户信息及余额
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, balance, is_admin, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ code: 404, message: '用户不存在' });
  }
  res.json({ code: 200, data: user });
});

// 修改密码
app.post('/api/auth/change-password', authMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ code: 400, message: '原密码和新密码均不能为空' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ code: 400, message: '新密码不能少于 6 位' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!verifyPassword(oldPassword, user.password_hash, user.salt)) {
    return res.status(400).json({ code: 400, message: '原密码验证不正确' });
  }

  const { hash, salt } = hashPassword(newPassword);
  db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').run(hash, salt, user.id);
  res.json({ code: 200, message: '密码修改成功，请牢记新密码' });
});

// ==================== 2. 卡密兑换与管理模块 ====================

// 买家前台：卡密兑换余额
app.post('/api/cards/redeem', authMiddleware, (req, res) => {
  const { code } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ code: 400, message: '请输入有效的卡密字符串' });
  }

  const cleanCode = code.trim();
  const card = db.prepare('SELECT * FROM cards WHERE code = ?').get(cleanCode);

  if (!card) {
    return res.status(400).json({ code: 400, message: '卡密不存在或输入有误，请核对' });
  }
  if (card.status === 1) {
    return res.status(400).json({
      code: 400,
      message: `该卡密已于 ${card.used_at || '之前'} 被使用，不可重复兑换`
    });
  }
  if (card.status === 2) {
    return res.status(400).json({ code: 400, message: '该卡密已被管理员作废' });
  }

  // 执行原子事务：标记卡密已用，增加用户余额，记录日志
  try {
    db.exec('BEGIN TRANSACTION;');

    // 1. 标记卡密
    db.prepare(`
      UPDATE cards 
      SET status = 1, used_by = ?, used_username = ?, used_at = datetime('now', 'localtime')
      WHERE id = ? AND status = 0
    `).run(req.user.id, req.user.username, card.id);

    // 2. 增加用户余额
    db.prepare(`
      UPDATE users 
      SET balance = balance + ? 
      WHERE id = ?
    `).run(card.amount, req.user.id);

    // 3. 读取更新后的余额
    const updatedUser = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);

    // 4. 写入流水记录
    db.prepare(`
      INSERT INTO balance_logs (user_id, username, type, amount, balance_after, remark)
      VALUES (?, ?, 'redeem', ?, ?, ?)
    `).run(
      req.user.id,
      req.user.username,
      card.amount,
      updatedUser.balance,
      `卡密兑换到账 (面额: ¥${card.amount.toFixed(2)}, 卡号: ${card.code})`
    );

    db.exec('COMMIT;');

    res.json({
      code: 200,
      message: `恭喜！成功兑换 ¥${card.amount.toFixed(2)} 元`,
      data: {
        amount: card.amount,
        new_balance: updatedUser.balance
      }
    });
  } catch (err) {
    db.exec('ROLLBACK;');
    console.error('兑换卡密异常:', err);
    res.status(500).json({ code: 500, message: '兑换处理异常，请重试' });
  }
});

// 管理员：批量生成卡密
app.post('/api/admin/cards/generate', adminMiddleware, (req, res) => {
  const { amount, count, prefix = 'CARD', batch_name = '' } = req.body;
  const numAmount = parseFloat(amount);
  const numCount = parseInt(count, 10);

  if (isNaN(numAmount) || numAmount <= 0) {
    return res.status(400).json({ code: 400, message: '请输入有效的卡密面值' });
  }
  if (isNaN(numCount) || numCount < 1 || numCount > 500) {
    return res.status(400).json({ code: 400, message: '生成数量必须在 1 到 500 张之间' });
  }

  const batchNo = `BATCH-${Date.now().toString().slice(-6)}`;
  const cleanPrefix = (prefix.trim().toUpperCase() || 'CARD').replace(/[^A-Z0-9]/g, '');

  const generatedCards = [];
  const insertCard = db.prepare(`
    INSERT INTO cards (code, amount, status, batch_no)
    VALUES (?, ?, 0, ?)
  `);

  try {
    db.exec('BEGIN TRANSACTION;');
    for (let i = 0; i < numCount; i++) {
      // 生成格式如: CARD-88A1-B9C2-D3E4
      const rand1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const rand2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const rand3 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const code = `${cleanPrefix}-${rand1}-${rand2}-${rand3}`;

      insertCard.run(code, numAmount, batch_name ? `${batch_name} (${batchNo})` : batchNo);
      generatedCards.push(code);
    }
    db.exec('COMMIT;');

    res.json({
      code: 200,
      message: `成功生成 ${numCount} 张面值 ¥${numAmount.toFixed(2)} 的卡密！`,
      data: {
        batch_no: batchNo,
        amount: numAmount,
        count: numCount,
        cards: generatedCards
      }
    });
  } catch (err) {
    db.exec('ROLLBACK;');
    console.error('批量生成卡密异常:', err);
    res.status(500).json({ code: 500, message: '生成失败，请稍后重试' });
  }
});

// 管理员：获取卡密列表
app.get('/api/admin/cards', adminMiddleware, (req, res) => {
  const { status, search, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);

  let whereClauses = [];
  let params = [];

  if (status !== undefined && status !== '') {
    whereClauses.push('status = ?');
    params.push(parseInt(status, 10));
  }
  if (search) {
    whereClauses.push('(code LIKE ? OR batch_no LIKE ? OR used_username LIKE ?)');
    const term = `%${search}%`;
    params.push(term, term, term);
  }

  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  const totalStmt = db.prepare(`SELECT COUNT(*) as total FROM cards ${whereSql}`);
  const total = totalStmt.get(...params).total;

  const listStmt = db.prepare(`
    SELECT * FROM cards 
    ${whereSql}
    ORDER BY id DESC 
    LIMIT ? OFFSET ?
  `);
  const cards = listStmt.all(...params, parseInt(limit, 10), offset);

  // 统计概览
  const stats = db.prepare(`
    SELECT 
      COUNT(*) as total_count,
      SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as unused_count,
      SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as used_count,
      SUM(CASE WHEN status = 0 THEN amount ELSE 0 END) as unused_amount,
      SUM(CASE WHEN status = 1 THEN amount ELSE 0 END) as used_amount
    FROM cards
  `).get();

  res.json({
    code: 200,
    data: {
      total,
      cards,
      stats: {
        total_count: stats.total_count || 0,
        unused_count: stats.unused_count || 0,
        used_count: stats.used_count || 0,
        unused_amount: (stats.unused_amount || 0).toFixed(2),
        used_amount: (stats.used_amount || 0).toFixed(2)
      }
    }
  });
});

// 管理员：作废卡密
app.post('/api/admin/cards/:id/void', adminMiddleware, (req, res) => {
  const cardId = parseInt(req.params.id, 10);
  const card = db.prepare('SELECT * FROM cards WHERE id = ?').get(cardId);
  if (!card) {
    return res.status(404).json({ code: 404, message: '卡密不存在' });
  }
  if (card.status === 1) {
    return res.status(400).json({ code: 400, message: '已使用的卡密无法作废' });
  }

  db.prepare('UPDATE cards SET status = 2 WHERE id = ?').run(cardId);
  res.json({ code: 200, message: '卡密已成功作废' });
});

// ==================== 3. 商品发布与展示模块 ====================

// 买家端：获取已上架商品
app.get('/api/goods', (req, res) => {
  const goods = db.prepare(`
    SELECT id, name, price, category, description, cover_url, require_input, input_placeholder, stock 
    FROM goods 
    WHERE status = 1 
    ORDER BY sort_order ASC, id DESC
  `).all();
  res.json({ code: 200, data: goods });
});

// 买家端：获取商品详情
app.get('/api/goods/:id', (req, res) => {
  const good = db.prepare('SELECT * FROM goods WHERE id = ? AND status = 1').get(req.params.id);
  if (!good) {
    return res.status(404).json({ code: 404, message: '商品不存在或已下架' });
  }
  res.json({ code: 200, data: good });
});

// 管理员端：获取所有商品（包括下架）
app.get('/api/admin/goods', adminMiddleware, (req, res) => {
  const goods = db.prepare('SELECT * FROM goods ORDER BY sort_order ASC, id DESC').all();
  res.json({ code: 200, data: goods });
});

// 管理员端：新增商品
app.post('/api/admin/goods', adminMiddleware, (req, res) => {
  const { name, price, category, description, cover_url, require_input, input_placeholder, stock, sort_order } = req.body;
  if (!name || price === undefined) {
    return res.status(400).json({ code: 400, message: '商品名称和价格为必填项' });
  }

  const numPrice = parseFloat(price);
  if (isNaN(numPrice) || numPrice <= 0) {
    return res.status(400).json({ code: 400, message: '商品价格必须大于0' });
  }

  const stmt = db.prepare(`
    INSERT INTO goods (name, price, category, description, cover_url, require_input, input_placeholder, stock, sort_order, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `);

  const result = stmt.run(
    name.trim(),
    numPrice,
    (category || '虚拟商品').trim(),
    description || '',
    cover_url || '',
    require_input !== undefined ? parseInt(require_input, 10) : 1,
    input_placeholder || '请填写您的代办账号/区服信息/具体需求',
    stock !== undefined ? parseInt(stock, 10) : 9999,
    sort_order !== undefined ? parseInt(sort_order, 10) : 0
  );

  res.json({ code: 200, message: '商品发布成功', data: { id: Number(result.lastInsertRowid) } });
});

// 管理员端：修改商品
app.put('/api/admin/goods/:id', adminMiddleware, (req, res) => {
  const goodId = parseInt(req.params.id, 10);
  const { name, price, category, description, cover_url, require_input, input_placeholder, stock, sort_order, status } = req.body;

  const good = db.prepare('SELECT id FROM goods WHERE id = ?').get(goodId);
  if (!good) {
    return res.status(404).json({ code: 404, message: '商品不存在' });
  }

  db.prepare(`
    UPDATE goods 
    SET name = ?, price = ?, category = ?, description = ?, cover_url = ?, require_input = ?, input_placeholder = ?, stock = ?, sort_order = ?, status = ?
    WHERE id = ?
  `).run(
    name,
    parseFloat(price),
    category,
    description,
    cover_url,
    parseInt(require_input, 10),
    input_placeholder,
    parseInt(stock, 10),
    parseInt(sort_order, 10),
    parseInt(status, 10),
    goodId
  );

  res.json({ code: 200, message: '商品修改成功' });
});

// 管理员端：切换商品上下架
app.patch('/api/admin/goods/:id/status', adminMiddleware, (req, res) => {
  const goodId = parseInt(req.params.id, 10);
  const { status } = req.body;
  db.prepare('UPDATE goods SET status = ? WHERE id = ?').run(parseInt(status, 10), goodId);
  res.json({ code: 200, message: status === 1 ? '商品已成功上架' : '商品已下架' });
});

// ==================== 4. 订单与代办处理模块 ====================

// 买家端：用余额下单购买商品（带自定义信息提交）
app.post('/api/orders/create', authMiddleware, (req, res) => {
  const { goods_id, quantity = 1, user_inputs } = req.body;
  const numQty = parseInt(quantity, 10);

  if (isNaN(numQty) || numQty < 1) {
    return res.status(400).json({ code: 400, message: '购买数量必须至少为 1' });
  }

  const good = db.prepare('SELECT * FROM goods WHERE id = ? AND status = 1').get(goods_id);
  if (!good) {
    return res.status(400).json({ code: 400, message: '该商品已下架或不存在' });
  }
  if (good.stock < numQty) {
    return res.status(400).json({ code: 400, message: '该商品库存不足' });
  }

  // 如果该商品要求买家填写指定信息，必须校验
  if (good.require_input && (!user_inputs || !user_inputs.trim())) {
    return res.status(400).json({
      code: 400,
      message: `请填写【${good.input_placeholder || '指定信息'}】，以便站长为您完成服务`
    });
  }

  const totalPrice = parseFloat((good.price * numQty).toFixed(2));

  // 检查买家当前余额
  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  if (!user || user.balance < totalPrice) {
    const diff = (totalPrice - (user ? user.balance : 0)).toFixed(2);
    return res.status(400).json({
      code: 402,
      message: `账户余额不足！本单需支付 ¥${totalPrice.toFixed(2)}，当前余额 ¥${(user ? user.balance : 0).toFixed(2)}（尚缺 ¥${diff}）。请先在右上角使用卡密充值。`
    });
  }

  // 生成唯一订单编号 ORD-年月日-随机串
  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const randSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
  const orderNo = `ORD-${dateStr}-${randSuffix}`;

  try {
    db.exec('BEGIN TRANSACTION;');

    // 1. 扣除买家余额
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(totalPrice, req.user.id);

    // 2. 扣除商品库存
    db.prepare('UPDATE goods SET stock = stock - ? WHERE id = ?').run(numQty, good.id);

    // 3. 创建订单记录
    const orderStmt = db.prepare(`
      INSERT INTO orders (order_no, user_id, username, goods_id, goods_name, price, quantity, total_price, user_inputs, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `);
    const orderRes = orderStmt.run(
      orderNo,
      req.user.id,
      req.user.username,
      good.id,
      good.name,
      good.price,
      numQty,
      totalPrice,
      (user_inputs || '').trim()
    );

    // 4. 写入余额流水记录
    const updatedUser = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
    db.prepare(`
      INSERT INTO balance_logs (user_id, username, type, amount, balance_after, remark)
      VALUES (?, ?, 'purchase', ?, ?, ?)
    `).run(
      req.user.id,
      req.user.username,
      -totalPrice,
      updatedUser.balance,
      `购买商品：${good.name} x${numQty} (订单号: ${orderNo})`
    );

    db.exec('COMMIT;');

    res.json({
      code: 200,
      message: '下单成功！站长将在后台极速为您处理，您可在“我的订单”随时查看处理进度。',
      data: {
        order_id: Number(orderRes.lastInsertRowid),
        order_no: orderNo,
        goods_name: good.name,
        total_price: totalPrice,
        new_balance: updatedUser.balance
      }
    });
  } catch (err) {
    db.exec('ROLLBACK;');
    console.error('下单事务异常:', err);
    res.status(500).json({ code: 500, message: '下单失败，请稍后重试' });
  }
});

// 买家端：查看自己的订单列表
app.get('/api/orders/my', authMiddleware, (req, res) => {
  const orders = db.prepare(`
    SELECT * FROM orders 
    WHERE user_id = ? 
    ORDER BY id DESC
  `).all(req.user.id);
  res.json({ code: 200, data: orders });
});

// 管理员端：获取所有订单（支持筛选）
app.get('/api/admin/orders', adminMiddleware, (req, res) => {
  const { status, search, page = 1, limit = 50 } = req.query;
  const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);

  let whereClauses = [];
  let params = [];

  if (status !== undefined && status !== '') {
    whereClauses.push('status = ?');
    params.push(parseInt(status, 10));
  }
  if (search) {
    whereClauses.push('(order_no LIKE ? OR username LIKE ? OR goods_name LIKE ? OR user_inputs LIKE ?)');
    const term = `%${search}%`;
    params.push(term, term, term, term);
  }

  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  const total = db.prepare(`SELECT COUNT(*) as total FROM orders ${whereSql}`).get(...params).total;
  const orders = db.prepare(`
    SELECT * FROM orders 
    ${whereSql} 
    ORDER BY id DESC 
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit, 10), offset);

  // 待处理与总计统计
  const stats = db.prepare(`
    SELECT 
      COUNT(*) as total_orders,
      SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as pending_orders,
      SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as completed_orders,
      SUM(CASE WHEN status = 1 THEN total_price ELSE 0 END) as total_sales
    FROM orders
  `).get();

  res.json({
    code: 200,
    data: {
      total,
      orders,
      stats: {
        total_orders: stats.total_orders || 0,
        pending_orders: stats.pending_orders || 0,
        completed_orders: stats.completed_orders || 0,
        total_sales: (stats.total_sales || 0).toFixed(2)
      }
    }
  });
});

// 管理员端：处理订单（完成/交付回执，或退款）
app.post('/api/admin/orders/:id/process', adminMiddleware, (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  const { status, admin_reply } = req.body;
  const targetStatus = parseInt(status, 10); // 1: 完成, 2: 退款

  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) {
    return res.status(404).json({ code: 404, message: '订单不存在' });
  }

  if (targetStatus === 1) {
    // 标记已完成，并保存站长回执信息
    db.prepare(`
      UPDATE orders 
      SET status = 1, admin_reply = ?, finish_time = datetime('now', 'localtime')
      WHERE id = ?
    `).run(admin_reply || '站长已处理完成！', orderId);

    return res.json({ code: 200, message: '订单已成功标记为【已完成】，买家端已同步更新！' });
  } else if (targetStatus === 2) {
    // 全额退款回用户余额
    if (order.status === 2) {
      return res.status(400).json({ code: 400, message: '该订单此前已经退款，不可重复退款' });
    }

    try {
      db.exec('BEGIN TRANSACTION;');

      // 1. 更新订单为已退款
      db.prepare(`
        UPDATE orders 
        SET status = 2, admin_reply = ?, finish_time = datetime('now', 'localtime')
        WHERE id = ?
      `).run(admin_reply ? `【已退款】${admin_reply}` : '【已退款】订单已取消并全额退回账户余额', orderId);

      // 2. 资金退回买家余额
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(order.total_price, order.user_id);

      // 3. 回滚库存
      db.prepare('UPDATE goods SET stock = stock + ? WHERE id = ?').run(order.quantity, order.goods_id);

      // 4. 写入流水
      const updatedUser = db.prepare('SELECT balance FROM users WHERE id = ?').get(order.user_id);
      db.prepare(`
        INSERT INTO balance_logs (user_id, username, type, amount, balance_after, remark)
        VALUES (?, ?, 'refund', ?, ?, ?)
      `).run(
        order.user_id,
        order.username,
        order.total_price,
        updatedUser.balance,
        `订单退款到账：${order.goods_name} (原订单号: ${order.order_no})`
      );

      db.exec('COMMIT;');
      return res.json({ code: 200, message: `订单已取消，已将 ¥${order.total_price.toFixed(2)} 全额退回买家余额` });
    } catch (err) {
      db.exec('ROLLBACK;');
      console.error('退款事务异常:', err);
      return res.status(500).json({ code: 500, message: '退款处理失败' });
    }
  } else {
    return res.status(400).json({ code: 400, message: '非法的订单状态设置' });
  }
});

// ==================== 5. 系统设置与数据看板模块 ====================

// 公开：站点基础配置
app.get('/api/settings/public', (req, res) => {
  const rows = db.prepare('SELECT key, value FROM system_settings').all();
  const settings = {};
  rows.forEach(r => {
    settings[r.key] = r.value;
  });
  res.json({ code: 200, data: settings });
});

// 管理员：保存配置（如联动小铺卡密直达购买网址、网站公告、客服等）
app.post('/api/admin/settings', adminMiddleware, (req, res) => {
  const { site_name, site_announcement, contact_info, liandong_shop_url } = req.body;

  const saveSetting = db.prepare(`
    INSERT INTO system_settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);

  if (site_name !== undefined) saveSetting.run('site_name', site_name);
  if (site_announcement !== undefined) saveSetting.run('site_announcement', site_announcement);
  if (contact_info !== undefined) saveSetting.run('contact_info', contact_info);
  if (liandong_shop_url !== undefined) saveSetting.run('liandong_shop_url', liandong_shop_url);

  res.json({ code: 200, message: '站点配置已更新生效' });
});

// 管理员：数据看板统计
app.get('/api/admin/dashboard', adminMiddleware, (req, res) => {
  // 总用户数
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').get().count;

  // 今日订单与总订单
  const orderStats = db.prepare(`
    SELECT 
      COUNT(*) as total_orders,
      SUM(CASE WHEN date(created_at) = date('now', 'localtime') THEN 1 ELSE 0 END) as today_orders,
      SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as pending_orders,
      SUM(CASE WHEN status = 1 THEN total_price ELSE 0 END) as total_revenue,
      SUM(CASE WHEN status = 1 AND date(created_at) = date('now', 'localtime') THEN total_price ELSE 0 END) as today_revenue
    FROM orders
  `).get();

  // 卡密统计
  const cardStats = db.prepare(`
    SELECT 
      COUNT(*) as total_cards,
      SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as unused_cards,
      SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as used_cards
    FROM cards
  `).get();

  // 最新 5 条待处理订单
  const recentPendingOrders = db.prepare(`
    SELECT * FROM orders WHERE status = 0 ORDER BY id DESC LIMIT 5
  `).all();

  res.json({
    code: 200,
    data: {
      user_count: userCount,
      total_orders: orderStats.total_orders || 0,
      today_orders: orderStats.today_orders || 0,
      pending_orders: orderStats.pending_orders || 0,
      total_revenue: (orderStats.total_revenue || 0).toFixed(2),
      today_revenue: (orderStats.today_revenue || 0).toFixed(2),
      total_cards: cardStats.total_cards || 0,
      unused_cards: cardStats.unused_cards || 0,
      used_cards: cardStats.used_cards || 0,
      recent_pending_orders: recentPendingOrders
    }
  });
});

// 买家端查看自己的余额变动流水
app.get('/api/balance/logs', authMiddleware, (req, res) => {
  const logs = db.prepare(`
    SELECT * FROM balance_logs WHERE user_id = ? ORDER BY id DESC LIMIT 50
  `).all(req.user.id);
  res.json({ code: 200, data: logs });
});

// 根路由及前台单页兜底
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 启动监听
app.listen(PORT, '0.0.0.0', () => {
  console.log(`===================================================`);
  console.log(`🌟 星火卡密商城与代办系统 已成功启动！`);
  console.log(`🏠 前台商城地址：http://localhost:${PORT}`);
  console.log(`⚙️  管理后台地址：http://localhost:${PORT}/admin.html`);
  console.log(`🔑 默认管理员账号：admin 密码：admin123`);
  console.log(`===================================================`);
});
