const express = require('express');
const cors = require('cors');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { db, hashPassword, verifyPassword, encryptText, decryptText } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'spark-card-shop-ultra-secure-key-2026';

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 全平铺静态资源托管
app.use(express.static(__dirname));
if (fs.existsSync(path.join(__dirname, 'public'))) {
  app.use(express.static(path.join(__dirname, 'public')));
}

// 页面路由
app.get('/', (req, res) => {
  const candidates = [
    path.join(__dirname, 'index.html'),
    path.join(__dirname, 'public', 'index.html')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return res.sendFile(p);
  }
  res.send('<h1>便捷数字小铺运行中</h1>');
});

app.get('/admin.html', (req, res) => {
  const candidates = [
    path.join(__dirname, 'admin.html'),
    path.join(__dirname, 'public', 'admin.html')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return res.sendFile(p);
  }
  res.send('<h1>站长管理后台</h1>');
});

// 安全 Token
function generateToken(user) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      username: user.username,
      is_admin: user.is_admin,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000
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

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.is_admin) {
      return res.status(403).json({ code: 403, message: '无管理员访问权限' });
    }
    next();
  });
}

// ==================== 1. 用户认证模块 ====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ code: 400, message: '用户名和密码不能为空' });
    }

    const cleanUsername = username.trim();
    if (cleanUsername.length < 3 || cleanUsername.length > 20) {
      return res.status(400).json({ code: 400, message: '用户名长度需在 3 到 20 位之间' });
    }
    if (password.length < 6) {
      return res.status(400).json({ code: 400, message: '密码长度不能少于 6 位' });
    }

    const existUser = await db.get('SELECT id FROM users WHERE LOWER(username) = LOWER(?);', [cleanUsername]);
    if (existUser) {
      return res.status(400).json({ code: 400, message: `用户名【${cleanUsername}】已被占用，请更换` });
    }

    const { hash, salt } = hashPassword(password);
    const result = await db.run(
      'INSERT INTO users (username, password_hash, salt, balance, is_admin) VALUES (?, ?, ?, 0.00, 0);',
      [cleanUsername, hash, salt]
    );

    const userId = result.lastInsertRowid;
    const user = { id: userId, username: cleanUsername, balance: 0.00, is_admin: 0 };
    const token = generateToken(user);
    res.json({
      code: 200,
      message: '注册成功',
      data: { token, user }
    });
  } catch (err) {
    console.error('注册异常:', err);
    res.status(500).json({ code: 500, message: '该用户名已存在，请更换' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ code: 400, message: '请输入用户名和密码' });
    }

    const cleanUsername = username.trim();
    const user = await db.get('SELECT * FROM users WHERE LOWER(username) = LOWER(?);', [cleanUsername]);
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
  } catch (err) {
    console.error('登录异常:', err);
    res.status(500).json({ code: 500, message: '登录处理异常' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await db.get('SELECT id, username, balance, is_admin, created_at FROM users WHERE id = ?;', [req.user.id]);
    if (!user) {
      return res.status(404).json({ code: 404, message: '用户不存在' });
    }
    res.json({ code: 200, data: user });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取用户信息失败' });
  }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ code: 400, message: '原密码和新密码均不能为空' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ code: 400, message: '新密码不能少于 6 位' });
    }

    const user = await db.get('SELECT * FROM users WHERE id = ?;', [req.user.id]);
    if (!verifyPassword(oldPassword, user.password_hash, user.salt)) {
      return res.status(400).json({ code: 400, message: '原密码验证不正确' });
    }

    const { hash, salt } = hashPassword(newPassword);
    await db.run('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?;', [hash, salt, user.id]);
    res.json({ code: 200, message: '密码修改成功，请牢记新密码' });
  } catch (err) {
    res.status(500).json({ code: 500, message: '修改密码失败' });
  }
});

// ==================== 2. 卡密兑换与管理 ====================
app.post('/api/cards/redeem', authMiddleware, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ code: 400, message: '请输入有效的卡密' });
    }

    const cleanCode = code.trim();
    const card = await db.get('SELECT * FROM cards WHERE code = ?;', [cleanCode]);

    if (!card) {
      return res.status(400).json({ code: 400, message: '卡密不存在或输入有误，请核对' });
    }
    if (card.status === 1) {
      return res.status(400).json({ code: 400, message: '该卡密此前已被兑换使用' });
    }
    if (card.status === 2) {
      return res.status(400).json({ code: 400, message: '该卡密已被管理员作废' });
    }

    // 原子批处理
    await db.batch([
      {
        sql: `UPDATE cards SET status = 1, used_by = ?, used_username = ?, used_at = datetime('now', 'localtime') WHERE id = ? AND status = 0;`,
        args: [req.user.id, req.user.username, card.id]
      },
      {
        sql: `UPDATE users SET balance = balance + ? WHERE id = ?;`,
        args: [card.amount, req.user.id]
      },
      {
        sql: `INSERT INTO balance_logs (user_id, username, type, amount, balance_after, remark)
              VALUES (?, ?, 'redeem', ?, (SELECT balance FROM users WHERE id = ?), ?);`,
        args: [req.user.id, req.user.username, card.amount, req.user.id, `卡密兑换到账 (面额: ¥${card.amount.toFixed(2)})`]
      }
    ]);

    const updatedUser = await db.get('SELECT balance FROM users WHERE id = ?;', [req.user.id]);

    res.json({
      code: 200,
      message: `恭喜！成功兑换 ¥${card.amount.toFixed(2)} 元`,
      data: {
        amount: card.amount,
        new_balance: updatedUser.balance
      }
    });
  } catch (err) {
    console.error('兑换异常:', err);
    res.status(500).json({ code: 500, message: '兑换处理异常，请重试' });
  }
});

app.post('/api/admin/cards/generate', adminMiddleware, async (req, res) => {
  try {
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
    const stmts = [];

    for (let i = 0; i < numCount; i++) {
      const rand1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const rand2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const rand3 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const code = `${cleanPrefix}-${rand1}-${rand2}-${rand3}`;

      stmts.push({
        sql: `INSERT INTO cards (code, amount, status, batch_no) VALUES (?, ?, 0, ?);`,
        args: [code, numAmount, batch_name ? `${batch_name} (${batchNo})` : batchNo]
      });
      generatedCards.push(code);
    }

    await db.batch(stmts);

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
    console.error('生成卡密失败:', err);
    res.status(500).json({ code: 500, message: '生成失败，请稍后重试' });
  }
});

app.get('/api/admin/cards', adminMiddleware, async (req, res) => {
  try {
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

    const totalRes = await db.get(`SELECT COUNT(*) as total FROM cards ${whereSql};`, params);
    const total = totalRes ? totalRes.total : 0;

    const cards = await db.all(`SELECT * FROM cards ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?;`, [...params, parseInt(limit, 10), offset]);

    const stats = await db.get(`
      SELECT 
        COUNT(*) as total_count,
        SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as unused_count,
        SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as used_count,
        SUM(CASE WHEN status = 0 THEN amount ELSE 0 END) as unused_amount,
        SUM(CASE WHEN status = 1 THEN amount ELSE 0 END) as used_amount
      FROM cards;
    `);

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
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取卡密列表失败' });
  }
});

app.post('/api/admin/cards/:id/void', adminMiddleware, async (req, res) => {
  try {
    const cardId = parseInt(req.params.id, 10);
    const card = await db.get('SELECT * FROM cards WHERE id = ?;', [cardId]);
    if (!card) {
      return res.status(404).json({ code: 404, message: '卡密不存在' });
    }
    if (card.status === 1) {
      return res.status(400).json({ code: 400, message: '已使用的卡密无法作废' });
    }

    await db.run('UPDATE cards SET status = 2 WHERE id = ?;', [cardId]);
    res.json({ code: 200, message: '卡密已成功作废' });
  } catch (err) {
    res.status(500).json({ code: 500, message: '作废失败' });
  }
});

// ==================== 3. 商品发布与展示 ====================
app.get('/api/goods', async (req, res) => {
  try {
    const goods = await db.all(`
      SELECT id, name, price, category, description, cover_url, require_input, input_placeholder, stock 
      FROM goods 
      WHERE status = 1 
      ORDER BY sort_order ASC, id DESC;
    `);
    res.json({ code: 200, data: goods });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取商品失败' });
  }
});

app.get('/api/goods/:id', async (req, res) => {
  try {
    const good = await db.get('SELECT * FROM goods WHERE id = ? AND status = 1;', [req.params.id]);
    if (!good) {
      return res.status(404).json({ code: 404, message: '商品不存在或已下架' });
    }
    res.json({ code: 200, data: good });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取商品详情失败' });
  }
});

app.get('/api/admin/goods', adminMiddleware, async (req, res) => {
  try {
    const goods = await db.all('SELECT * FROM goods ORDER BY sort_order ASC, id DESC;');
    res.json({ code: 200, data: goods });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取商品失败' });
  }
});

app.post('/api/admin/goods', adminMiddleware, async (req, res) => {
  try {
    const { name, price, category, description, require_input, input_placeholder, stock, sort_order } = req.body;
    if (!name || price === undefined) {
      return res.status(400).json({ code: 400, message: '商品名称和价格为必填项' });
    }

    const numPrice = parseFloat(price);
    if (isNaN(numPrice) || numPrice <= 0) {
      return res.status(400).json({ code: 400, message: '商品价格必须大于0' });
    }

    const result = await db.run(`
      INSERT INTO goods (name, price, category, description, cover_url, require_input, input_placeholder, stock, sort_order, status)
      VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 1);
    `, [
      name.trim(),
      numPrice,
      (category || '虚拟服务').trim(),
      description || '',
      require_input !== undefined ? parseInt(require_input, 10) : 1,
      input_placeholder || '请填写您的代办账号/区服信息',
      stock !== undefined ? parseInt(stock, 10) : 9999,
      sort_order !== undefined ? parseInt(sort_order, 10) : 0
    ]);

    res.json({ code: 200, message: '商品发布成功', data: { id: result.lastInsertRowid } });
  } catch (err) {
    res.status(500).json({ code: 500, message: '商品发布失败' });
  }
});

app.put('/api/admin/goods/:id', adminMiddleware, async (req, res) => {
  try {
    const goodId = parseInt(req.params.id, 10);
    const { name, price, category, description, require_input, input_placeholder, stock, sort_order, status } = req.body;

    await db.run(`
      UPDATE goods 
      SET name = ?, price = ?, category = ?, description = ?, require_input = ?, input_placeholder = ?, stock = ?, sort_order = ?, status = ?
      WHERE id = ?;
    `, [
      name,
      parseFloat(price),
      category,
      description,
      parseInt(require_input, 10),
      input_placeholder,
      parseInt(stock, 10),
      parseInt(sort_order, 10),
      parseInt(status, 10),
      goodId
    ]);

    res.json({ code: 200, message: '商品修改成功' });
  } catch (err) {
    res.status(500).json({ code: 500, message: '修改失败' });
  }
});

// ==================== 4. 订单与隐私加密代办处理 ====================
app.post('/api/orders/create', authMiddleware, async (req, res) => {
  try {
    const { goods_id, quantity = 1, user_inputs } = req.body;
    const numQty = parseInt(quantity, 10);

    const good = await db.get('SELECT * FROM goods WHERE id = ? AND status = 1;', [goods_id]);
    if (!good) {
      return res.status(400).json({ code: 400, message: '该商品已下架或不存在' });
    }
    if (good.stock < numQty) {
      return res.status(400).json({ code: 400, message: '该商品库存不足' });
    }

    if (good.require_input && (!user_inputs || !user_inputs.trim())) {
      return res.status(400).json({
        code: 400,
        message: `请填写【${good.input_placeholder || '指定信息'}】，以便站长为您完成服务`
      });
    }

    const totalPrice = parseFloat((good.price * numQty).toFixed(2));

    const user = await db.get('SELECT balance FROM users WHERE id = ?;', [req.user.id]);
    if (!user || user.balance < totalPrice) {
      const diff = (totalPrice - (user ? user.balance : 0)).toFixed(2);
      return res.status(400).json({
        code: 402,
        message: `账户余额不足！本单需支付 ¥${totalPrice.toFixed(2)}，当前余额 ¥${(user ? user.balance : 0).toFixed(2)}（尚缺 ¥${diff}）。请先兑换卡密。`
      });
    }

    const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const randSuffix = crypto.randomBytes(3).toString('hex').toUpperCase();
    const orderNo = `ORD-${dateStr}-${randSuffix}`;

    const encryptedUserInputs = encryptText((user_inputs || '').trim());

    await db.batch([
      {
        sql: `UPDATE users SET balance = balance - ? WHERE id = ?;`,
        args: [totalPrice, req.user.id]
      },
      {
        sql: `UPDATE goods SET stock = stock - ? WHERE id = ?;`,
        args: [numQty, good.id]
      },
      {
        sql: `INSERT INTO orders (order_no, user_id, username, goods_id, goods_name, price, quantity, total_price, user_inputs, status)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0);`,
        args: [orderNo, req.user.id, req.user.username, good.id, good.name, good.price, numQty, totalPrice, encryptedUserInputs]
      },
      {
        sql: `INSERT INTO balance_logs (user_id, username, type, amount, balance_after, remark)
              VALUES (?, ?, 'purchase', ?, (SELECT balance FROM users WHERE id = ?), ?);`,
        args: [req.user.id, req.user.username, -totalPrice, req.user.id, `购买商品：${good.name} (订单号: ${orderNo})`]
      }
    ]);

    const updatedUser = await db.get('SELECT balance FROM users WHERE id = ?;', [req.user.id]);

    res.json({
      code: 200,
      message: '下单成功！站长将在后台极速为您处理，您可在“我的订单”随时查看进度。',
      data: {
        order_no: orderNo,
        goods_name: good.name,
        total_price: totalPrice,
        new_balance: updatedUser.balance
      }
    });
  } catch (err) {
    console.error('下单异常:', err);
    res.status(500).json({ code: 500, message: '下单失败，请稍后重试' });
  }
});

app.get('/api/orders/my', authMiddleware, async (req, res) => {
  try {
    const orders = await db.all(`SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC;`, [req.user.id]);
    const decryptedOrders = orders.map(o => ({
      ...o,
      user_inputs: decryptText(o.user_inputs),
      admin_reply: decryptText(o.admin_reply)
    }));
    res.json({ code: 200, data: decryptedOrders });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取订单失败' });
  }
});

app.get('/api/admin/orders', adminMiddleware, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 50 } = req.query;
    const offset = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    let whereClauses = [];
    let params = [];

    if (status !== undefined && status !== '') {
      whereClauses.push('status = ?');
      params.push(parseInt(status, 10));
    }
    if (search) {
      whereClauses.push('(order_no LIKE ? OR username LIKE ? OR goods_name LIKE ?)');
      const term = `%${search}%`;
      params.push(term, term, term);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const totalRes = await db.get(`SELECT COUNT(*) as total FROM orders ${whereSql};`, params);
    const total = totalRes ? totalRes.total : 0;

    const orders = await db.all(`SELECT * FROM orders ${whereSql} ORDER BY id DESC LIMIT ? OFFSET ?;`, [...params, parseInt(limit, 10), offset]);

    const stats = await db.get(`
      SELECT 
        COUNT(*) as total_orders,
        SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as pending_orders,
        SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as completed_orders,
        SUM(CASE WHEN status = 1 THEN total_price ELSE 0 END) as total_sales
      FROM orders;
    `);

    const decryptedOrders = orders.map(o => ({
      ...o,
      user_inputs: decryptText(o.user_inputs),
      admin_reply: decryptText(o.admin_reply)
    }));

    res.json({
      code: 200,
      data: {
        total,
        orders: decryptedOrders,
        stats: {
          total_orders: stats.total_orders || 0,
          pending_orders: stats.pending_orders || 0,
          completed_orders: stats.completed_orders || 0,
          total_sales: (stats.total_sales || 0).toFixed(2)
        }
      }
    });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取订单失败' });
  }
});

app.post('/api/admin/orders/:id/process', adminMiddleware, async (req, res) => {
  try {
    const orderId = parseInt(req.params.id, 10);
    const { status, admin_reply } = req.body;
    const targetStatus = parseInt(status, 10);

    const order = await db.get('SELECT * FROM orders WHERE id = ?;', [orderId]);
    if (!order) {
      return res.status(404).json({ code: 404, message: '订单不存在' });
    }

    const encryptedReply = encryptText(admin_reply || (targetStatus === 1 ? '站长已处理完成！' : '【已退款】订单已取消并退款'));

    if (targetStatus === 1) {
      await db.run(`UPDATE orders SET status = 1, admin_reply = ?, finish_time = datetime('now', 'localtime') WHERE id = ?;`, [encryptedReply, orderId]);
      return res.json({ code: 200, message: '订单已标记为【已完成】' });
    } else if (targetStatus === 2) {
      if (order.status === 2) {
        return res.status(400).json({ code: 400, message: '该订单已退款' });
      }

      await db.batch([
        {
          sql: `UPDATE orders SET status = 2, admin_reply = ?, finish_time = datetime('now', 'localtime') WHERE id = ?;`,
          args: [encryptedReply, orderId]
        },
        {
          sql: `UPDATE users SET balance = balance + ? WHERE id = ?;`,
          args: [order.total_price, order.user_id]
        },
        {
          sql: `UPDATE goods SET stock = stock + ? WHERE id = ?;`,
          args: [order.quantity, order.goods_id]
        },
        {
          sql: `INSERT INTO balance_logs (user_id, username, type, amount, balance_after, remark)
                VALUES (?, ?, 'refund', ?, (SELECT balance FROM users WHERE id = ?), ?);`,
          args: [order.user_id, order.username, order.total_price, order.user_id, `订单退款到账 (原订单: ${order.order_no})`]
        }
      ]);

      return res.json({ code: 200, message: `已将 ¥${order.total_price.toFixed(2)} 全额退回买家余额` });
    }
  } catch (err) {
    res.status(500).json({ code: 500, message: '处理失败' });
  }
});

// ==================== 5. 站点配置与看板 ====================
app.get('/api/settings/public', async (req, res) => {
  try {
    const rows = await db.all('SELECT key, value FROM system_settings;');
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    res.json({ code: 200, data: settings });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取配置失败' });
  }
});

app.post('/api/admin/settings', adminMiddleware, async (req, res) => {
  try {
    const { site_name, site_announcement, contact_info, liandong_shop_url } = req.body;
    const stmts = [];
    if (site_name !== undefined) stmts.push({ sql: `INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;`, args: ['site_name', site_name] });
    if (site_announcement !== undefined) stmts.push({ sql: `INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;`, args: ['site_announcement', site_announcement] });
    if (contact_info !== undefined) stmts.push({ sql: `INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;`, args: ['contact_info', contact_info] });
    if (liandong_shop_url !== undefined) stmts.push({ sql: `INSERT INTO system_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;`, args: ['liandong_shop_url', liandong_shop_url] });

    await db.batch(stmts);
    res.json({ code: 200, message: '站点配置已更新生效' });
  } catch (err) {
    res.status(500).json({ code: 500, message: '保存配置失败' });
  }
});

// 站长即时发布最新公告接口
app.post('/api/admin/announcement', adminMiddleware, async (req, res) => {
  try {
    const { announcement } = req.body;
    if (announcement === undefined) {
      return res.status(400).json({ code: 400, message: '公告内容不能为空' });
    }
    await db.run(
      `INSERT INTO system_settings (key, value) VALUES ('site_announcement', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;`,
      [announcement.trim()]
    );
    res.json({ code: 200, message: '站长公告已成功发布并全网实时同步！' });
  } catch (err) {
    res.status(500).json({ code: 500, message: '发布公告失败' });
  }
});

app.get('/api/admin/dashboard', adminMiddleware, async (req, res) => {
  try {
    const userCountRes = await db.get('SELECT COUNT(*) as count FROM users WHERE is_admin = 0;');
    const orderStats = await db.get(`
      SELECT 
        COUNT(*) as total_orders,
        SUM(CASE WHEN date(created_at) = date('now', 'localtime') THEN 1 ELSE 0 END) as today_orders,
        SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as pending_orders,
        SUM(CASE WHEN status = 1 THEN total_price ELSE 0 END) as total_revenue,
        SUM(CASE WHEN status = 1 AND date(created_at) = date('now', 'localtime') THEN total_price ELSE 0 END) as today_revenue
      FROM orders;
    `);

    const cardStats = await db.get(`
      SELECT 
        COUNT(*) as total_cards,
        SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as unused_cards,
        SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as used_cards
      FROM cards;
    `);

    const recentPendingOrders = await db.all(`SELECT * FROM orders WHERE status = 0 ORDER BY id DESC LIMIT 5;`);
    const decryptedPendingOrders = recentPendingOrders.map(o => ({
      ...o,
      user_inputs: decryptText(o.user_inputs)
    }));

    res.json({
      code: 200,
      data: {
        user_count: userCountRes ? userCountRes.count : 0,
        total_orders: orderStats.total_orders || 0,
        today_orders: orderStats.today_orders || 0,
        pending_orders: orderStats.pending_orders || 0,
        total_revenue: (orderStats.total_revenue || 0).toFixed(2),
        today_revenue: (orderStats.today_revenue || 0).toFixed(2),
        total_cards: cardStats.total_cards || 0,
        unused_cards: cardStats.unused_cards || 0,
        used_cards: cardStats.used_cards || 0,
        recent_pending_orders: decryptedPendingOrders
      }
    });
  } catch (err) {
    res.status(500).json({ code: 500, message: '获取看板数据失败' });
  }
});

app.get('*', (req, res) => {
  if (req.path.includes('.')) {
    return res.status(404).send('File Not Found');
  }
  const candidates = [
    path.join(__dirname, 'index.html'),
    path.join(__dirname, 'public', 'index.html')
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return res.sendFile(p);
  }
  res.send('<h1>便捷数字小铺运行中</h1>');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`===================================================`);
  console.log(`🌟 便捷数字小铺已成功启动！`);
  console.log(`🌐 永久数据库：已连接 Turso 云端持久化存储！`);
  console.log(`🏠 前台商城地址：http://localhost:${PORT}`);
  console.log(`⚙️  管理后台地址：http://localhost:${PORT}/admin.html`);
  console.log(`🔑 站长账号：admin 密码：Zy060206`);
  console.log(`===================================================`);
});
