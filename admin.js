// 站长管理后台逻辑
let currentAdminUser = null;
let currentProcessingOrderId = null;

// Toast 提示
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';
  if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// 统一 API 请求封装
async function adminApi(url, options = {}) {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers
  };

  try {
    const res = await fetch(url, { ...options, headers });
    const data = await res.json();
    if (res.status === 401 || res.status === 403) {
      showAdminLock(true);
      return { code: res.status, message: data.message || '权限校验失败' };
    }
    return data;
  } catch (err) {
    console.error('API 异常:', err);
    return { code: 500, message: '无法连接后端服务' };
  }
}

// 页面初始化
document.addEventListener('DOMContentLoaded', async () => {
  await verifyAdminAuth();
});

// 验证管理员身份
async function verifyAdminAuth() {
  const token = localStorage.getItem('token');
  if (!token) {
    showAdminLock(true);
    return;
  }

  const res = await adminApi('/api/auth/me');
  if (res.code === 200 && res.data && res.data.is_admin === 1) {
    currentAdminUser = res.data;
    document.getElementById('admin-user-display').textContent = currentAdminUser.username;
    showAdminLock(false);
    loadDashboard();
  } else {
    showAdminLock(true);
  }
}

function showAdminLock(show) {
  const lock = document.getElementById('admin-login-lock');
  lock.style.display = show ? 'flex' : 'none';
}

// 管理员登录
async function handleAdminLogin(e) {
  e.preventDefault();
  const username = document.getElementById('lock-username').value.trim();
  const password = document.getElementById('lock-password').value;

  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();
  if (data.code === 200) {
    if (!data.data.user.is_admin) {
      showToast('该账号不是管理员账号！', 'error');
      return;
    }
    localStorage.setItem('token', data.data.token);
    currentAdminUser = data.data.user;
    document.getElementById('admin-user-display').textContent = currentAdminUser.username;
    showAdminLock(false);
    showToast('管理员登录成功！', 'success');
    loadDashboard();
  } else {
    showToast(data.message || '登录失败', 'error');
  }
}

function adminLogout() {
  localStorage.removeItem('token');
  window.location.reload();
}

// 侧边栏选项卡切换
function switchAdminTab(tab) {
  const tabs = ['dashboard', 'orders', 'cards', 'goods', 'settings'];
  tabs.forEach(t => {
    document.getElementById(`pane-${t}`).style.display = t === tab ? 'block' : 'none';
    const menuEl = document.getElementById(`menu-${t}`);
    if (menuEl) {
      if (t === tab) menuEl.classList.add('active');
      else menuEl.classList.remove('active');
    }
  });

  const titles = {
    dashboard: '📊 数据概览与待办',
    orders: '📦 订单处理中心',
    cards: '🎁 卡密批量生成与管理',
    goods: '🛍️ 商品发布管理',
    settings: '⚙️ 站点配置与小铺对接'
  };
  document.getElementById('current-page-title').textContent = titles[tab] || '管理后台';

  if (tab === 'dashboard') loadDashboard();
  if (tab === 'orders') loadAdminOrders();
  if (tab === 'cards') loadAdminCards();
  if (tab === 'goods') loadAdminGoods();
  if (tab === 'settings') loadSettings();
}

// ==================== 1. 控制看板 ====================
async function loadDashboard() {
  const res = await adminApi('/api/admin/dashboard');
  if (res.code === 200 && res.data) {
    const d = res.data;
    document.getElementById('dash-pending-orders').textContent = d.pending_orders;
    document.getElementById('dash-today-revenue').textContent = Number(d.today_revenue).toFixed(2);
    document.getElementById('dash-total-revenue').textContent = Number(d.total_revenue).toFixed(2);
    document.getElementById('dash-unused-cards').textContent = d.unused_cards;

    // 侧边栏红标
    const badge = document.getElementById('sidebar-pending-count');
    if (d.pending_orders > 0) {
      badge.style.display = 'inline-block';
      badge.textContent = d.pending_orders;
    } else {
      badge.style.display = 'none';
    }

    // 渲染待处理表格
    const tbody = document.getElementById('dash-pending-table-body');
    if (d.recent_pending_orders && d.recent_pending_orders.length > 0) {
      tbody.innerHTML = d.recent_pending_orders.map(o => `
        <tr>
          <td><strong>${o.order_no}</strong></td>
          <td>${escapeHtml(o.goods_name)}</td>
          <td><span class="badge badge-info">${escapeHtml(o.username)}</span></td>
          <td style="max-width: 260px; word-break: break-all; color: #1e40af; font-weight: 500;">${escapeHtml(o.user_inputs || '无')}</td>
          <td style="color: #e11d48; font-weight: 700;">¥${Number(o.total_price).toFixed(2)}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${o.created_at}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="openProcessModal(${JSON.stringify(o).replace(/"/g, '&quot;')})">接单处理</button>
          </td>
        </tr>
      `).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">🎉 目前没有待处理的订单，一切顺畅！</td></tr>';
    }
  }
}

// ==================== 2. 订单管理 ====================
async function loadAdminOrders() {
  const status = document.getElementById('order-filter-status').value;
  const search = document.getElementById('order-search-input').value.trim();
  const tbody = document.getElementById('admin-orders-table-body');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 20px;">正在加载订单数据...</td></tr>';

  let url = `/api/admin/orders?limit=100`;
  if (status !== '') url += `&status=${status}`;
  if (search !== '') url += `&search=${encodeURIComponent(search)}`;

  const res = await adminApi(url);
  if (res.code === 200 && res.data) {
    const orders = res.data.orders;
    if (orders.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 30px; color: var(--text-muted);">暂无匹配订单</td></tr>';
      return;
    }

    tbody.innerHTML = orders.map(o => {
      let statusBadge = '<span class="badge badge-warning">⏳ 待处理</span>';
      if (o.status === 1) statusBadge = '<span class="badge badge-success">✅ 已完成</span>';
      if (o.status === 2) statusBadge = '<span class="badge badge-danger">↩️ 已退款</span>';

      return `
        <tr>
          <td><strong style="font-size: 0.85rem;">${o.order_no}</strong></td>
          <td>${escapeHtml(o.goods_name)}</td>
          <td><span class="badge badge-info">${escapeHtml(o.username)}</span></td>
          <td style="max-width: 220px; word-break: break-all; color: #1e3a8a; font-weight: 500; font-size: 0.88rem;">${escapeHtml(o.user_inputs || '无')}</td>
          <td style="color: #e11d48; font-weight: 700;">¥${Number(o.total_price).toFixed(2)}</td>
          <td>${statusBadge}</td>
          <td style="max-width: 180px; font-size: 0.82rem; color: #166534;">${escapeHtml(o.admin_reply || '-')}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${o.created_at}</td>
          <td>
            ${o.status === 0 ? `
              <button class="btn btn-primary btn-sm" onclick="openProcessModal(${JSON.stringify(o).replace(/"/g, '&quot;')})">处理/回执</button>
            ` : `
              <button class="btn btn-outline btn-sm" onclick="openProcessModal(${JSON.stringify(o).replace(/"/g, '&quot;')})">查看/重写</button>
            `}
          </td>
        </tr>
      `;
    }).join('');
  }
}

// 订单处理弹窗
function openProcessModal(order) {
  currentProcessingOrderId = order.id;
  document.getElementById('proc-order-no').textContent = order.order_no;
  document.getElementById('proc-good-name').textContent = order.goods_name;
  document.getElementById('proc-price').textContent = Number(order.total_price).toFixed(2);
  document.getElementById('proc-username').textContent = order.username;
  document.getElementById('proc-user-inputs').textContent = order.user_inputs || '买家未填写额外信息';
  document.getElementById('proc-admin-reply').value = order.admin_reply || '';
  openModal('process-order-modal');
}

async function submitProcessOrder(targetStatus) {
  if (!currentProcessingOrderId) return;
  const reply = document.getElementById('proc-admin-reply').value.trim();

  if (targetStatus === 2) {
    if (!confirm('确定要取消该订单并将支付金额【全额退还】到买家账户余额中吗？')) {
      return;
    }
  }

  const res = await adminApi(`/api/admin/orders/${currentProcessingOrderId}/process`, {
    method: 'POST',
    body: JSON.stringify({
      status: targetStatus,
      admin_reply: reply
    })
  });

  if (res.code === 200) {
    showToast(res.message, 'success');
    closeModal('process-order-modal');
    loadAdminOrders();
    loadDashboard();
  } else {
    showToast(res.message || '操作失败', 'error');
  }
}

// ==================== 3. 卡密生成与导出 ====================
let lastGeneratedCardsList = [];

async function generateCards() {
  const amount = document.getElementById('gen-amount').value;
  const count = document.getElementById('gen-count').value;
  const prefix = document.getElementById('gen-prefix').value;
  const batch_name = document.getElementById('gen-batch').value;

  const res = await adminApi('/api/admin/cards/generate', {
    method: 'POST',
    body: JSON.stringify({ amount, count, prefix, batch_name })
  });

  if (res.code === 200 && res.data) {
    showToast(res.message, 'success');
    lastGeneratedCardsList = res.data.cards;
    document.getElementById('export-cards-textarea').value = res.data.cards.join('\n');
    openModal('export-cards-modal');
    loadAdminCards();
    loadDashboard();
  } else {
    showToast(res.message || '生成失败', 'error');
  }
}

function copyAllGeneratedCards() {
  const text = document.getElementById('export-cards-textarea').value;
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast('卡密已成功复制到剪贴板！可直接粘贴到联动小铺库存', 'success');
  }).catch(() => {
    showToast('复制失败，请手动全选复制', 'warning');
  });
}

async function loadAdminCards() {
  const status = document.getElementById('card-filter-status').value;
  const search = document.getElementById('card-search-input').value.trim();
  const tbody = document.getElementById('admin-cards-table-body');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px;">正在加载卡密台账...</td></tr>';

  let url = `/api/admin/cards?limit=100`;
  if (status !== '') url += `&status=${status}`;
  if (search !== '') url += `&search=${encodeURIComponent(search)}`;

  const res = await adminApi(url);
  if (res.code === 200 && res.data) {
    const { cards, stats } = res.data;
    document.getElementById('card-stat-summary').innerHTML = `
      总卡密: <strong>${stats.total_count}</strong> 张 | 未使用: <strong style="color:var(--success);">${stats.unused_count}</strong> 张 (¥${stats.unused_amount}) | 已兑换: <strong style="color:var(--primary);">${stats.used_count}</strong> 张
    `;

    if (cards.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">暂无卡密记录</td></tr>';
      return;
    }

    tbody.innerHTML = cards.map(c => {
      let statusBadge = '<span class="badge badge-success">未使用</span>';
      if (c.status === 1) statusBadge = '<span class="badge badge-info">已兑换</span>';
      if (c.status === 2) statusBadge = '<span class="badge badge-danger">已作废</span>';

      return `
        <tr>
          <td><code style="font-family: monospace; font-size: 0.95rem; font-weight: 600;">${c.code}</code></td>
          <td style="color: #e11d48; font-weight: 700;">¥${Number(c.amount).toFixed(2)}</td>
          <td>${statusBadge}</td>
          <td style="font-size: 0.85rem; color: var(--text-muted);">${escapeHtml(c.batch_no || '-')}</td>
          <td>${c.used_username ? `<span class="badge badge-info">${escapeHtml(c.used_username)}</span>` : '-'}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${c.used_at || '-'}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${c.created_at}</td>
          <td>
            ${c.status === 0 ? `
              <button class="btn btn-outline btn-sm" style="color: var(--danger); border-color: var(--danger);" onclick="voidCard(${c.id})">作废</button>
            ` : '-'}
          </td>
        </tr>
      `;
    }).join('');
  }
}

async function voidCard(id) {
  if (!confirm('确定要作废这张卡密吗？作废后用户将无法再兑换。')) return;
  const res = await adminApi(`/api/admin/cards/${id}/void`, { method: 'POST' });
  if (res.code === 200) {
    showToast(res.message, 'success');
    loadAdminCards();
  } else {
    showToast(res.message || '作废失败', 'error');
  }
}

// ==================== 4. 商品管理 ====================
async function loadAdminGoods() {
  const tbody = document.getElementById('admin-goods-table-body');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 20px;">正在加载商品...</td></tr>';

  const res = await adminApi('/api/admin/goods');
  if (res.code === 200 && res.data) {
    const goods = res.data;
    if (goods.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">暂无商品，请点击右上角发布</td></tr>';
      return;
    }

    tbody.innerHTML = goods.map(g => `
      <tr>
        <td>
          <img src="${g.cover_url || ''}" style="width: 48px; height: 48px; object-fit: cover; border-radius: 6px; background: #e2e8f0;" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%2248%22 height=%2248%22><rect width=%22100%%22 height=%22100%%22 fill=%22%23e2e8f0%22/></svg>'">
        </td>
        <td><strong>${escapeHtml(g.name)}</strong></td>
        <td style="color: #e11d48; font-weight: 700;">¥${Number(g.price).toFixed(2)}</td>
        <td><span class="goods-cat">${escapeHtml(g.category || '默认')}</span></td>
        <td>${g.require_input ? '<span class="badge badge-warning">需买家填写</span>' : '<span class="badge badge-info">无需填写</span>'}</td>
        <td style="font-size: 0.82rem; color: var(--text-muted); max-width: 200px;">${escapeHtml(g.input_placeholder || '-')}</td>
        <td>${g.status === 1 ? '<span class="badge badge-success">在售</span>' : '<span class="badge badge-danger">已下架</span>'}</td>
        <td>
          <div style="display: flex; gap: 6px;">
            <button class="btn btn-outline btn-sm" onclick="editGood(${JSON.stringify(g).replace(/"/g, '&quot;')})">编辑</button>
            <button class="btn ${g.status === 1 ? 'btn-danger' : 'btn-success'} btn-sm" onclick="toggleGoodStatus(${g.id}, ${g.status === 1 ? 0 : 1})">
              ${g.status === 1 ? '下架' : '上架'}
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  }
}

function openGoodModal() {
  document.getElementById('good-edit-modal-title').textContent = '发布新商品';
  document.getElementById('edit-good-id').value = '';
  document.getElementById('edit-good-name').value = '';
  document.getElementById('edit-good-price').value = '';
  document.getElementById('edit-good-cat').value = '虚拟服务';
  document.getElementById('edit-good-cover').value = 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=500&auto=format&fit=crop&q=60';
  document.getElementById('edit-good-desc').value = '';
  document.getElementById('edit-good-require-input').checked = true;
  document.getElementById('edit-good-placeholder').value = '请填写您的【账号 + 区服/定制需求】';
  openModal('good-edit-modal');
}

function editGood(good) {
  document.getElementById('good-edit-modal-title').textContent = '编辑商品';
  document.getElementById('edit-good-id').value = good.id;
  document.getElementById('edit-good-name').value = good.name;
  document.getElementById('edit-good-price').value = good.price;
  document.getElementById('edit-good-cat').value = good.category || '';
  document.getElementById('edit-good-cover').value = good.cover_url || '';
  document.getElementById('edit-good-desc').value = good.description || '';
  document.getElementById('edit-good-require-input').checked = good.require_input === 1;
  document.getElementById('edit-good-placeholder').value = good.input_placeholder || '';
  openModal('good-edit-modal');
}

async function saveGood() {
  const id = document.getElementById('edit-good-id').value;
  const name = document.getElementById('edit-good-name').value.trim();
  const price = document.getElementById('edit-good-price').value;
  const category = document.getElementById('edit-good-cat').value.trim();
  const cover_url = document.getElementById('edit-good-cover').value.trim();
  const description = document.getElementById('edit-good-desc').value.trim();
  const require_input = document.getElementById('edit-good-require-input').checked ? 1 : 0;
  const input_placeholder = document.getElementById('edit-good-placeholder').value.trim();

  if (!name || !price) {
    showToast('商品名称和价格不能为空', 'warning');
    return;
  }

  const payload = {
    name,
    price: parseFloat(price),
    category,
    cover_url,
    description,
    require_input,
    input_placeholder,
    stock: 9999,
    sort_order: 0,
    status: 1
  };

  const isEdit = !!id;
  const url = isEdit ? `/api/admin/goods/${id}` : '/api/admin/goods';
  const method = isEdit ? 'PUT' : 'POST';

  const res = await adminApi(url, {
    method,
    body: JSON.stringify(payload)
  });

  if (res.code === 200) {
    showToast(res.message, 'success');
    closeModal('good-edit-modal');
    loadAdminGoods();
  } else {
    showToast(res.message || '保存失败', 'error');
  }
}

async function toggleGoodStatus(id, newStatus) {
  const res = await adminApi(`/api/admin/goods/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status: newStatus })
  });
  if (res.code === 200) {
    showToast(res.message, 'success');
    loadAdminGoods();
  } else {
    showToast(res.message || '操作失败', 'error');
  }
}

// ==================== 5. 系统设置与对接 ====================
async function loadSettings() {
  const res = await adminApi('/api/settings/public');
  if (res.code === 200 && res.data) {
    document.getElementById('set-site-name').value = res.data.site_name || '';
    document.getElementById('set-liandong-url').value = res.data.liandong_shop_url || '';
    document.getElementById('set-site-announcement').value = res.data.site_announcement || '';
    document.getElementById('set-contact-info').value = res.data.contact_info || '';
  }
}

async function saveSettings(e) {
  e.preventDefault();
  const site_name = document.getElementById('set-site-name').value.trim();
  const liandong_shop_url = document.getElementById('set-liandong-url').value.trim();
  const site_announcement = document.getElementById('set-site-announcement').value.trim();
  const contact_info = document.getElementById('set-contact-info').value.trim();

  const res = await adminApi('/api/admin/settings', {
    method: 'POST',
    body: JSON.stringify({ site_name, liandong_shop_url, site_announcement, contact_info })
  });

  if (res.code === 200) {
    showToast(res.message, 'success');
  } else {
    showToast(res.message || '保存失败', 'error');
  }
}

async function changeAdminPassword(e) {
  e.preventDefault();
  const oldPassword = document.getElementById('pw-old').value;
  const newPassword = document.getElementById('pw-new').value;

  const res = await adminApi('/api/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({ oldPassword, newPassword })
  });

  if (res.code === 200) {
    showToast(res.message, 'success');
    document.getElementById('pw-old').value = '';
    document.getElementById('pw-new').value = '';
  } else {
    showToast(res.message || '修改密码失败', 'error');
  }
}

// 模态框通用控制
function openModal(id) {
  document.getElementById(id).classList.add('active');
}
function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

// XSS 防护
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
