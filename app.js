// 前台应用逻辑
let currentUser = null;
let currentGoodToBuy = null;
let siteSettings = {};

// Toast 通知提示组件
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
async function apiRequest(url, options = {}) {
  const token = localStorage.getItem('token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...options.headers
  };

  try {
    const res = await fetch(url, { ...options, headers });
    const data = await res.json();
    if (res.status === 401) {
      // 登录失效
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      updateUserUI(null);
    }
    return data;
  } catch (err) {
    console.error('API 请求错误:', err);
    return { code: 500, message: '网络异常，请检查服务是否正常启动' };
  }
}

// 初始化
document.addEventListener('DOMContentLoaded', async () => {
  await loadSiteSettings();
  await checkUserLogin();
  await loadGoods();
});

// 加载公开站点设置
async function loadSiteSettings() {
  const res = await apiRequest('/api/settings/public');
  if (res.code === 200 && res.data) {
    siteSettings = res.data;
    if (siteSettings.site_name) {
      document.title = siteSettings.site_name;
      document.getElementById('site-name-display').textContent = siteSettings.site_name;
    }
    if (siteSettings.site_announcement) {
      document.getElementById('site-announcement-display').textContent = siteSettings.site_announcement;
    }
    if (siteSettings.contact_info) {
      document.getElementById('contact-info-display').textContent = siteSettings.contact_info;
    }
  }
}

// 跳转联动小铺购买卡密
function goToLiandongShop() {
  const url = siteSettings.liandong_shop_url;
  if (url && url.startsWith('http')) {
    window.open(url, '_blank');
  } else {
    showToast('站长尚未在后台配置联动小铺具体链接，请联系客服获取卡密！', 'warning');
  }
}

// 检查并恢复登录状态
async function checkUserLogin() {
  const token = localStorage.getItem('token');
  if (!token) {
    updateUserUI(null);
    return;
  }

  const res = await apiRequest('/api/auth/me');
  if (res.code === 200) {
    currentUser = res.data;
    updateUserUI(currentUser);
  } else {
    currentUser = null;
    localStorage.removeItem('token');
    updateUserUI(null);
  }
}

// 更新用户导航栏状态
function updateUserUI(user) {
  const guestZone = document.getElementById('user-guest-zone');
  const loggedZone = document.getElementById('user-logged-zone');

  if (user) {
    guestZone.style.display = 'none';
    loggedZone.style.display = 'flex';
    document.getElementById('nav-username').textContent = user.username;
    document.getElementById('nav-balance').textContent = Number(user.balance).toFixed(2);
  } else {
    guestZone.style.display = 'flex';
    loggedZone.style.display = 'none';
  }
}

// 退出登录
function logout() {
  localStorage.removeItem('token');
  currentUser = null;
  updateUserUI(null);
  showToast('您已安全退出登录', 'info');
}

// 加载并渲染商品列表
async function loadGoods() {
  const container = document.getElementById('goods-container');
  const badge = document.getElementById('goods-count-badge');

  const res = await apiRequest('/api/goods');
  if (res.code !== 200 || !res.data) {
    container.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--danger);">加载商品列表失败</div>';
    return;
  }

  const goods = res.data;
  badge.textContent = `共 ${goods.length} 款服务`;

  if (goods.length === 0) {
    container.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-muted);">暂无上架商品</div>';
    return;
  }

  container.innerHTML = goods.map(item => `
    <div class="goods-card">
      <img class="goods-cover" src="${item.cover_url || 'https://images.unsplash.com/photo-1542751371-adc38448a05e?w=500&auto=format&fit=crop&q=60'}" alt="${item.name}" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 width=%22300%22 height=%22160%22><rect width=%22100%%22 height=%22100%%22 fill=%22%23e2e8f0%22/><text x=%2250%%22 y=%2250%%22 dominant-baseline=%22middle%22 text-anchor=%22middle%22 fill=%22%2394a3b8%22 font-size=%2216%22>虚拟商品图</text></svg>'">
      <div class="goods-body">
        <span class="goods-cat">${item.category || '虚拟服务'}</span>
        <h3 class="goods-title">${escapeHtml(item.name)}</h3>
        <p class="goods-desc">${escapeHtml(item.description || '无详细介绍')}</p>
        <div class="goods-footer">
          <div class="goods-price"><small>¥</small>${Number(item.price).toFixed(2)}</div>
          <button class="btn btn-primary btn-sm" onclick="openBuyModal(${JSON.stringify(item).replace(/"/g, '&quot;')})">
            立即购买
          </button>
        </div>
      </div>
    </div>
  `).join('');
}

// 模态框通用控制
function openModal(id) {
  document.getElementById(id).classList.add('active');
}
function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

// 登录/注册弹窗交互
let currentAuthTab = 'login';
function openAuthModal(tab = 'login') {
  switchAuthTab(tab);
  openModal('auth-modal');
}

function switchAuthTab(tab) {
  currentAuthTab = tab;
  const isLogin = tab === 'login';
  document.getElementById('auth-modal-title').textContent = isLogin ? '账号登录' : '免费注册账号';
  document.getElementById('tab-login').style.background = isLogin ? 'white' : 'transparent';
  document.getElementById('tab-login').style.boxShadow = isLogin ? '0 1px 3px rgba(0,0,0,0.1)' : 'none';
  document.getElementById('tab-register').style.background = !isLogin ? 'white' : 'transparent';
  document.getElementById('tab-register').style.boxShadow = !isLogin ? '0 1px 3px rgba(0,0,0,0.1)' : 'none';
  document.getElementById('register-confirm-group').style.display = isLogin ? 'none' : 'block';
  document.getElementById('auth-submit-btn').textContent = isLogin ? '立即登录' : '立即注册并登录';
}

async function handleAuthSubmit(e) {
  e.preventDefault();
  const username = document.getElementById('auth-username').value.trim();
  const password = document.getElementById('auth-password').value;

  if (currentAuthTab === 'register') {
    const confirmPassword = document.getElementById('auth-confirm-password').value;
    if (password !== confirmPassword) {
      showToast('两次输入的密码不一致', 'error');
      return;
    }
  }

  const endpoint = currentAuthTab === 'login' ? '/api/auth/login' : '/api/auth/register';
  const res = await apiRequest(endpoint, {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });

  if (res.code === 200) {
    showToast(res.message || '操作成功', 'success');
    localStorage.setItem('token', res.data.token);
    currentUser = res.data.user;
    updateUserUI(currentUser);
    closeModal('auth-modal');
  } else {
    showToast(res.message || '操作失败', 'error');
  }
}

// 卡密兑换弹窗
function openRedeemModal() {
  if (!currentUser) {
    showToast('请先登录账号后再兑换卡密', 'warning');
    openAuthModal('login');
    return;
  }
  document.getElementById('redeem-code-input').value = '';
  openModal('redeem-modal');
}

function fillTestCard(code) {
  document.getElementById('redeem-code-input').value = code;
}

async function submitRedeem() {
  const code = document.getElementById('redeem-code-input').value.trim();
  if (!code) {
    showToast('请输入卡密', 'warning');
    return;
  }

  const res = await apiRequest('/api/cards/redeem', {
    method: 'POST',
    body: JSON.stringify({ code })
  });

  if (res.code === 200) {
    showToast(res.message, 'success');
    currentUser.balance = res.data.new_balance;
    updateUserUI(currentUser);
    closeModal('redeem-modal');
  } else {
    showToast(res.message || '兑换失败', 'error');
  }
}

// 购买与定制信息弹窗
function openBuyModal(good) {
  if (!currentUser) {
    showToast('请先登录账号后再进行购买', 'warning');
    openAuthModal('login');
    return;
  }

  currentGoodToBuy = good;
  document.getElementById('buy-good-name').textContent = good.name;
  document.getElementById('buy-good-price').textContent = Number(good.price).toFixed(2);
  document.getElementById('buy-good-cover').src = good.cover_url || '';
  document.getElementById('buy-user-balance').textContent = Number(currentUser.balance).toFixed(2);

  const balanceStatus = document.getElementById('buy-balance-status');
  const confirmBtn = document.getElementById('buy-confirm-btn');

  if (Number(currentUser.balance) < Number(good.price)) {
    const diff = (Number(good.price) - Number(currentUser.balance)).toFixed(2);
    balanceStatus.innerHTML = `<span style="color: #e11d48; font-weight: 600;">⚠️ 余额不足 (尚缺 ¥${diff})</span> · <a href="javascript:void(0)" onclick="closeModal('buy-modal'); openRedeemModal();" style="color: var(--primary); text-decoration: underline;">去兑换卡密</a>`;
    confirmBtn.disabled = true;
    confirmBtn.style.opacity = '0.6';
    confirmBtn.textContent = '余额不足，无法购买';
  } else {
    balanceStatus.innerHTML = `<span style="color: var(--success); font-weight: 600;">✅ 余额充足，购买后剩余 ¥${(Number(currentUser.balance) - Number(good.price)).toFixed(2)}</span>`;
    confirmBtn.disabled = false;
    confirmBtn.style.opacity = '1';
    confirmBtn.textContent = '确认扣除余额下单';
  }

  const inputGroup = document.getElementById('buy-input-group');
  if (good.require_input) {
    inputGroup.style.display = 'block';
    document.getElementById('buy-input-label').innerHTML = `${escapeHtml(good.input_placeholder || '请填写指定代办信息')} <span style="color: #e11d48;">*</span>`;
    document.getElementById('buy-user-input').placeholder = `例如：${good.input_placeholder || '请输入您的账号或需求'}`;
    document.getElementById('buy-user-input').value = '';
  } else {
    inputGroup.style.display = 'none';
  }

  openModal('buy-modal');
}

// 提交订单
async function submitOrder() {
  if (!currentGoodToBuy) return;

  let userInputs = '';
  if (currentGoodToBuy.require_input) {
    userInputs = document.getElementById('buy-user-input').value.trim();
    if (!userInputs) {
      showToast('请完整填写要求的指定信息，以便站长为您处理', 'warning');
      return;
    }
  }

  const confirmBtn = document.getElementById('buy-confirm-btn');
  confirmBtn.disabled = true;
  confirmBtn.textContent = '正在提交订单...';

  const res = await apiRequest('/api/orders/create', {
    method: 'POST',
    body: JSON.stringify({
      goods_id: currentGoodToBuy.id,
      quantity: 1,
      user_inputs: userInputs
    })
  });

  confirmBtn.disabled = false;
  confirmBtn.textContent = '确认扣除余额下单';

  if (res.code === 200) {
    showToast(res.message, 'success');
    currentUser.balance = res.data.new_balance;
    updateUserUI(currentUser);
    closeModal('buy-modal');
    // 自动打开订单弹窗供买家查看
    setTimeout(() => {
      openOrdersModal();
    }, 400);
  } else {
    showToast(res.message || '下单失败', 'error');
  }
}

// 我的订单中心
async function openOrdersModal() {
  if (!currentUser) {
    showToast('请先登录账号', 'warning');
    openAuthModal('login');
    return;
  }
  openModal('orders-modal');
  await loadMyOrders();
}

async function loadMyOrders() {
  const container = document.getElementById('orders-list-container');
  container.innerHTML = '<div style="text-align:center; padding:30px; color:var(--text-muted);">正在加载您的订单...</div>';

  const res = await apiRequest('/api/orders/my');
  if (res.code !== 200 || !res.data) {
    container.innerHTML = '<div style="text-align:center; padding:30px; color:var(--danger);">订单加载失败</div>';
    return;
  }

  const orders = res.data;
  if (orders.length === 0) {
    container.innerHTML = '<div style="text-align:center; padding:40px; color:var(--text-muted);">您暂无任何订单记录</div>';
    return;
  }

  container.innerHTML = orders.map(order => {
    let statusBadge = '<span class="badge badge-warning">⏳ 待处理</span>';
    if (order.status === 1) statusBadge = '<span class="badge badge-success">✅ 已完成</span>';
    if (order.status === 2) statusBadge = '<span class="badge badge-danger">↩️ 已退款</span>';

    return `
      <div class="order-card">
        <div class="order-header">
          <span>单号：<strong>${order.order_no}</strong></span>
          <span>${statusBadge}</span>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
          <h4 style="font-size: 1.05rem;">${escapeHtml(order.goods_name)}</h4>
          <span style="font-weight: 700; color: #e11d48; font-size: 1.1rem;">¥${Number(order.total_price).toFixed(2)}</span>
        </div>
        ${order.user_inputs ? `
          <div style="background: #f8fafc; padding: 8px 12px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 6px; border: 1px solid var(--border);">
            <strong style="color: var(--text-muted);">您提交的代办信息：</strong>
            <div style="color: var(--text-main); margin-top: 2px; word-break: break-all;">${escapeHtml(order.user_inputs)}</div>
          </div>
        ` : ''}
        ${order.admin_reply ? `
          <div class="order-reply-box">
            <strong style="display: block; margin-bottom: 2px;">站长处理回执：</strong>
            <div style="word-break: break-all;">${escapeHtml(order.admin_reply)}</div>
          </div>
        ` : (order.status === 0 ? `
          <div style="font-size: 0.82rem; color: var(--warning); margin-top: 6px;">
            🕒 站长已收到您的订单，正在加急为您处理中，请稍候...
          </div>
        ` : '')}
        <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 8px; text-align: right;">
          下单时间：${order.created_at}
        </div>
      </div>
    `;
  }).join('');
}

// XSS 过滤防护
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
