/**
 * CF-Workers-VPSmonitor 登录守卫
 *
 * WebSSH 页面本身不提供登录表单；所有 SSH API（/api/admin/ssh/*）都由
 * Worker 的管理员 JWT 会话中间件保护。此模块在应用启动前校验会话，
 * 未登录时跳转到后台登录页（登录成功后回跳）。
 */
const AUTH_CHECK_RETRY_ATTEMPTS = 5;
const AUTH_CHECK_RETRY_DELAY_MS = 800;

function redirectToLogin(): void {
  // Login 页面通过 location.state 回跳，这里保持简单直接跳后台登录页。
  location.replace('/admin/login');
}

async function isAuthenticated(): Promise<boolean> {
  for (let attempt = 0; attempt < AUTH_CHECK_RETRY_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch('/api/me', { credentials: 'same-origin' });
      if (response.ok) return true;
      if (response.status === 401) return false;
      // 数据库引导中（202/503）时稍后重试。
      await new Promise((resolve) => setTimeout(resolve, AUTH_CHECK_RETRY_DELAY_MS));
    } catch {
      // 网络瞬时错误：重试。
      await new Promise((resolve) => setTimeout(resolve, AUTH_CHECK_RETRY_DELAY_MS));
    }
  }
  return false;
}

void isAuthenticated().then((authenticated) => {
  if (!authenticated) {
    redirectToLogin();
    return;
  }
  document.documentElement.dataset.authenticated = 'true';
});
