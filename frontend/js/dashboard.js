/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Dashboard Frontend Logic
 *  Loads user data, security stats, and activity log.
 * ═══════════════════════════════════════════════════════════════
 */

// ─── Toast System (duplicated for standalone page) ─────────────
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.innerHTML = `
    <span class="toast__icon">${icons[type]}</span>
    <span class="toast__message">${message}</span>
    <button class="toast__close" onclick="this.parentElement.classList.add('toast-exit'); setTimeout(() => this.parentElement.remove(), 300)">✕</button>
  `;
    container.appendChild(toast);
    setTimeout(() => {
        if (toast.parentElement) {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }
    }, duration);
}

// ─── Load Dashboard Data ───────────────────────────────────────
async function loadDashboard() {
    try {
        // Fetch dashboard data
        const res = await fetch('/api/user/dashboard', { credentials: 'include' });

        if (!res.ok) {
            if (res.status === 401) {
                window.location.href = '/';
                return;
            }
            throw new Error('Failed to load dashboard');
        }

        const { data } = await res.json();
        const { user, stats } = data;

        // ── Populate user info
        document.getElementById('userName').textContent = user.name || user.email.split('@')[0];
        document.getElementById('userNavName').textContent = user.name || user.email.split('@')[0];

        // Avatar initial
        const initial = (user.name || user.email)[0].toUpperCase();
        document.getElementById('userAvatar').textContent = initial;

        // ── Verification Banner
        if (!user.isVerified) {
            const banner = document.getElementById('verifyBanner');
            if (banner) {
                banner.style.display = 'flex';

                document.getElementById('resendVerifyBtn').addEventListener('click', async function () {
                    const btn = this;
                    btn.disabled = true;
                    btn.textContent = 'Sending...';

                    try {
                        const firebaseUser = firebase.auth().currentUser;
                        if (firebaseUser) {
                            await firebaseUser.sendEmailVerification();
                            showToast('Verification email sent! Check your inbox.', 'success');
                            btn.textContent = 'Sent ✅';
                        } else {
                            // Reload to sync firebase user if missing
                            showToast('Session sync error. Please reload.', 'warning');
                        }
                    } catch (err) {
                        console.error('Verify error:', err);
                        if (err.code === 'auth/too-many-requests') {
                            showToast('Too many requests. Try again later.', 'warning');
                        } else {
                            showToast('Failed to send email.', 'error');
                        }
                        btn.disabled = false;
                        btn.textContent = 'Resend Email';
                    }
                });
            }
        }

        // ── Security Score Ring
        const score = stats.securityScore || 0;
        document.getElementById('securityScore').textContent = `${score}%`;

        const ring = document.getElementById('securityRingFill');
        const circumference = 2 * Math.PI * 40; // r=40
        const offset = circumference - (score / 100) * circumference;
        // Delay the animation for visual effect
        setTimeout(() => {
            ring.style.strokeDashoffset = offset;
        }, 300);

        // Security detail text
        let secText = 'Good standing';
        if (score >= 90) secText = '🟢 Excellent protection';
        else if (score >= 70) secText = '🟡 Good, can be improved';
        else if (score >= 50) secText = '🟠 Fair, enable 2FA';
        else secText = '🔴 Needs attention';
        document.getElementById('securityDetail').textContent = secText;

        // ── Total Logins
        document.getElementById('totalLogins').textContent = stats.totalLogins || 0;
        const lastLogin = stats.lastLogin && stats.lastLogin !== 'First login!'
            ? `Last: ${formatDate(stats.lastLogin)}`
            : 'First login!';
        document.getElementById('lastLogin').textContent = lastLogin;

        // ── Account Age
        document.getElementById('accountAge').textContent = stats.accountAge || '—';
        document.getElementById('createdAt').textContent = `Created: ${formatDate(user.createdAt)}`;

        // ── Account Status
        const statusEl = document.getElementById('accountStatus');
        if (user.isLocked) {
            statusEl.textContent = 'Locked';
            statusEl.style.color = 'var(--accent-danger)';
        } else {
            statusEl.textContent = 'Active';
            statusEl.style.color = 'var(--accent-success)';
        }
        document.getElementById('accountRole').textContent = `Role: ${capitalize(user.role)}`;

        // ─── Load security log
        loadSecurityLog();

        // ─── Admin Dashboard
        if (user.role === 'admin') {
            document.getElementById('adminSection').style.display = 'block';
            loadAdminRequests();
        }

    } catch (err) {
        console.error('Dashboard error:', err);
        showToast('Failed to load dashboard data.', 'error');
    }
}

// ─── Load Security Log ─────────────────────────────────────────
async function loadSecurityLog() {
    try {
        const res = await fetch('/api/auth/security-log', { credentials: 'include' });
        if (!res.ok) throw new Error('Failed to load log');

        const { securityLog } = await res.json();
        const list = document.getElementById('securityLog');

        if (!securityLog || securityLog.length === 0) {
            list.innerHTML = '<li class="security-log--empty">No recent activity.</li>';
            return;
        }

        list.innerHTML = securityLog.map(log => `
            <li class="security-item ${log.severity === 'alert' ? 'security-item--alert' : ''}">
                <div class="security-item__icon">
                    ${log.severity === 'alert' ? '🚨' : log.severity === 'warning' ? '⚠️' : '🛡️'}
                </div>
                <div class="security-item__info">
                    <div class="security-item__action">${log.action}</div>
                    <div class="security-item__details">
                        ${log.details || getBrowser(log.userAgent)} · ${log.ip}
                    </div>
                </div>
                <div class="security-item__time">
                    ${formatTimeAgo(log.timestamp)}
                </div>
            </li>
        `).join('');

    } catch (err) {
        console.error('Security log error:', err);
        const list = document.getElementById('securityLog');
        if (list) list.innerHTML = '<li class="security-log--empty">Failed to load activity.</li>';
    }
}

// ─── Load Admin Requests ───────────────────────────────────────
async function loadAdminRequests() {
    try {
        const res = await fetch('/api/admin/requests', { credentials: 'include' });
        if (!res.ok) throw new Error('Failed to load requests');

        const { data } = await res.json();
        const tbody = document.getElementById('adminRequestsTable');

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="padding: 1rem; text-align: center; color: var(--text-muted);">No pending unblock requests.</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(req => `
            <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 0.75rem;">
                    <div style="font-weight: 600;">${req.name || 'Unknown'}</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">${req.email}</div>
                </td>
                <td style="padding: 0.75rem;">${req.reason}</td>
                <td style="padding: 0.75rem; font-size: 0.85rem; color: var(--text-muted);">${formatTimeAgo(req.timestamp)}</td>
                <td style="padding: 0.75rem;">
                    <button onclick="handleRequest('${req.userId}', 'approve')" class="btn btn--sm" title="Approve" style="background-color: var(--accent-success); color: #fff; border: none; margin-right: 0.5rem; padding: 0.25rem 0.6rem;">✔️</button>
                    <button onclick="handleRequest('${req.userId}', 'reject')" class="btn btn--sm" title="Reject" style="background-color: var(--accent-danger); color: #fff; border: none; padding: 0.25rem 0.6rem;">❌</button>
                </td>
            </tr>
        `).join('');

    } catch (err) {
        console.error('Admin load error:', err);
    }
}

// ─── Handle Admin Request ──────────────────────────────────────
window.handleRequest = async (userId, action) => {
    if (!confirm(`Are you sure you want to ${action} this request?`)) return;

    try {
        const res = await fetch('/api/admin/handle-request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ userId, action })
        });

        const data = await res.json();

        if (res.ok) {
            showToast(`${action === 'approve' ? 'Approved' : 'Rejected'} successfully.`, 'success');

            if (data.resetLink) {
                setTimeout(() => {
                    prompt("User Unlocked!\n\nHere is the password reset link to give to the user:", data.resetLink);
                }, 500);
            }

            loadAdminRequests(); // Reload list
        } else {
            showToast(data.message || 'Action failed.', 'error');
        }
    } catch (err) {
        console.error('Admin action error:', err);
        showToast('Network error.', 'error');
    }
};

// ─── Logout ────────────────────────────────────────────────────
document.getElementById('logoutBtn').addEventListener('click', async () => {
    try {
        const res = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });

        if (res.ok) {
            showToast('Logged out successfully.', 'success');
            setTimeout(() => {
                window.location.href = '/';
            }, 500);
        }
    } catch {
        showToast('Logout failed. Please try again.', 'error');
    }
});

// ─── Helper Functions ──────────────────────────────────────────
function formatDate(dateStr) {
    try {
        const d = new Date(dateStr);
        return d.toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch {
        return dateStr;
    }
}

function formatTimeAgo(dateStr) {
    try {
        const d = new Date(dateStr);
        const now = new Date();
        const diffMs = now - d;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHr = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHr / 24);

        if (diffSec < 60) return 'Just now';
        if (diffMin < 60) return `${diffMin}m ago`;
        if (diffHr < 24) return `${diffHr}h ago`;
        if (diffDay < 7) return `${diffDay}d ago`;
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
        return '';
    }
}

function getBrowser(ua) {
    if (ua.includes('Chrome') && !ua.includes('Edg')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari';
    if (ua.includes('Edg')) return 'Edge';
    if (ua.includes('Opera') || ua.includes('OPR')) return 'Opera';
    return 'Browser';
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// ─── Initialize ────────────────────────────────────────────────
loadDashboard();
