/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Auth Frontend (Firebase Integrated)
 *
 *  Flow:
 *  Register: Firebase createUser → get ID token → send to backend
 *  Login:    Firebase signIn → get ID token → send to backend
 *  Backend verifies token & issues httpOnly JWT cookie.
 * ═══════════════════════════════════════════════════════════════
 */

// ─── Tab Switching ─────────────────────────────────────────────
const tabLogin = document.getElementById('tabLogin');
const tabRegister = document.getElementById('tabRegister');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');

tabLogin.addEventListener('click', () => switchTab('login'));
tabRegister.addEventListener('click', () => switchTab('register'));

function switchTab(tab) {
    if (tab === 'login') {
        tabLogin.classList.add('active');
        tabRegister.classList.remove('active');
        loginForm.classList.add('active');
        registerForm.classList.remove('active');
    } else {
        tabRegister.classList.add('active');
        tabLogin.classList.remove('active');
        registerForm.classList.add('active');
        loginForm.classList.remove('active');
    }
}

// ─── Password Visibility Toggle ────────────────────────────────
function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        btn.textContent = '🙈';
    } else {
        input.type = 'password';
        btn.textContent = '👁️';
    }
}

// ─── Password Strength Meter ───────────────────────────────────
const regPassword = document.getElementById('regPassword');
const strengthFill = document.getElementById('strengthFill');
const strengthText = document.getElementById('strengthText');
const checks = {
    length: document.getElementById('checkLength'),
    upper: document.getElementById('checkUpper'),
    lower: document.getElementById('checkLower'),
    number: document.getElementById('checkNumber'),
    special: document.getElementById('checkSpecial')
};

regPassword.addEventListener('input', () => {
    const val = regPassword.value;
    let strength = 0;
    const results = {
        length: val.length >= 8,
        upper: /[A-Z]/.test(val),
        lower: /[a-z]/.test(val),
        number: /[0-9]/.test(val),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val)
    };

    Object.keys(results).forEach(key => {
        const el = checks[key];
        const icon = el.querySelector('.password-check__icon');
        if (results[key]) {
            el.classList.add('met');
            icon.textContent = '✓';
            strength++;
        } else {
            el.classList.remove('met');
            icon.textContent = '○';
        }
    });

    strengthFill.setAttribute('data-strength', strength);
    const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Strong', 'Excellent'];
    const colors = ['', 'var(--accent-danger)', 'var(--accent-danger)', 'var(--accent-warning)', 'var(--accent-warning)', 'var(--accent-success)'];
    strengthText.textContent = val.length === 0 ? 'Enter a password' : labels[strength];
    strengthText.style.color = val.length === 0 ? '' : colors[strength];
});

// ─── Confirm Password Check ───────────────────────────────────
const regConfirmPassword = document.getElementById('regConfirmPassword');

regConfirmPassword.addEventListener('input', () => {
    if (regConfirmPassword.value && regConfirmPassword.value !== regPassword.value) {
        regConfirmPassword.classList.add('invalid');
        regConfirmPassword.classList.remove('valid');
    } else if (regConfirmPassword.value) {
        regConfirmPassword.classList.add('valid');
        regConfirmPassword.classList.remove('invalid');
    }
});

// ─── Toast Notification System ─────────────────────────────────
function showToast(message, type = 'info', duration = 5000) {
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

// ─── Firebase Error Messages ───────────────────────────────────
function getFirebaseErrorMessage(errorCode) {
    const messages = {
        'auth/email-already-in-use': 'An account with this email already exists. Please sign in instead.',
        'auth/invalid-email': 'Please enter a valid email address.',
        'auth/weak-password': 'Password is too weak. Must be at least 6 characters.',
        'auth/user-not-found': 'Invalid email or password.',
        'auth/wrong-password': 'Invalid email or password.',
        'auth/invalid-credential': 'Invalid email or password.',
        'auth/too-many-requests': 'Too many attempts. Please try again later.',
        'auth/user-disabled': 'This account has been disabled.',
        'auth/network-request-failed': 'Network error. Please check your connection.',
        'auth/operation-not-allowed': 'Email/password sign-in is not enabled.'
    };
    return messages[errorCode] || 'Authentication failed. Please try again.';
}

// ─── LOGIN (Local Auth) ────────────────────────────────────────
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('loginBtn');
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) {
        showToast('Please fill in all fields.', 'warning');
        return;
    }

    btn.classList.add('loading');
    btn.disabled = true;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        if (res.ok) {
            showToast('Login successful! Redirecting...', 'success');
            setTimeout(() => {
                if (data.redirect) {
                    window.location.href = data.redirect;
                } else {
                    window.location.href = '/dashboard';
                }
            }, 800);
        } else {
            // Check for Lockout
            if (res.status === 423) {
                const { message, canRequestUnlock } = data;
                showToast(message, 'error', 6000);

                if (canRequestUnlock) {
                    // Simple UI for request: prompt for now
                    setTimeout(async () => {
                        const reason = prompt("🔒 Account Locked\n\nPlease enter a reason for the admin to unlock your account:");
                        if (reason) {
                            try {
                                const reqRes = await fetch('/api/auth/unlock-request', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ email, reason })
                                });
                                const reqData = await reqRes.json();
                                if (reqRes.ok) {
                                    showToast('Request submitted. Admin will review it.', 'success');
                                } else {
                                    showToast(reqData.message || 'Request failed.', 'error');
                                }
                            } catch {
                                showToast('Could not submit request.', 'error');
                            }
                        }
                    }, 1000);
                }
            } else {
                showToast(data.message || 'Login failed.', 'error');
            }
        }
    } catch (err) {
        console.error('Login error:', err);
        showToast('Login failed. Please try again.', 'error');
    } finally {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});

// ─── REGISTER (Local Auth) ─────────────────────────────────────
registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('registerBtn');
    const name = document.getElementById('regName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = regPassword.value;
    const confirmPassword = regConfirmPassword.value;

    // Client-side validation
    if (!email || !password || !confirmPassword) {
        showToast('Please fill in all required fields.', 'warning');
        return;
    }

    if (password !== confirmPassword) {
        showToast('Passwords do not match.', 'error');
        return;
    }

    const strength = [
        password.length >= 8,
        /[A-Z]/.test(password),
        /[a-z]/.test(password),
        /[0-9]/.test(password),
        /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    ].filter(Boolean).length;

    if (strength < 5) {
        showToast('Password must meet all strength requirements.', 'warning');
        return;
    }

    btn.classList.add('loading');
    btn.disabled = true;

    try {
        const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password, name })
        });

        const data = await res.json();

        if (res.ok) {
            showToast('Account created! Redirecting to dashboard...', 'success');
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 800);
        } else {
            showToast(data.message || 'Registration failed.', 'error');
        }
    } catch (err) {
        console.error('Register error:', err);
        showToast('Registration failed. Please try again.', 'error');
    } finally {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
});

// ─── Check if already logged in ────────────────────────────────
(async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me', { credentials: 'include' });
        if (res.ok) {
            window.location.href = '/dashboard';
        }
    } catch {
        // Not logged in — stay on auth page
    }
})();
