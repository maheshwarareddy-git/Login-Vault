/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Auth Routes (Firebase Integrated)
 *  Uses Firebase Auth for email/password + backend JWT sessions.
 *
 *  Flow:
 *  1. Frontend → Firebase Client SDK → createUser / signIn
 *  2. Frontend → Gets Firebase ID token
 *  3. Frontend → Sends ID token to our backend
 *  4. Backend → Verifies Firebase ID token
 *  5. Backend → Creates/updates local profile + issues JWT cookie
 * ═══════════════════════════════════════════════════════════════
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const SecurityEvent = require('../models/SecurityEvent');
const { verifyFirebaseToken } = require('../config/firebase');
const { protect } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');
const { generateCsrfToken } = require('../middleware/csrf');
const { sendEmail } = require('../services/emailService');


const router = express.Router();

// ─── Helper: Sign JWT & Set Cookie ─────────────────────────────
function signTokenAndSetCookie(user, statusCode, req, res, message, redirectUrl = null) {
    const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role, firebaseUid: user.firebaseUid },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );

    const cookieOptions = {
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production',
        path: '/'
    };

    res.cookie('jwt', token, cookieOptions);

    return res.status(statusCode).json({
        status: 'success',
        message: message || 'Authentication successful!',
        user: User.sanitize(user),
        redirect: redirectUrl
    });
}

// ─── GET /api/auth/csrf-token ──────────────────────────────────
router.get('/csrf-token', (req, res) => {
    const sessionKey = (req.cookies && req.cookies.jwt) || req.ip;
    const token = generateCsrfToken(sessionKey);
    res.json({ status: 'success', csrfToken: token });
});

// ─── POST /api/auth/register ───────────────────────────────────
router.post('/register', authLimiter, async (req, res) => {
    try {
        const { email, password, name } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                message: 'Email and password are required.'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                status: 'error',
                message: 'Password must be at least 8 characters long.'
            });
        }

        const existingUser = User.findByEmail(email);
        if (existingUser) {
            return res.status(400).json({
                status: 'error',
                message: 'Email already in use. Please log in.'
            });
        }

        const newUser = await User.create({
            email,
            password,
            name,
            isVerified: false // Default to false for local auth until verify email flow exists
        });

        // Log security event
        const user = User.findById(newUser.id);
        SecurityEvent.log({
            userId: user.id,
            email: user.email,
            action: 'REGISTRATION',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: 'Registered via Local Auth',
            severity: 'info'
        });

        User.addSecurityLog(user.id, {
            action: 'REGISTRATION',
            ip: req.ip,
            userAgent: req.headers['user-agent']
        });

        signTokenAndSetCookie(user, 201, req, res, 'Account created successfully!');
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error during registration.'
        });
    }
});

// ─── POST /api/auth/login ──────────────────────────────────────
router.post('/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                status: 'error',
                message: 'Email and password are required.'
            });
        }

        const user = User.findByEmail(email);

        // 1. Check if user exists
        if (!user) {
            // Fake delay to prevent enumeration
            await new Promise(resolve => setTimeout(resolve, 500));
            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password.'
            });
        }

        // 2. Check if locked
        if (User.isAccountLocked(user)) {
            let message = 'Account is locked due to too many failed attempts.';
            let canRequest = true;

            if (user.unblockRequest) {
                if (user.unblockRequest.status === 'pending') {
                    message = 'Account locked. Your unlock request is pending admin approval.';
                    canRequest = false;
                } else if (user.unblockRequest.status === 'rejected') {
                    message = 'Account locked. Your unlock request was rejected.';
                    canRequest = false;
                }
            }

            return res.status(423).json({
                status: 'error',
                message,
                isLocked: true,
                canRequestUnlock: canRequest
            });
        }

        // 3. Verify password
        const isMatch = await User.comparePassword(password, user.passwordHash);

        if (!isMatch) {
            // Increment failed attempts
            User.incrementLoginAttempts(user.id);
            const updatedUser = User.findById(user.id);

            // Check if NOW locked
            if (User.isAccountLocked(updatedUser)) {
                SecurityEvent.log({
                    userId: user.id,
                    email: user.email,
                    action: 'ACCOUNT_LOCKED',
                    ip: req.ip,
                    userAgent: req.headers['user-agent'],
                    details: 'Account locked after 3 failed attempts',
                    severity: 'alert'
                });
                return res.status(423).json({
                    status: 'error',
                    message: 'Account is locked due to too many failed attempts.',
                    isLocked: true,
                    canRequestUnlock: true
                });
            }

            SecurityEvent.log({
                userId: user.id,
                email: user.email,
                action: 'LOGIN_FAILED',
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                details: 'Invalid password',
                severity: 'warning'
            });

            return res.status(401).json({
                status: 'error',
                message: 'Invalid email or password.'
            });
        }

        // 4. Success
        User.resetLoginAttempts(user.id);

        SecurityEvent.log({
            userId: user.id,
            email: user.email,
            action: 'LOGIN_SUCCESS',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: 'Local Auth login',
            severity: 'info'
        });

        User.addSecurityLog(user.id, {
            action: 'LOGIN_SUCCESS',
            ip: req.ip,
            userAgent: req.headers['user-agent']
        });

        // Check if there's a pending reset token (e.g. from Admin unlock)
        let redirect = null;
        if (user.resetPasswordToken) {
            redirect = `/reset-password.html?token=${user.resetPasswordToken}`;
        }

        signTokenAndSetCookie(user, 200, req, res, 'Logged in successfully!', redirect);

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ status: 'error', message: 'Server error.' });
    }
});

// ─── POST /api/auth/logout ─────────────────────────────────────
router.post('/logout', (req, res) => {
    if (req.cookies && req.cookies.jwt) {
        try {
            const decoded = jwt.verify(req.cookies.jwt, process.env.JWT_SECRET);
            SecurityEvent.log({
                userId: decoded.id,
                email: decoded.email,
                action: 'LOGOUT',
                ip: req.ip,
                userAgent: req.headers['user-agent'],
                severity: 'info'
            });
            User.addSecurityLog(decoded.id, {
                action: 'LOGOUT',
                ip: req.ip,
                userAgent: req.headers['user-agent']
            });
        } catch {
            // Token expired — still clear cookie
        }
    }

    res.cookie('jwt', 'loggedout', {
        expires: new Date(Date.now() + 1000),
        httpOnly: true,
        sameSite: 'strict',
        path: '/'
    });

    res.status(200).json({ status: 'success', message: 'Logged out successfully.' });
});

// ─── GET /api/auth/me ──────────────────────────────────────────
router.get('/me', protect, (req, res) => {
    res.status(200).json({ status: 'success', user: req.user });
});

// ─── GET /api/auth/security-log ────────────────────────────────
router.get('/security-log', protect, (req, res) => {
    const events = SecurityEvent.getByUser(req.user.id, 20);
    const user = User.findById(req.user.id);
    const userLog = (user && user.securityLog) ? user.securityLog.slice(0, 20) : [];

    const result = events.length > 0
        ? events.map(e => ({
            action: e.action,
            ip: e.ip,
            userAgent: e.userAgent,
            timestamp: e.timestamp,
            details: e.details,
            severity: e.severity
        }))
        : userLog;

    res.status(200).json({ status: 'success', securityLog: result.slice(0, 20) });
});

// ─── POST /api/auth/unlock-request ─────────────────────────────
router.post('/unlock-request', authLimiter, async (req, res) => {
    try {
        const { email, reason } = req.body;

        if (!email || !reason) {
            return res.status(400).json({
                status: 'error',
                message: 'Email and reason are required.'
            });
        }

        const user = User.findByEmail(email);
        if (!user) {
            return res.status(404).json({
                status: 'error',
                message: 'User not found.'
            });
        }

        if (!user.isLocked) {
            return res.status(400).json({
                status: 'error',
                message: 'Account is not locked.'
            });
        }

        if (user.unblockRequest && user.unblockRequest.status === 'pending') {
            return res.status(400).json({
                status: 'error',
                message: 'A request is already pending.'
            });
        }

        // Update user with request
        const request = {
            reason: reason.trim(),
            status: 'pending',
            timestamp: new Date().toISOString()
        };

        const JsonDB = require('../config/database');
        const userDb = new JsonDB('users');
        userDb.updateById(user.id, { unblockRequest: request });

        SecurityEvent.log({
            userId: user.id,
            email: user.email,
            action: 'UNLOCK_REQUEST',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: `Reason: ${reason}`,
            severity: 'warning'
        });

        res.status(200).json({
            status: 'success',
            message: 'Unblock request submitted. An admin will review it shortly.'
        });

    } catch (err) {
        console.error('Unlock request error:', err);
        res.status(500).json({ status: 'error', message: 'Server error.' });
    }
});

// ─── FORGOT PASSWORD ───────────────────────────────────────────
router.post('/forgot-password', authLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ status: 'error', message: 'Email is required' });
        }

        const user = User.findByEmail(email);
        if (!user) {
            // Fake success to prevent enumeration
            await new Promise(resolve => setTimeout(resolve, 500));
            return res.status(200).json({ status: 'success', message: 'If account exists, email sent.' });
        }

        // Generate Token
        const crypto = require('crypto');
        const token = crypto.randomBytes(32).toString('hex');
        const expires = Date.now() + 3600000; // 1 hour

        User.setResetToken(user.id, token, expires);

        // LOGGING TOKEN TO CONSOLE (Simulation)
        console.log('\n==================================================');
        console.log(`🔐 PASSWORD RESET LINK for ${email}:`);
        console.log(`http://localhost:3000/reset-password.html?token=${token}`);
        console.log('==================================================\n');

        SecurityEvent.log({
            userId: user.id,
            email: user.email,
            action: 'RESET_REQUEST',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: 'Password reset requested',
            severity: 'info'
        });

        // Send Email to User
        const emailHtml = `
            <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                <h2 style="color: #6366f1;">Reset Your Password</h2>
                <p>Hello ${user.name || 'User'},</p>
                <p>We received a request to reset your password for your LoginVault account.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="http://localhost:3000/reset-password.html?token=${token}" 
                       style="background-color: #6366f1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                       Reset Password
                    </a>
                </div>
                <p>If you did not request this, you can safely ignore this email.</p>
                <p>The link will expire in 1 hour.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 0.8rem; color: #666;">© 2026 LoginVault Security</p>
            </div>
        `;
        sendEmail(user.email, 'Reset Your Password - LoginVault', emailHtml);

        res.status(200).json({ status: 'success', message: 'Reset link sent to your email.' });


    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ status: 'error', message: 'Server error.' });
    }
});

// ─── RESET PASSWORD ────────────────────────────────────────────
router.post('/reset-password', authLimiter, async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (!token || !password || !confirmPassword) {
            return res.status(400).json({ status: 'error', message: 'All fields required.' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ status: 'error', message: 'Passwords do not match.' });
        }

        if (password.length < 8) {
            return res.status(400).json({ status: 'error', message: 'Password too short.' });
        }

        const user = User.findByResetToken(token);
        if (!user) {
            return res.status(400).json({ status: 'error', message: 'Invalid or expired token.' });
        }

        if (user.resetPasswordExpires < Date.now()) {
            return res.status(400).json({ status: 'error', message: 'Token has expired.' });
        }

        const bcrypt = require('bcryptjs');
        const newHash = await bcrypt.hash(password, 12);

        User.flattenResetToken(user.id, newHash);

        SecurityEvent.log({
            userId: user.id,
            email: user.email,
            action: 'PASSWORD_RESET',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: 'Password changed successfully',
            severity: 'alert'
        });

        res.status(200).json({ status: 'success', message: 'Password updated.' });

    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ status: 'error', message: 'Server error.' });
    }
});

module.exports = router;
