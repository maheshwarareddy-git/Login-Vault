/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Admin Routes
 *  Handle user unblock requests and other admin tasks.
 * ═══════════════════════════════════════════════════════════════
 */

const express = require('express');
const User = require('../models/User');
const { protect, restrictTo } = require('../middleware/auth');
const SecurityEvent = require('../models/SecurityEvent');
const { sendEmail } = require('../services/emailService');


const router = express.Router();

// Protect all routes: Must be logged in AND have 'admin' role
router.use(protect);
router.use(restrictTo('admin'));

// ─── GET /api/admin/requests ───────────────────────────────────
// List all pending unblock requests
router.get('/requests', (req, res) => {
    // Find all users where unblockRequest.status === 'pending'
    // Since our JSON DB is simple, we might need to filter manually
    const allUsers = User.findAll(); // specific method implementation might be needed
    const pendingRequests = allUsers
        .filter(u => u.unblockRequest && u.unblockRequest.status === 'pending')
        .map(u => ({
            userId: u.id,
            email: u.email,
            name: u.name,
            reason: u.unblockRequest.reason,
            timestamp: u.unblockRequest.timestamp,
            failedAttempts: u.failedLoginAttempts
        }));

    res.status(200).json({
        status: 'success',
        results: pendingRequests.length,
        data: pendingRequests
    });
});

// ─── POST /api/admin/handle-request ────────────────────────────
// Approve or Reject a request
router.post('/handle-request', (req, res) => {
    const { userId, action } = req.body; // action: 'approve' | 'reject'

    if (!userId || !['approve', 'reject'].includes(action)) {
        return res.status(400).json({ status: 'error', message: 'Invalid data.' });
    }

    const user = User.findById(userId);
    if (!user) {
        return res.status(404).json({ status: 'error', message: 'User not found.' });
    }

    if (!user.unblockRequest || user.unblockRequest.status !== 'pending') {
        return res.status(400).json({ status: 'error', message: 'No pending request for this user.' });
    }

    const JsonDB = require('../config/database');
    const userDb = new JsonDB('users');

    if (action === 'approve') {
        // Unlock user
        // Generate Reset Token for convenience (User requested "option to reset")
        const crypto = require('crypto');
        const token = crypto.randomBytes(32).toString('hex');
        const expires = Date.now() + 3600000; // 1 hour

        userDb.updateById(userId, {
            isLocked: false,
            failedLoginAttempts: 0,
            resetPasswordToken: token,
            resetPasswordExpires: expires,
            unblockRequest: {
                ...user.unblockRequest,
                status: 'approved',
                resolvedAt: new Date().toISOString(),
                resolvedBy: req.user.email
            }
        });

        // Log the Reset Link for the Admin/User to see
        console.log('\n==================================================');
        console.log(`🔐 ACCOUNT UNLOCKED for ${user.email}`);
        console.log(`🔑 PASSWORD RESET LINK (Auto-Generated):`);
        console.log(`http://localhost:3000/reset-password.html?token=${token}`);
        console.log('==================================================\n');

        SecurityEvent.log({
            userId: req.user.id,
            email: req.user.email,
            action: 'ADMIN_ACTION',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: `Approved unblock for ${user.email}. Reset link generated.`,
            severity: 'info'
        });

        // Send Email to User
        const emailHtml = `
            <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                <h2 style="color: #6366f1;">Account Unlocked!</h2>
                <p>Hello ${user.name || 'User'},</p>
                <p>An administrator has approved your unblock request. Your account is now active.</p>
                <p>For security, please reset your password using the link below:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="http://localhost:3000/reset-password.html?token=${token}" 
                       style="background-color: #6366f1; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                       Reset Password
                    </a>
                </div>
                <p>Or copy this link: <br> http://localhost:3000/reset-password.html?token=${token}</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="font-size: 0.8rem; color: #666;">If you did not request this, please contact support immediately.</p>
            </div>
        `;
        sendEmail(user.email, 'Account Unlocked - LoginVault', emailHtml);

    } else {
        // Reject request (remains locked)
        userDb.updateById(userId, {
            unblockRequest: {
                ...user.unblockRequest,
                status: 'rejected',
                resolvedAt: new Date().toISOString(),
                resolvedBy: req.user.email
            }
        });

        SecurityEvent.log({
            userId: req.user.id,
            email: req.user.email,
            action: 'ADMIN_ACTION',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            details: `Rejected unblock request for ${user.email}`,
            severity: 'warning'
        });
    }

    // Construct the reset link
    const resetLink = `http://localhost:3000/reset-password.html?token=${token}`;

    res.status(200).json({
        status: 'success',
        message: `Request ${action}d successfully.`,
        resetLink: action === 'approve' ? resetLink : null
    });
});

module.exports = router;
