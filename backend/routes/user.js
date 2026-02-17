/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — User Routes
 *  Protected user endpoints: dashboard, profile.
 * ═══════════════════════════════════════════════════════════════
 */

const express = require('express');
const User = require('../models/User');
const { protect } = require('../middleware/auth');

const router = express.Router();

// All routes below require authentication
router.use(protect);

// ─── GET /api/user/dashboard ───────────────────────────────────
router.get('/dashboard', (req, res) => {
    const user = User.findById(req.user.id);

    res.status(200).json({
        status: 'success',
        data: {
            user: User.sanitize(user),
            stats: {
                accountAge: getAccountAge(user.createdAt),
                lastLogin: user.lastLogin || 'First login!',
                securityScore: calculateSecurityScore(user),
                totalLogins: (user.securityLog || []).filter(l => l.action === 'LOGIN_SUCCESS').length
            }
        }
    });
});

// ─── PUT /api/user/profile ─────────────────────────────────────
router.put('/profile', async (req, res) => {
    const { name } = req.body;
    let user = User.update(req.user.id, { name });

    if (!user) {
        return res.status(404).json({ status: 'error', message: 'User not found.' });
    }

    // Sync to Firebase if linked
    if (user.firebaseUid) {
        try {
            const { firebaseAuth } = require('../config/firebase');
            await firebaseAuth.updateUser(user.firebaseUid, {
                displayName: name
            });
        } catch (err) {
            console.error('Failed to sync profile change to Firebase:', err.message);
            // Don't fail the request, just log it. Local update succeeded.
        }
    }

    res.status(200).json({
        status: 'success',
        message: 'Profile updated.',
        user
    });
});

// ─── Helpers ───────────────────────────────────────────────────
function getAccountAge(createdAt) {
    const now = new Date();
    const created = new Date(createdAt);
    const diffMs = now - created;
    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    if (days === 0) return 'Today';
    if (days === 1) return '1 day';
    if (days < 30) return `${days} days`;
    const months = Math.floor(days / 30);
    return months === 1 ? '1 month' : `${months} months`;
}

function calculateSecurityScore(user) {
    let score = 0;
    // Password exists
    score += 30;
    // Email verified
    if (user.isVerified) score += 20;
    // Account not locked
    if (!user.isLocked) score += 10;
    // No recent failed attempts
    if (user.failedLoginAttempts === 0) score += 15;
    // Base security for having an account
    score += 25;
    return Math.min(score, 100);
}

module.exports = router;
