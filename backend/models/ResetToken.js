/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Password Reset Token Model
 *  Manages secure password reset tokens with expiration.
 * ═══════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const JsonDB = require('../config/database');

const db = new JsonDB('reset_tokens');

// Token expires in 1 hour
const TOKEN_EXPIRY_MS = 60 * 60 * 1000;

class ResetToken {
    /**
     * Create a password reset token for a user
     * @param {string} userId
     * @returns {string} The raw token (to send in email)
     */
    static create(userId) {
        // Invalidate any existing tokens for this user
        ResetToken.invalidateByUser(userId);

        // Generate cryptographically secure random token
        const rawToken = crypto.randomBytes(32).toString('hex');

        // Store hash of token (never store raw token in DB)
        const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');

        const record = {
            id: uuidv4(),
            userId,
            tokenHash: hashedToken,
            used: false,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + TOKEN_EXPIRY_MS).toISOString()
        };

        db.insert(record);
        return rawToken;
    }

    /**
     * Verify a token and return associated data
     * @param {string} rawToken - The raw token from the URL
     * @returns {Object|null} Token record if valid, null otherwise
     */
    static verify(rawToken) {
        const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
        const record = db.findOne({ tokenHash: hashedToken });

        if (!record) return null;
        if (record.used) return null;
        if (new Date(record.expiresAt) < new Date()) return null;

        return record;
    }

    /**
     * Mark a token as used (one-time use)
     * @param {string} id - Token record ID
     */
    static markUsed(id) {
        db.updateById(id, { used: true, usedAt: new Date().toISOString() });
    }

    /**
     * Invalidate all tokens for a user
     * @param {string} userId
     */
    static invalidateByUser(userId) {
        const tokens = db.find({ userId });
        tokens.forEach(t => {
            db.updateById(t.id, { used: true });
        });
    }

    /**
     * Cleanup expired tokens (called periodically)
     */
    static cleanup() {
        const all = db.find();
        const now = new Date();
        all.forEach(t => {
            if (new Date(t.expiresAt) < now || t.used) {
                db.deleteById(t.id);
            }
        });
    }
}

// Clean up expired tokens every 30 minutes
setInterval(() => ResetToken.cleanup(), 30 * 60 * 1000);

module.exports = ResetToken;
