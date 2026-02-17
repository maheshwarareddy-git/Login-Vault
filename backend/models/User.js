/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — User Model
 *  Handles user data, password hashing, and login attempt tracking.
 * ═══════════════════════════════════════════════════════════════
 */

const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const JsonDB = require('../config/database');

const db = new JsonDB('users');

const SALT_ROUNDS = 12;
const MAX_LOGIN_ATTEMPTS = 3;
// Lockout is now indefinite, so LOCK_TIME_MS is removed.

class User {
    /**
     * Create a new user
     * @param {Object} userData - { email, password, name }
     * @returns {Object} Created user (without password)
     */
    static async create({ email, password, name }) {
        // Hash password with bcrypt (12 salt rounds)
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const user = {
            id: uuidv4(),
            email: email.toLowerCase().trim(),
            name: name ? name.trim() : '',
            passwordHash,
            role: 'user',
            isVerified: false,
            isLocked: false,
            failedLoginAttempts: 0,
            unblockRequest: null, // { reason, status: 'pending'|'approved'|'rejected', timestamp }
            lastLogin: null,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            securityLog: []
        };

        db.insert(user);
        return User.sanitize(user);
    }

    /**
     * Find user by email
     * @param {string} email
     * @returns {Object|null} Full user object (includes hash)
     */
    static findByEmail(email) {
        return db.findOne({ email: email.toLowerCase().trim() });
    }

    /**
     * Find user by ID
     * @param {string} id
     * @returns {Object|null} Full user object
     */
    static findById(id) {
        return db.findById(id);
    }

    /**
     * Find user by reset token
     * @param {string} token
     * @returns {Object|null}
     */
    static findByResetToken(token) {
        return db.findOne({ resetPasswordToken: token });
    }

    /**
     * Compare a candidate password with the stored hash
     * @param {string} candidatePassword
     * @param {string} storedHash
     * @returns {boolean}
     */
    static async comparePassword(candidatePassword, storedHash) {
        return bcrypt.compare(candidatePassword, storedHash);
    }

    /**
     * Check if account is currently locked
     * @param {Object} user
     * @returns {boolean}
     */
    static isAccountLocked(user) {
        // Indefinite lock until admin unlocks
        return user.isLocked === true;
    }

    /**
     * Increment failed login attempts & lock if threshold reached
     * @param {string} userId
     * @returns {Object} Updated user
     */
    static incrementLoginAttempts(userId) {
        const user = db.findById(userId);
        if (!user) return null;

        const attempts = (user.failedLoginAttempts || 0) + 1;
        const updates = {
            failedLoginAttempts: attempts,
            updatedAt: new Date().toISOString()
        };

        if (attempts >= MAX_LOGIN_ATTEMPTS) {
            updates.isLocked = true;
            // No lockUntil, it's permanent until admin unlocks
        }

        return db.updateById(userId, updates);
    }

    /**
     * Reset login attempts on successful login
     * @param {string} userId
     */
    static resetLoginAttempts(userId) {
        db.updateById(userId, {
            failedLoginAttempts: 0,
            isLocked: false,
            unblockRequest: null, // Clear any previous request
            lastLogin: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        });
    }

    /**
     * Add a security log entry
     * @param {string} userId
     * @param {Object} entry - { action, ip, userAgent, timestamp }
     */
    static addSecurityLog(userId, entry) {
        const user = db.findById(userId);
        if (!user) return;

        const log = user.securityLog || [];
        log.unshift({
            ...entry,
            timestamp: new Date().toISOString()
        });

        // Keep only last 50 entries
        if (log.length > 50) log.length = 50;

        db.updateById(userId, { securityLog: log });
    }

    /**
     * Set password reset token
     * @param {string} userId
     * @param {string} token
     * @param {number} expires - Timestamp
     */
    static setResetToken(userId, token, expires) {
        db.updateById(userId, {
            resetPasswordToken: token,
            resetPasswordExpires: expires
        });
    }

    /**
     * Update password and clear reset token
     * @param {string} userId
     * @param {string} newHash
     */
    static flattenResetToken(userId, newHash) {
        db.updateById(userId, {
            passwordHash: newHash,
            resetPasswordToken: null,
            resetPasswordExpires: null,
            isLocked: false, // Auto-unlock on password reset
            failedLoginAttempts: 0,
            updatedAt: new Date().toISOString()
        });
    }

    /**
     * Update user profile
     * @param {string} userId
     * @param {Object} updates
     * @returns {Object} Sanitized user
     */
    static update(userId, updates) {
        const allowedUpdates = {};
        if (updates.name) allowedUpdates.name = updates.name.trim();
        allowedUpdates.updatedAt = new Date().toISOString();
        const user = db.updateById(userId, allowedUpdates);
        return user ? User.sanitize(user) : null;
    }

    /**
     * Remove sensitive fields from user object
     * @param {Object} user
     * @returns {Object}
     */
    static sanitize(user) {
        if (!user) return null;
        const { passwordHash, securityLog, ...safe } = user;
        return safe;
    }

    /**
     * Get all users (admin)
     * @returns {Array}
     */
    static findAll() {
        const users = db.find();
        return users.map(User.sanitize);
    }
}

module.exports = User;
