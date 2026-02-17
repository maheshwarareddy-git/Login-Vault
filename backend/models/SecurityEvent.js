/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Security Event Model
 *  Centralized audit log for all security events.
 * ═══════════════════════════════════════════════════════════════
 */

const { v4: uuidv4 } = require('uuid');
const JsonDB = require('../config/database');

const db = new JsonDB('security_events');

class SecurityEvent {
    /**
     * Log a security event
     * @param {Object} data
     */
    static log({ userId, email, action, ip, userAgent, details, severity }) {
        const event = {
            id: uuidv4(),
            userId: userId || null,
            email: email || null,
            action,
            ip: ip || 'unknown',
            userAgent: userAgent || 'unknown',
            details: details || null,
            severity: severity || 'info', // info, warning, critical
            timestamp: new Date().toISOString()
        };

        db.insert(event);
        return event;
    }

    /**
     * Get recent events for a user
     * @param {string} userId
     * @param {number} limit
     * @returns {Array}
     */
    static getByUser(userId, limit = 20) {
        const events = db.find({ userId });
        return events
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, limit);
    }

    /**
     * Get all events (admin)
     * @param {number} limit
     * @returns {Array}
     */
    static getAll(limit = 100) {
        const events = db.find();
        return events
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, limit);
    }

    /**
     * Get events by action type
     * @param {string} action
     * @returns {Array}
     */
    static getByAction(action) {
        return db.find({ action })
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    /**
     * Get suspicious events (warnings + critical)
     * @param {number} limit
     * @returns {Array}
     */
    static getSuspicious(limit = 50) {
        const events = db.find();
        return events
            .filter(e => e.severity === 'warning' || e.severity === 'critical')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, limit);
    }

    /**
     * Count failed login attempts for an IP in the last N minutes
     * @param {string} ip
     * @param {number} minutes
     * @returns {number}
     */
    static countFailedLoginsFromIP(ip, minutes = 15) {
        const cutoff = new Date(Date.now() - minutes * 60 * 1000);
        const events = db.find({ ip, action: 'LOGIN_FAILED' });
        return events.filter(e => new Date(e.timestamp) > cutoff).length;
    }
}

module.exports = SecurityEvent;
