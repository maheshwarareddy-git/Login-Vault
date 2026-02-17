/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — CSRF Protection Middleware
 *  Token-based CSRF protection for state-changing operations.
 * ═══════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');

// In-memory CSRF token store (keyed by session/user)
const csrfTokens = new Map();

/**
 * Generate a CSRF token for the current session
 */
function generateCsrfToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    csrfTokens.set(sessionId, {
        token,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
    });
    return token;
}

/**
 * Validate a CSRF token
 */
function validateCsrfToken(sessionId, token) {
    const stored = csrfTokens.get(sessionId);
    if (!stored) return false;
    if (stored.expiresAt < Date.now()) {
        csrfTokens.delete(sessionId);
        return false;
    }
    // Timing-safe comparison
    try {
        return crypto.timingSafeEqual(
            Buffer.from(stored.token),
            Buffer.from(token)
        );
    } catch {
        return false;
    }
}

/**
 * Middleware to provide CSRF token on GET requests
 */
function csrfTokenProvider(req, res, next) {
    // Generate token based on JWT cookie or IP
    const sessionKey = (req.cookies && req.cookies.jwt) || req.ip;
    const token = generateCsrfToken(sessionKey);
    res.locals.csrfToken = token;
    next();
}

/**
 * Middleware to validate CSRF token on state-changing requests
 */
function csrfProtection(req, res, next) {
    // Only protect state-changing methods
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const sessionKey = (req.cookies && req.cookies.jwt) || req.ip;
    const token = req.headers['x-csrf-token'] || req.body._csrf;

    if (!token) {
        return res.status(403).json({
            status: 'error',
            message: 'CSRF token missing. Please refresh the page and try again.'
        });
    }

    if (!validateCsrfToken(sessionKey, token)) {
        return res.status(403).json({
            status: 'error',
            message: 'Invalid or expired CSRF token. Please refresh the page.'
        });
    }

    next();
}

/**
 * Endpoint to get a fresh CSRF token
 */
function getCsrfToken(req, res) {
    const sessionKey = (req.cookies && req.cookies.jwt) || req.ip;
    const token = generateCsrfToken(sessionKey);
    res.json({ csrfToken: token });
}

// Cleanup expired tokens every 30 minutes
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of csrfTokens) {
        if (val.expiresAt < now) csrfTokens.delete(key);
    }
}, 30 * 60 * 1000);

module.exports = { csrfProtection, csrfTokenProvider, getCsrfToken, generateCsrfToken };
