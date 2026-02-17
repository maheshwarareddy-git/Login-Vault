/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Rate Limiter Middleware
 *  Protects against brute force and DDoS attacks.
 * ═══════════════════════════════════════════════════════════════
 */

// In-memory rate limiting store
const rateLimitStore = new Map();

/**
 * Creates a rate limiter middleware
 * @param {Object} options - { windowMs, max, message }
 */
function createRateLimiter({ windowMs = 15 * 60 * 1000, max = 100, message = 'Too many requests' }) {
    return (req, res, next) => {
        const key = req.ip || req.connection.remoteAddress;
        const now = Date.now();

        if (!rateLimitStore.has(key)) {
            rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
            return next();
        }

        const entry = rateLimitStore.get(key);

        // Reset window if expired
        if (now > entry.resetTime) {
            rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
            return next();
        }

        entry.count++;

        if (entry.count > max) {
            const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
            res.set('Retry-After', retryAfter);
            return res.status(429).json({
                status: 'error',
                message: message,
                retryAfterSeconds: retryAfter
            });
        }

        next();
    };
}

// General API rate limiter — 100 requests per 15 minutes
const generalLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP. Please try again later.'
});

// Auth-specific rate limiter — 30 login/register attempts per 15 minutes (Relaxes for testing)
const authLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: 'Too many authentication attempts. Please try again in 15 minutes.'
});

// Clean up expired entries every 30 minutes
setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitStore) {
        if (now > entry.resetTime) {
            rateLimitStore.delete(key);
        }
    }
}, 30 * 60 * 1000);

module.exports = { generalLimiter, authLimiter, createRateLimiter };
