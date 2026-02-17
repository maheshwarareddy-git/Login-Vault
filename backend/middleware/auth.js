/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Auth Middleware
 *  JWT token verification for protected routes.
 * ═══════════════════════════════════════════════════════════════
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Protect routes — verifies JWT from httpOnly cookie
 */
const protect = async (req, res, next) => {
    try {
        // 1. Extract token from httpOnly cookie
        let token = null;
        if (req.cookies && req.cookies.jwt) {
            token = req.cookies.jwt;
        }

        if (!token) {
            return res.status(401).json({
                status: 'error',
                message: 'You are not logged in. Please log in to access this resource.'
            });
        }

        // 2. Verify token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    status: 'error',
                    message: 'Session expired. Please log in again.'
                });
            }
            return res.status(401).json({
                status: 'error',
                message: 'Invalid session. Please log in again.'
            });
        }

        // 3. Check if user still exists
        const user = User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({
                status: 'error',
                message: 'User no longer exists.'
            });
        }

        // 4. Check if user is locked
        if (User.isAccountLocked(user)) {
            return res.status(403).json({
                status: 'error',
                message: 'Account is locked. Please try again later.'
            });
        }

        // 5. Attach user to request
        req.user = User.sanitize(user);
        next();
    } catch (err) {
        return res.status(500).json({
            status: 'error',
            message: 'Authentication error. Please try again.'
        });
    }
};

/**
 * Restrict to specific roles
 * @param  {...string} roles - 'admin', 'user'
 */
const restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                status: 'error',
                message: 'You do not have permission to perform this action.'
            });
        }
        next();
    };
};

module.exports = { protect, restrictTo };
