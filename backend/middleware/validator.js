/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Input Validator Middleware
 *  Validates and sanitizes all user input.
 * ═══════════════════════════════════════════════════════════════
 */

const validator = require('validator');

/**
 * Validate registration input
 */
const validateRegistration = (req, res, next) => {
    const { email, password, confirmPassword, name } = req.body;
    const errors = [];

    // Email validation
    if (!email) {
        errors.push('Email is required.');
    } else if (!validator.isEmail(email)) {
        errors.push('Please provide a valid email address.');
    }

    // Name validation
    if (name && name.length > 50) {
        errors.push('Name must be less than 50 characters.');
    }

    // Password validation
    if (!password) {
        errors.push('Password is required.');
    } else {
        if (password.length < 8) {
            errors.push('Password must be at least 8 characters long.');
        }
        if (password.length > 128) {
            errors.push('Password must be less than 128 characters.');
        }
        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter.');
        }
        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter.');
        }
        if (!/[0-9]/.test(password)) {
            errors.push('Password must contain at least one number.');
        }
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character.');
        }
    }

    // Confirm password
    if (confirmPassword !== undefined && password !== confirmPassword) {
        errors.push('Passwords do not match.');
    }

    if (errors.length > 0) {
        return res.status(400).json({
            status: 'error',
            message: 'Validation failed.',
            errors
        });
    }

    // Sanitize inputs
    req.body.email = validator.normalizeEmail(email);
    if (name) req.body.name = validator.escape(validator.trim(name));

    next();
};

/**
 * Validate login input
 */
const validateLogin = (req, res, next) => {
    const { email, password } = req.body;
    const errors = [];

    if (!email) {
        errors.push('Email is required.');
    } else if (!validator.isEmail(email)) {
        errors.push('Please provide a valid email address.');
    }

    if (!password) {
        errors.push('Password is required.');
    }

    if (errors.length > 0) {
        return res.status(400).json({
            status: 'error',
            message: 'Validation failed.',
            errors
        });
    }

    req.body.email = validator.normalizeEmail(email);
    next();
};

module.exports = { validateRegistration, validateLogin };
