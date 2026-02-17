/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Error Handler
 *  Centralized error handling with account enumeration prevention.
 * ═══════════════════════════════════════════════════════════════
 */

class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Global error handling middleware
 */
const globalErrorHandler = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    if (process.env.NODE_ENV === 'development') {
        return res.status(err.statusCode).json({
            status: err.status,
            message: err.message,
            error: err,
            stack: err.stack
        });
    }

    // Production: don't leak error details
    if (err.isOperational) {
        return res.status(err.statusCode).json({
            status: err.status,
            message: err.message
        });
    }

    // Programming or unknown errors
    console.error('💥 ERROR:', err);
    return res.status(500).json({
        status: 'error',
        message: 'Something went wrong. Please try again later.'
    });
};

module.exports = { AppError, globalErrorHandler };
