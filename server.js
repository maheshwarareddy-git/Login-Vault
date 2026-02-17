/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║                                                               ║
 * ║   🔐  L O G I N V A U L T                                    ║
 * ║   Enterprise Secure Login System                              ║
 * ║                                                               ║
 * ║   Phase 1+2: Core Auth + Advanced Security                     ║
 * ║   • bcrypt password hashing (12 rounds)                       ║
 * ║   • JWT with httpOnly cookies                                 ║
 * ║   • Rate limiting & brute force protection                    ║
 * ║   • Account lockout with progressive delays                   ║
 * ║   • Input sanitization & validation                           ║
 * ║   • Security headers (Helmet)                                 ║
 * ║                                                               ║
 * ╚═══════════════════════════════════════════════════════════════╝
 */

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const path = require('path');

const authRoutes = require('./backend/routes/auth');
const userRoutes = require('./backend/routes/user');
const adminRoutes = require('./backend/routes/admin'); // New admin routes
const { globalErrorHandler } = require('./backend/utils/errorHandler');
const { generalLimiter } = require('./backend/middleware/rateLimiter');

const app = express();

// ─── SECURITY MIDDLEWARE ───────────────────────────────────────

// Helmet: Security headers (CSP, HSTS, X-Frame-Options, etc.)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://www.gstatic.com", "https://apis.google.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://identitytoolkit.googleapis.com", "https://securetoken.googleapis.com", "https://www.googleapis.com"],
            frameSrc: ["'self'", "https://loginvault-c872d.firebaseapp.com"],
        }
    },
    crossOriginEmbedderPolicy: false
}));

// CORS
app.use(cors({
    origin: true,
    credentials: true
}));

// Prevent HTTP Parameter Pollution
app.use(hpp());

// Rate Limiting (global)
app.use('/api/', generalLimiter);

// ─── BODY PARSING ──────────────────────────────────────────────

app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ─── STATIC FILES ──────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'frontend')));

// ─── API ROUTES ────────────────────────────────────────────────

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/admin', adminRoutes); // Mount admin API

// ─── FRONTEND ROUTES ──────────────────────────────────────────

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'dashboard.html'));
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'forgot-password.html'));
});

app.get('/settings', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'settings.html'));
});

// ─── 404 HANDLER ───────────────────────────────────────────────

app.all('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        message: `Cannot find ${req.originalUrl} on this server.`
    });
});

// ─── GLOBAL ERROR HANDLER ──────────────────────────────────────

app.use(globalErrorHandler);

// ─── START SERVER ──────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log('');
    console.log('  ╔═══════════════════════════════════════════════╗');
    console.log('  ║                                               ║');
    console.log('  ║   🔐  LoginVault Server Running               ║');
    console.log(`  ║   📡  http://localhost:${PORT}                   ║`);
    console.log('  ║   🛡️   Security: ACTIVE                       ║');
    console.log('  ║   📁  Database: JSON File Storage             ║');
    console.log('  ║                                               ║');
    console.log('  ╚═══════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
