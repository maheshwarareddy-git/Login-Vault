/**
 * ═══════════════════════════════════════════════════════════════
 *  LoginVault — Firebase Admin SDK Configuration
 *  Verifies Firebase ID tokens on the backend.
 * ═══════════════════════════════════════════════════════════════
 */

const admin = require('firebase-admin');

// Initialize Firebase Admin with project ID
// (No service account needed for ID token verification)
admin.initializeApp({
    projectId: 'loginvault-c872d'
});

const firebaseAuth = admin.auth();

/**
 * Verify a Firebase ID token
 * @param {string} idToken - The Firebase ID token from the client
 * @returns {Object} The decoded token with user info (uid, email, etc.)
 */
async function verifyFirebaseToken(idToken) {
    try {
        const decodedToken = await firebaseAuth.verifyIdToken(idToken);
        return decodedToken;
    } catch (error) {
        console.error('Firebase token verification failed:', error.message);
        throw new Error('Invalid or expired authentication token.');
    }
}

module.exports = { firebaseAuth, verifyFirebaseToken };
