const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '7d'; // customer sessions last 7 days
const ADMIN_JWT_EXPIRY = '4h'; // admin sessions last 4 hours (more secure)

if (!JWT_SECRET) {
    throw new Error('Missing JWT_SECRET environment variable');
}

/**
 * Hash a password
 */
async function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

/**
 * Compare password with hash
 */
async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

/**
 * Generate JWT token for customer
 */
function generateToken(userId, email, role = 'customer') {
    const expiry = role === 'admin' ? ADMIN_JWT_EXPIRY : JWT_EXPIRY;
    return jwt.sign(
        { userId, email, role },
        JWT_SECRET,
        { expiresIn: expiry }
    );
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

/**
 * Generate a secure random token (for password reset, etc.)
 */
function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = { hashPassword, verifyPassword, generateToken, verifyToken, generateSecureToken };
