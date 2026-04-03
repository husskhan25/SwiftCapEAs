const { verifyToken } = require('./auth');

/**
 * Parse Authorization header and verify JWT
 * Returns decoded token or null
 */
function authenticateRequest(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }

    const token = authHeader.split(' ')[1];
    return verifyToken(token);
}

/**
 * Verify request is from authenticated customer
 */
function requireCustomer(req) {
    const decoded = authenticateRequest(req);
    if (!decoded || decoded.role !== 'customer') {
        return null;
    }
    return decoded;
}

/**
 * Verify request is from authenticated admin
 */
function requireAdmin(req) {
    const decoded = authenticateRequest(req);
    if (!decoded || decoded.role !== 'admin') {
        return null;
    }
    return decoded;
}

/**
 * Standard JSON error response
 */
function errorResponse(res, statusCode, message) {
    return res.status(statusCode).json({ success: false, error: message });
}

/**
 * Handle CORS preflight
 */
function handleCors(req, res) {
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return true;
    }
    return false;
}

module.exports = { authenticateRequest, requireCustomer, requireAdmin, errorResponse, handleCors };
