const { supabase } = require('../lib/supabase');
const { verifyPassword, generateToken } = require('../lib/auth');
const { checkRateLimit } = require('../lib/rate-limit');
const { handleCors, errorResponse } = require('../lib/middleware');
const { authenticator } = require('otplib');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const { email, password, totp_code } = req.body;

        if (!email || !password) {
            return errorResponse(res, 400, 'Email and password are required');
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Strict rate limiting for admin — max 5 attempts per 30 minutes
        const rateCheck = await checkRateLimit(normalizedEmail, 'admin_login', 5, 30);
        if (!rateCheck.allowed) {
            return errorResponse(res, 429, 'Too many attempts. Account locked for 30 minutes.');
        }

        // Find admin user
        const { data: admin, error } = await supabase
            .from('admin_users')
            .select('*')
            .eq('email', normalizedEmail)
            .single();

        if (error || !admin) {
            return errorResponse(res, 401, 'Invalid credentials');
        }

        // Verify password
        const validPassword = await verifyPassword(password, admin.password_hash);
        if (!validPassword) {
            return errorResponse(res, 401, 'Invalid credentials');
        }

        // Check 2FA if enabled
        if (admin.totp_enabled) {
            if (!totp_code) {
                return res.status(200).json({
                    success: false,
                    requires_2fa: true,
                    message: 'Enter your authenticator code'
                });
            }

            const isValidTotp = authenticator.check(totp_code, admin.totp_secret);
            if (!isValidTotp) {
                return errorResponse(res, 401, 'Invalid authenticator code');
            }
        }

        // Generate admin JWT
        const token = generateToken(admin.id, admin.email, 'admin');

        return res.status(200).json({
            success: true,
            token: token,
            admin: {
                id: admin.id,
                email: admin.email,
                totp_enabled: admin.totp_enabled
            }
        });

    } catch (error) {
        console.error('Admin login error:', error);
        return errorResponse(res, 500, 'An error occurred');
    }
};
