const { supabase } = require('../../lib/supabase');
const { verifyPassword, generateToken } = require('../../lib/auth');
const { checkRateLimit } = require('../../lib/rate-limit');
const { handleCors, errorResponse } = require('../../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return errorResponse(res, 400, 'Email and password are required');
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Rate limiting — max 10 login attempts per email per 15 minutes
        const rateCheck = await checkRateLimit(normalizedEmail, 'login', 10, 15);
        if (!rateCheck.allowed) {
            return errorResponse(res, 429, 'Too many login attempts. Please wait 15 minutes and try again.');
        }

        // Find user
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', normalizedEmail)
            .single();

        if (error || !user) {
            return errorResponse(res, 401, 'Invalid email or password');
        }

        // Check if password has been set
        if (!user.password_set || !user.password_hash) {
            return errorResponse(res, 401, 'Password not set yet. Please check your welcome email for the setup link, or use Forgot Password.');
        }

        // Verify password
        const validPassword = await verifyPassword(password, user.password_hash);
        if (!validPassword) {
            return errorResponse(res, 401, 'Invalid email or password');
        }

        // Generate JWT
        const token = generateToken(user.id, user.email, 'customer');

        return res.status(200).json({
            success: true,
            token: token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        return errorResponse(res, 500, 'An error occurred. Please try again.');
    }
};
