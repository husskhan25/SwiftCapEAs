const { supabase } = require('../lib/supabase');
const { hashPassword, generateToken } = require('../lib/auth');
const { handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const { token, password } = req.body;

        if (!token || !password) {
            return errorResponse(res, 400, 'Token and password are required');
        }

        // Validate password length
        if (password.length < 8) {
            return errorResponse(res, 400, 'Password must be at least 8 characters');
        }

        // Find user with this token
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('password_reset_token', token)
            .single();

        if (error || !user) {
            return errorResponse(res, 400, 'Invalid or expired link. Please use Forgot Password to get a new link.');
        }

        // Check token expiry
        if (user.password_reset_expires && new Date(user.password_reset_expires) < new Date()) {
            return errorResponse(res, 400, 'This link has expired. Please use Forgot Password to get a new link.');
        }

        // Hash and save password
        const hashedPassword = await hashPassword(password);

        const { error: updateError } = await supabase
            .from('users')
            .update({
                password_hash: hashedPassword,
                password_set: true,
                password_reset_token: null,
                password_reset_expires: null
            })
            .eq('id', user.id);

        if (updateError) {
            throw new Error(`Failed to update password: ${updateError.message}`);
        }

        // Auto-login after setting password
        const jwtToken = generateToken(user.id, user.email, 'customer');

        return res.status(200).json({
            success: true,
            message: 'Password set successfully',
            token: jwtToken,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        });

    } catch (error) {
        console.error('Set password error:', error);
        return errorResponse(res, 500, 'An error occurred. Please try again.');
    }
};
