const { supabase } = require('../../lib/supabase');
const { hashPassword, generateSecureToken } = require('../../lib/auth');
const { generateToken } = require('../../lib/auth');
const { sendPasswordResetEmail } = require('../../lib/email');
const { checkRateLimit } = require('../../lib/rate-limit');
const { handleCors, errorResponse } = require('../../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    const { action } = req.body;

    if (action === 'set-password') {
        return handleSetPassword(req, res);
    } else if (action === 'forgot-password') {
        return handleForgotPassword(req, res);
    } else if (action === 'reset-password') {
        return handleResetPassword(req, res);
    } else {
        return errorResponse(res, 400, 'Invalid action. Use: set-password, forgot-password, or reset-password');
    }
};

async function handleSetPassword(req, res) {
    try {
        const { token, password } = req.body;

        if (!token || !password) {
            return errorResponse(res, 400, 'Token and password are required');
        }

        if (password.length < 8) {
            return errorResponse(res, 400, 'Password must be at least 8 characters');
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('password_reset_token', token)
            .single();

        if (error || !user) {
            return errorResponse(res, 400, 'Invalid or expired link. Please use Forgot Password to get a new link.');
        }

        if (user.password_reset_expires && new Date(user.password_reset_expires) < new Date()) {
            return errorResponse(res, 400, 'This link has expired. Please use Forgot Password to get a new link.');
        }

        const hashedPassword = await hashPassword(password);

        await supabase
            .from('users')
            .update({
                password_hash: hashedPassword,
                password_set: true,
                password_reset_token: null,
                password_reset_expires: null
            })
            .eq('id', user.id);

        const jwtToken = generateToken(user.id, user.email, 'customer');

        return res.status(200).json({
            success: true,
            message: 'Password set successfully',
            token: jwtToken,
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        console.error('Set password error:', error);
        return errorResponse(res, 500, 'An error occurred. Please try again.');
    }
}

async function handleForgotPassword(req, res) {
    try {
        const { email } = req.body;

        if (!email) {
            return errorResponse(res, 400, 'Email is required');
        }

        const normalizedEmail = email.toLowerCase().trim();

        const rateCheck = await checkRateLimit(normalizedEmail, 'forgot_password', 5, 60);
        if (!rateCheck.allowed) {
            return errorResponse(res, 429, 'Too many reset requests. Please wait and try again later.');
        }

        const successMessage = 'If an account with that email exists, a password reset link has been sent.';

        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', normalizedEmail)
            .single();

        if (!user) {
            return res.status(200).json({ success: true, message: successMessage });
        }

        const resetToken = generateSecureToken();
        const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();

        await supabase
            .from('users')
            .update({
                password_reset_token: resetToken,
                password_reset_expires: tokenExpiry
            })
            .eq('id', user.id);

        await sendPasswordResetEmail(user.email, user.name, resetToken);

        return res.status(200).json({ success: true, message: successMessage });
    } catch (error) {
        console.error('Forgot password error:', error);
        return errorResponse(res, 500, 'An error occurred. Please try again.');
    }
}

async function handleResetPassword(req, res) {
    try {
        const { token, password } = req.body;

        if (!token || !password) {
            return errorResponse(res, 400, 'Token and password are required');
        }

        if (password.length < 8) {
            return errorResponse(res, 400, 'Password must be at least 8 characters');
        }

        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('password_reset_token', token)
            .single();

        if (error || !user) {
            return errorResponse(res, 400, 'Invalid or expired reset link. Please request a new one.');
        }

        if (user.password_reset_expires && new Date(user.password_reset_expires) < new Date()) {
            return errorResponse(res, 400, 'This reset link has expired. Please request a new one.');
        }

        const hashedPassword = await hashPassword(password);

        await supabase
            .from('users')
            .update({
                password_hash: hashedPassword,
                password_set: true,
                password_reset_token: null,
                password_reset_expires: null
            })
            .eq('id', user.id);

        return res.status(200).json({
            success: true,
            message: 'Password has been reset successfully. You can now log in.'
        });
    } catch (error) {
        console.error('Reset password error:', error);
        return errorResponse(res, 500, 'An error occurred. Please try again.');
    }
}
