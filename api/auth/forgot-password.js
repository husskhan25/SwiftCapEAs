const { supabase } = require('../lib/supabase');
const { generateSecureToken } = require('../lib/auth');
const { sendPasswordResetEmail } = require('../lib/email');
const { checkRateLimit } = require('../lib/rate-limit');
const { handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const { email } = req.body;

        if (!email) {
            return errorResponse(res, 400, 'Email is required');
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Rate limiting — max 5 reset requests per email per 60 minutes
        const rateCheck = await checkRateLimit(normalizedEmail, 'forgot_password', 5, 60);
        if (!rateCheck.allowed) {
            return errorResponse(res, 429, 'Too many reset requests. Please wait and try again later.');
        }

        // Always return success (don't reveal if email exists)
        const successMessage = 'If an account with that email exists, a password reset link has been sent.';

        // Find user
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', normalizedEmail)
            .single();

        if (!user) {
            // Don't reveal that the email doesn't exist
            return res.status(200).json({ success: true, message: successMessage });
        }

        // Generate reset token
        const resetToken = generateSecureToken();
        const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

        await supabase
            .from('users')
            .update({
                password_reset_token: resetToken,
                password_reset_expires: tokenExpiry
            })
            .eq('id', user.id);

        // Send reset email
        await sendPasswordResetEmail(user.email, user.name, resetToken);

        return res.status(200).json({ success: true, message: successMessage });

    } catch (error) {
        console.error('Forgot password error:', error);
        return errorResponse(res, 500, 'An error occurred. Please try again.');
    }
};
