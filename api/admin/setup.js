const { supabase } = require('../lib/supabase');
const { hashPassword } = require('../lib/auth');
const { handleCors, errorResponse } = require('../lib/middleware');

const ADMIN_SETUP_SECRET = process.env.ADMIN_SETUP_SECRET;

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const { email, password, setup_secret } = req.body;

        // Verify setup secret (prevents anyone from creating admin accounts)
        if (!ADMIN_SETUP_SECRET || setup_secret !== ADMIN_SETUP_SECRET) {
            return errorResponse(res, 403, 'Invalid setup secret');
        }

        if (!email || !password) {
            return errorResponse(res, 400, 'Email and password are required');
        }

        if (password.length < 12) {
            return errorResponse(res, 400, 'Admin password must be at least 12 characters');
        }

        // Check if admin already exists
        const { data: existing } = await supabase
            .from('admin_users')
            .select('id')
            .eq('email', email.toLowerCase())
            .single();

        if (existing) {
            return errorResponse(res, 400, 'Admin account already exists for this email');
        }

        // Create admin
        const hashedPassword = await hashPassword(password);

        const { data: admin, error } = await supabase
            .from('admin_users')
            .insert({
                email: email.toLowerCase(),
                password_hash: hashedPassword,
                totp_enabled: false
            })
            .select('id, email, created_at')
            .single();

        if (error) throw error;

        return res.status(201).json({
            success: true,
            message: 'Admin account created. Please set up 2FA immediately after first login.',
            admin: {
                id: admin.id,
                email: admin.email
            }
        });

    } catch (error) {
        console.error('Admin setup error:', error);
        return errorResponse(res, 500, 'Failed to create admin account');
    }
};
