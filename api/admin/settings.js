const { supabase } = require('../lib/supabase');
const { requireAdmin, handleCors, errorResponse } = require('../lib/middleware');
const { hashPassword } = require('../lib/auth');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const ADMIN_SETUP_SECRET = process.env.ADMIN_SETUP_SECRET;

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const action = req.method === 'GET' ? req.query.action : req.body.action;

    // Admin setup (no auth required — uses setup secret)
    if (action === 'setup-admin') {
        return setupAdmin(req, res);
    }

    // All other actions require admin auth
    const admin = requireAdmin(req);
    if (!admin) {
        return errorResponse(res, 401, 'Unauthorized');
    }

    if (req.method === 'GET') {
        if (action === 'products') return getProducts(req, res);
        if (action === 'setup-2fa') return generate2FA(req, res, admin);
        return errorResponse(res, 400, 'Invalid action');
    }

    if (req.method === 'POST') {
        if (action === 'verify-2fa') return verify2FA(req, res, admin);
        return errorResponse(res, 400, 'Invalid action');
    }

    if (req.method === 'PUT') {
        if (action === 'update-product') return updateProduct(req, res);
        return errorResponse(res, 400, 'Invalid action');
    }

    return errorResponse(res, 405, 'Method not allowed');
};

async function setupAdmin(req, res) {
    if (req.method !== 'POST') return errorResponse(res, 405, 'Method not allowed');

    try {
        const { email, password, setup_secret } = req.body;

        if (!ADMIN_SETUP_SECRET || setup_secret !== ADMIN_SETUP_SECRET) {
            return errorResponse(res, 403, 'Invalid setup secret');
        }

        if (!email || !password) {
            return errorResponse(res, 400, 'Email and password are required');
        }

        if (password.length < 12) {
            return errorResponse(res, 400, 'Admin password must be at least 12 characters');
        }

        const { data: existing } = await supabase
            .from('admin_users')
            .select('id')
            .eq('email', email.toLowerCase())
            .single();

        if (existing) {
            return errorResponse(res, 400, 'Admin account already exists for this email');
        }

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
            admin: { id: admin.id, email: admin.email }
        });
    } catch (error) {
        console.error('Admin setup error:', error);
        return errorResponse(res, 500, 'Failed to create admin account');
    }
}

async function getProducts(req, res) {
    try {
        const { data: products, error } = await supabase
            .from('products')
            .select('*')
            .order('created_at', { ascending: true });

        if (error) throw error;
        return res.status(200).json({ success: true, products });
    } catch (error) {
        console.error('Products fetch error:', error);
        return errorResponse(res, 500, 'Failed to load products');
    }
}

async function updateProduct(req, res) {
    try {
        const { product_id, max_accounts, max_hardware, is_active } = req.body;

        if (!product_id) return errorResponse(res, 400, 'Product ID is required');

        const updates = {};
        if (max_accounts !== undefined) updates.max_accounts = max_accounts;
        if (max_hardware !== undefined) updates.max_hardware = max_hardware;
        if (is_active !== undefined) updates.is_active = is_active;

        if (Object.keys(updates).length === 0) {
            return errorResponse(res, 400, 'No changes provided');
        }

        const { data: product, error } = await supabase
            .from('products')
            .update(updates)
            .eq('id', product_id)
            .select()
            .single();

        if (error) throw error;

        return res.status(200).json({
            success: true,
            message: `${product.name} updated successfully`,
            product
        });
    } catch (error) {
        console.error('Product update error:', error);
        return errorResponse(res, 500, 'Failed to update product');
    }
}

async function generate2FA(req, res, admin) {
    try {
        const secret = authenticator.generateSecret();
        const otpauth = authenticator.keyuri(admin.email, 'SwiftCap Admin', secret);
        const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

        await supabase
            .from('admin_users')
            .update({ totp_secret: secret })
            .eq('id', admin.userId);

        return res.status(200).json({
            success: true,
            secret: secret,
            qr_code: qrCodeDataUrl,
            message: 'Scan this QR code with Google Authenticator or Authy, then verify with a code.'
        });
    } catch (error) {
        console.error('2FA setup error:', error);
        return errorResponse(res, 500, 'Failed to generate 2FA setup');
    }
}

async function verify2FA(req, res, admin) {
    try {
        const { totp_code } = req.body;

        if (!totp_code) return errorResponse(res, 400, 'Authenticator code is required');

        const { data: adminData } = await supabase
            .from('admin_users')
            .select('totp_secret')
            .eq('id', admin.userId)
            .single();

        if (!adminData || !adminData.totp_secret) {
            return errorResponse(res, 400, 'Please generate 2FA setup first');
        }

        const isValid = authenticator.check(totp_code, adminData.totp_secret);
        if (!isValid) {
            return errorResponse(res, 400, 'Invalid code. Please try again with a fresh code from your authenticator app.');
        }

        await supabase
            .from('admin_users')
            .update({ totp_enabled: true })
            .eq('id', admin.userId);

        return res.status(200).json({
            success: true,
            message: '2FA has been enabled successfully. You will need your authenticator code on every login.'
        });
    } catch (error) {
        console.error('2FA verify error:', error);
        return errorResponse(res, 500, 'Failed to enable 2FA');
    }
}
