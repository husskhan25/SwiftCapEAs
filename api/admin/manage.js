const { supabase } = require('../lib/supabase');
const { requireAdmin, handleCors, errorResponse } = require('../lib/middleware');
const { createLicense } = require('../lib/license');
const { generateSecureToken } = require('../lib/auth');
const { sendWelcomeEmail } = require('../lib/email');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const admin = requireAdmin(req);
    if (!admin) {
        return errorResponse(res, 401, 'Unauthorized');
    }

    const action = req.method === 'GET' ? req.query.action : req.body.action;

    if (req.method === 'GET' && action === 'users') {
        return getUsers(req, res);
    }

    if (req.method === 'POST' && action === 'create-license') {
        return createLicenseHandler(req, res);
    }

    return errorResponse(res, 400, 'Invalid action');
};

async function getUsers(req, res) {
    try {
        const { search, page = 1, per_page = 50 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(per_page);

        let query = supabase
            .from('users')
            .select('id, email, name, password_set, created_at', { count: 'exact' })
            .order('created_at', { ascending: false })
            .range(offset, offset + parseInt(per_page) - 1);

        if (search) {
            query = query.or(`email.ilike.%${search}%,name.ilike.%${search}%`);
        }

        const { data: users, error, count } = await query;
        if (error) throw error;

        const userIds = (users || []).map(u => u.id);
        const { data: licenseCounts } = await supabase
            .from('licenses')
            .select('user_id')
            .in('user_id', userIds)
            .neq('status', 'expired');

        const countMap = {};
        (licenseCounts || []).forEach(l => {
            countMap[l.user_id] = (countMap[l.user_id] || 0) + 1;
        });

        const formattedUsers = (users || []).map(u => ({
            ...u,
            active_licenses: countMap[u.id] || 0
        }));

        return res.status(200).json({
            success: true,
            users: formattedUsers,
            total: count,
            page: parseInt(page),
            per_page: parseInt(per_page)
        });
    } catch (error) {
        console.error('Admin users error:', error);
        return errorResponse(res, 500, 'Failed to load users');
    }
}

async function createLicenseHandler(req, res) {
    try {
        const {
            email, name, product_slugs, license_type,
            max_accounts, max_hardware, send_email
        } = req.body;

        if (!email) {
            return errorResponse(res, 400, 'Customer email is required');
        }

        if (!product_slugs || !Array.isArray(product_slugs) || product_slugs.length === 0) {
            return errorResponse(res, 400, 'At least one product must be selected');
        }

        if (!license_type || !['lifetime', 'monthly', 'quarterly'].includes(license_type)) {
            return errorResponse(res, 400, 'License type must be lifetime, monthly, or quarterly');
        }

        const normalizedEmail = email.toLowerCase().trim();

        let { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', normalizedEmail)
            .single();

        if (!user) {
            const { data: newUser, error } = await supabase
                .from('users')
                .insert({ email: normalizedEmail, name: name || null })
                .select()
                .single();
            if (error) throw new Error(`Failed to create user: ${error.message}`);
            user = newUser;
        }

        const { data: products, error: productError } = await supabase
            .from('products')
            .select('*')
            .in('slug', product_slugs);

        if (productError || !products || products.length === 0) {
            return errorResponse(res, 400, 'Invalid product selection');
        }

        const foundSlugs = products.map(p => p.slug);
        const missingSlugs = product_slugs.filter(s => !foundSlugs.includes(s));
        if (missingSlugs.length > 0) {
            return errorResponse(res, 400, `Products not found: ${missingSlugs.join(', ')}`);
        }

        const createdLicenses = [];
        for (const product of products) {
            const license = await createLicense(
                user.id, product.id, license_type, 'manual', null,
                max_accounts || null, max_hardware || null
            );
            createdLicenses.push({
                licenseKey: license.license_key,
                productName: product.name,
                type: license_type
            });
        }

        if (send_email !== false) {
            const passwordToken = generateSecureToken();
            const tokenExpiry = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();

            await supabase
                .from('users')
                .update({ password_reset_token: passwordToken, password_reset_expires: tokenExpiry })
                .eq('id', user.id);

            await sendWelcomeEmail(user.email, user.name || name, createdLicenses, passwordToken);
        }

        return res.status(201).json({
            success: true,
            message: `${createdLicenses.length} license(s) created for ${normalizedEmail}`,
            licenses: createdLicenses,
            email_sent: send_email !== false
        });
    } catch (error) {
        console.error('Create license error:', error);
        return errorResponse(res, 500, 'Failed to create license');
    }
}
