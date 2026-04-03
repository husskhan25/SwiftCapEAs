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

    if (req.method !== 'POST') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const {
            email,
            name,
            product_slugs,      // array: ['master', 'trinity'] or ['master']
            license_type,        // 'lifetime', 'monthly', 'quarterly'
            max_accounts,        // optional override
            max_hardware,        // optional override
            send_email           // boolean — whether to send welcome email
        } = req.body;

        // Validation
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

        // Find or create user
        let { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('email', normalizedEmail)
            .single();

        if (!user) {
            const { data: newUser, error } = await supabase
                .from('users')
                .insert({
                    email: normalizedEmail,
                    name: name || null
                })
                .select()
                .single();

            if (error) throw new Error(`Failed to create user: ${error.message}`);
            user = newUser;
        }

        // Get products
        const { data: products, error: productError } = await supabase
            .from('products')
            .select('*')
            .in('slug', product_slugs);

        if (productError || !products || products.length === 0) {
            return errorResponse(res, 400, 'Invalid product selection');
        }

        // Check all requested products were found
        const foundSlugs = products.map(p => p.slug);
        const missingSlugs = product_slugs.filter(s => !foundSlugs.includes(s));
        if (missingSlugs.length > 0) {
            return errorResponse(res, 400, `Products not found: ${missingSlugs.join(', ')}`);
        }

        // Create licenses
        const createdLicenses = [];
        for (const product of products) {
            const license = await createLicense(
                user.id,
                product.id,
                license_type,
                'manual',
                null,
                max_accounts || null,
                max_hardware || null
            );
            createdLicenses.push({
                licenseKey: license.license_key,
                productName: product.name,
                type: license_type
            });
        }

        // Send welcome email if requested
        if (send_email !== false) {
            const passwordToken = generateSecureToken();
            const tokenExpiry = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();

            await supabase
                .from('users')
                .update({
                    password_reset_token: passwordToken,
                    password_reset_expires: tokenExpiry
                })
                .eq('id', user.id);

            await sendWelcomeEmail(
                user.email,
                user.name || name,
                createdLicenses,
                passwordToken
            );
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
};
