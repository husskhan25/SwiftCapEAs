const { supabase } = require('../lib/supabase');
const { requireCustomer, handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    if (req.method !== 'GET') {
        return errorResponse(res, 405, 'Method not allowed');
    }

    try {
        const user = requireCustomer(req);
        if (!user) {
            return errorResponse(res, 401, 'Please log in to view your licenses');
        }

        // Get all licenses for this user with product info and activations
        const { data: licenses, error } = await supabase
            .from('licenses')
            .select(`
                id,
                license_key,
                type,
                status,
                max_accounts,
                max_hardware,
                expires_at,
                created_at,
                product:products(
                    id,
                    name,
                    slug,
                    max_accounts,
                    max_hardware
                ),
                activations(
                    id,
                    mt_account_number,
                    hardware_id,
                    broker_name,
                    is_active,
                    activated_at,
                    last_seen_at
                )
            `)
            .eq('user_id', user.userId)
            .neq('status', 'expired')
            .order('created_at', { ascending: false });

        if (error) {
            throw new Error(`Failed to fetch licenses: ${error.message}`);
        }

        // Format response with effective limits
        const formattedLicenses = (licenses || []).map(license => {
            const activeActivations = (license.activations || []).filter(a => a.is_active);
            const effectiveMaxAccounts = license.max_accounts || license.product.max_accounts;
            const effectiveMaxHardware = license.max_hardware || license.product.max_hardware;
            const uniqueAccounts = [...new Set(activeActivations.map(a => a.mt_account_number))];
            const uniqueHardware = [...new Set(activeActivations.map(a => a.hardware_id))];

            return {
                id: license.id,
                license_key: license.license_key,
                product_name: license.product.name,
                product_slug: license.product.slug,
                type: license.type,
                status: license.status,
                max_accounts: effectiveMaxAccounts,
                max_hardware: effectiveMaxHardware,
                accounts_used: uniqueAccounts.length,
                hardware_used: uniqueHardware.length,
                expires_at: license.expires_at,
                created_at: license.created_at,
                activations: activeActivations.map(a => ({
                    id: a.id,
                    mt_account_number: a.mt_account_number,
                    hardware_id: a.hardware_id.substring(0, 8) + '...', // mask hardware ID for display
                    broker_name: a.broker_name,
                    activated_at: a.activated_at,
                    last_seen_at: a.last_seen_at
                }))
            };
        });

        return res.status(200).json({
            success: true,
            licenses: formattedLicenses
        });

    } catch (error) {
        console.error('Dashboard licenses error:', error);
        return errorResponse(res, 500, 'Failed to load licenses. Please try again.');
    }
};
