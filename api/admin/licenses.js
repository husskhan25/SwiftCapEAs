const { supabase } = require('../lib/supabase');
const { requireAdmin, handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const admin = requireAdmin(req);
    if (!admin) {
        return errorResponse(res, 401, 'Unauthorized');
    }

    // GET — list/search licenses
    if (req.method === 'GET') {
        try {
            const { search, status, product_slug, page = 1, per_page = 50 } = req.query;
            const offset = (parseInt(page) - 1) * parseInt(per_page);

            let query = supabase
                .from('licenses')
                .select(`
                    *,
                    user:users(id, email, name),
                    product:products(id, name, slug, max_accounts, max_hardware),
                    activations(
                        id, mt_account_number, hardware_id, broker_name,
                        is_active, activated_at, last_seen_at
                    )
                `, { count: 'exact' })
                .order('created_at', { ascending: false })
                .range(offset, offset + parseInt(per_page) - 1);

            // Filter by status
            if (status) {
                query = query.eq('status', status);
            }

            const { data: licenses, error, count } = await query;

            if (error) throw error;

            // Apply search filter (email or license key) — done in JS because Supabase
            // doesn't support OR across joined tables easily
            let filtered = licenses || [];
            if (search) {
                const searchLower = search.toLowerCase();
                filtered = filtered.filter(l =>
                    l.license_key.toLowerCase().includes(searchLower) ||
                    l.user?.email?.toLowerCase().includes(searchLower) ||
                    l.user?.name?.toLowerCase().includes(searchLower)
                );
            }

            // Filter by product
            if (product_slug) {
                filtered = filtered.filter(l => l.product?.slug === product_slug);
            }

            // Format response
            const formattedLicenses = filtered.map(l => {
                const activeActivations = (l.activations || []).filter(a => a.is_active);
                return {
                    id: l.id,
                    license_key: l.license_key,
                    user_email: l.user?.email,
                    user_name: l.user?.name,
                    product_name: l.product?.name,
                    product_slug: l.product?.slug,
                    type: l.type,
                    status: l.status,
                    source: l.source,
                    max_accounts: l.max_accounts || l.product?.max_accounts,
                    max_hardware: l.max_hardware || l.product?.max_hardware,
                    accounts_used: [...new Set(activeActivations.map(a => a.mt_account_number))].length,
                    hardware_used: [...new Set(activeActivations.map(a => a.hardware_id))].length,
                    expires_at: l.expires_at,
                    created_at: l.created_at,
                    activations: activeActivations
                };
            });

            return res.status(200).json({
                success: true,
                licenses: formattedLicenses,
                total: count,
                page: parseInt(page),
                per_page: parseInt(per_page)
            });

        } catch (error) {
            console.error('Admin licenses error:', error);
            return errorResponse(res, 500, 'Failed to load licenses');
        }
    }

    // PUT — update a license (revoke, change limits, change status)
    if (req.method === 'PUT') {
        try {
            const { license_id, status, max_accounts, max_hardware } = req.body;

            if (!license_id) {
                return errorResponse(res, 400, 'License ID is required');
            }

            const updates = {};
            if (status !== undefined) updates.status = status;
            if (max_accounts !== undefined) updates.max_accounts = max_accounts;
            if (max_hardware !== undefined) updates.max_hardware = max_hardware;

            if (Object.keys(updates).length === 0) {
                return errorResponse(res, 400, 'No changes provided');
            }

            const { data: license, error } = await supabase
                .from('licenses')
                .update(updates)
                .eq('id', license_id)
                .select(`
                    *,
                    user:users(email, name),
                    product:products(name)
                `)
                .single();

            if (error) throw error;

            return res.status(200).json({
                success: true,
                message: `License ${license.license_key} updated`,
                license
            });

        } catch (error) {
            console.error('License update error:', error);
            return errorResponse(res, 500, 'Failed to update license');
        }
    }

    // DELETE — force remove an activation
    if (req.method === 'DELETE') {
        try {
            const { activation_id } = req.body;

            if (!activation_id) {
                return errorResponse(res, 400, 'Activation ID is required');
            }

            await supabase
                .from('activations')
                .update({ is_active: false })
                .eq('id', activation_id);

            return res.status(200).json({
                success: true,
                message: 'Activation removed'
            });

        } catch (error) {
            console.error('Activation removal error:', error);
            return errorResponse(res, 500, 'Failed to remove activation');
        }
    }

    return errorResponse(res, 405, 'Method not allowed');
};
