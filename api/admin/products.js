const { supabase } = require('../lib/supabase');
const { requireAdmin, handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const admin = requireAdmin(req);
    if (!admin) {
        return errorResponse(res, 401, 'Unauthorized');
    }

    // GET — list all products with defaults
    if (req.method === 'GET') {
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

    // PUT — update product defaults (max_accounts, max_hardware, is_active)
    if (req.method === 'PUT') {
        try {
            const { product_id, max_accounts, max_hardware, is_active } = req.body;

            if (!product_id) {
                return errorResponse(res, 400, 'Product ID is required');
            }

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

    // POST — add new product (for future scalability)
    if (req.method === 'POST') {
        try {
            const { name, slug, key_prefix, max_accounts, max_hardware } = req.body;

            if (!name || !slug || !key_prefix) {
                return errorResponse(res, 400, 'Name, slug, and key_prefix are required');
            }

            const { data: product, error } = await supabase
                .from('products')
                .insert({
                    name,
                    slug,
                    key_prefix,
                    max_accounts: max_accounts || 5,
                    max_hardware: max_hardware || 2
                })
                .select()
                .single();

            if (error) throw error;

            return res.status(201).json({
                success: true,
                message: `${product.name} created successfully`,
                product
            });

        } catch (error) {
            console.error('Product create error:', error);
            return errorResponse(res, 500, 'Failed to create product');
        }
    }

    return errorResponse(res, 405, 'Method not allowed');
};
