const { supabase } = require('../lib/supabase');
const { requireAdmin, handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const admin = requireAdmin(req);
    if (!admin) {
        return errorResponse(res, 401, 'Unauthorized');
    }

    if (req.method !== 'GET') {
        return errorResponse(res, 405, 'Method not allowed');
    }

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

        // Get license counts for each user
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
};
