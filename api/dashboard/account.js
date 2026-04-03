const { supabase } = require('../../lib/supabase');
const { requireCustomer, handleCors, errorResponse } = require('../../lib/middleware');
const { hashPassword, verifyPassword } = require('../../lib/auth');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const user = requireCustomer(req);
    if (!user) {
        return errorResponse(res, 401, 'Please log in');
    }

    const { action } = req.method === 'GET' ? req.query : req.body;

    // GET requests
    if (req.method === 'GET') {
        if (action === 'profile') {
            return getProfile(req, res, user);
        }
        return errorResponse(res, 400, 'Invalid action');
    }

    // POST requests
    if (req.method === 'POST') {
        if (action === 'update-profile') {
            return updateProfile(req, res, user);
        } else if (action === 'deactivate') {
            return deactivate(req, res, user);
        }
        return errorResponse(res, 400, 'Invalid action');
    }

    return errorResponse(res, 405, 'Method not allowed');
};

async function getProfile(req, res, user) {
    try {
        const { data: profile, error } = await supabase
            .from('users')
            .select('id, email, name, created_at')
            .eq('id', user.userId)
            .single();

        if (error || !profile) {
            return errorResponse(res, 404, 'Profile not found');
        }

        return res.status(200).json({ success: true, profile });
    } catch (error) {
        console.error('Profile fetch error:', error);
        return errorResponse(res, 500, 'Failed to load profile');
    }
}

async function updateProfile(req, res, user) {
    try {
        const { name, current_password, new_password } = req.body;
        const updates = {};

        if (name !== undefined) {
            updates.name = name.trim();
        }

        if (new_password) {
            if (!current_password) {
                return errorResponse(res, 400, 'Current password is required to set a new password');
            }

            if (new_password.length < 8) {
                return errorResponse(res, 400, 'New password must be at least 8 characters');
            }

            const { data: userData } = await supabase
                .from('users')
                .select('password_hash')
                .eq('id', user.userId)
                .single();

            const validPassword = await verifyPassword(current_password, userData.password_hash);
            if (!validPassword) {
                return errorResponse(res, 401, 'Current password is incorrect');
            }

            updates.password_hash = await hashPassword(new_password);
        }

        if (Object.keys(updates).length === 0) {
            return errorResponse(res, 400, 'No changes provided');
        }

        await supabase
            .from('users')
            .update(updates)
            .eq('id', user.userId);

        return res.status(200).json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        return errorResponse(res, 500, 'Failed to update profile');
    }
}

async function deactivate(req, res, user) {
    try {
        const { activation_id } = req.body;

        if (!activation_id) {
            return errorResponse(res, 400, 'Activation ID is required');
        }

        const { data: activation, error: fetchError } = await supabase
            .from('activations')
            .select(`*, license:licenses(user_id)`)
            .eq('id', activation_id)
            .single();

        if (fetchError || !activation) {
            return errorResponse(res, 404, 'Activation not found');
        }

        if (activation.license.user_id !== user.userId) {
            return errorResponse(res, 403, 'You do not have permission to remove this activation');
        }

        await supabase
            .from('activations')
            .update({ is_active: false })
            .eq('id', activation_id);

        return res.status(200).json({
            success: true,
            message: 'Activation removed successfully. The slot is now free.'
        });
    } catch (error) {
        console.error('Deactivation error:', error);
        return errorResponse(res, 500, 'Failed to remove activation. Please try again.');
    }
}
