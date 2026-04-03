const { supabase } = require('../lib/supabase');
const { requireCustomer, handleCors, errorResponse } = require('../lib/middleware');
const { hashPassword, verifyPassword } = require('../lib/auth');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const user = requireCustomer(req);
    if (!user) {
        return errorResponse(res, 401, 'Please log in');
    }

    // GET — get profile info
    if (req.method === 'GET') {
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

    // PUT — update profile (name, password change)
    if (req.method === 'PUT') {
        try {
            const { name, current_password, new_password } = req.body;
            const updates = {};

            if (name !== undefined) {
                updates.name = name.trim();
            }

            // Password change
            if (new_password) {
                if (!current_password) {
                    return errorResponse(res, 400, 'Current password is required to set a new password');
                }

                if (new_password.length < 8) {
                    return errorResponse(res, 400, 'New password must be at least 8 characters');
                }

                // Verify current password
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

    return errorResponse(res, 405, 'Method not allowed');
};
