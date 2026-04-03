const { supabase } = require('../lib/supabase');
const { requireCustomer, handleCors, errorResponse } = require('../lib/middleware');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    // DELETE — remove an activation (deactivate account or hardware)
    if (req.method === 'DELETE') {
        try {
            const user = requireCustomer(req);
            if (!user) {
                return errorResponse(res, 401, 'Please log in');
            }

            const { activation_id } = req.body;

            if (!activation_id) {
                return errorResponse(res, 400, 'Activation ID is required');
            }

            // Verify this activation belongs to the user's license
            const { data: activation, error: fetchError } = await supabase
                .from('activations')
                .select(`
                    *,
                    license:licenses(user_id)
                `)
                .eq('id', activation_id)
                .single();

            if (fetchError || !activation) {
                return errorResponse(res, 404, 'Activation not found');
            }

            if (activation.license.user_id !== user.userId) {
                return errorResponse(res, 403, 'You do not have permission to remove this activation');
            }

            // Deactivate (soft delete — mark as inactive)
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

    return errorResponse(res, 405, 'Method not allowed');
};
