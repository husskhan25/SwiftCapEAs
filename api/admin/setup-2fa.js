const { supabase } = require('../lib/supabase');
const { requireAdmin, handleCors, errorResponse } = require('../lib/middleware');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

module.exports = async function handler(req, res) {
    if (handleCors(req, res)) return;

    const admin = requireAdmin(req);
    if (!admin) {
        return errorResponse(res, 401, 'Unauthorized');
    }

    // GET — generate 2FA secret and QR code
    if (req.method === 'GET') {
        try {
            const secret = authenticator.generateSecret();
            const otpauth = authenticator.keyuri(admin.email, 'SwiftCap Admin', secret);
            const qrCodeDataUrl = await QRCode.toDataURL(otpauth);

            // Store secret temporarily (not enabled yet until verified)
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

    // POST — verify and enable 2FA
    if (req.method === 'POST') {
        try {
            const { totp_code } = req.body;

            if (!totp_code) {
                return errorResponse(res, 400, 'Authenticator code is required');
            }

            // Get the stored secret
            const { data: adminData } = await supabase
                .from('admin_users')
                .select('totp_secret')
                .eq('id', admin.userId)
                .single();

            if (!adminData || !adminData.totp_secret) {
                return errorResponse(res, 400, 'Please generate 2FA setup first');
            }

            // Verify the code
            const isValid = authenticator.check(totp_code, adminData.totp_secret);
            if (!isValid) {
                return errorResponse(res, 400, 'Invalid code. Please try again with a fresh code from your authenticator app.');
            }

            // Enable 2FA
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

    return errorResponse(res, 405, 'Method not allowed');
};
