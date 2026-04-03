const { validateLicense } = require('./lib/license');
const { checkRateLimit } = require('./lib/rate-limit');
const { supabase } = require('./lib/supabase');

module.exports = async function handler(req, res) {
    // Only POST allowed
    if (req.method !== 'POST') {
        return res.status(405).json({ valid: false, status: 'error', message: 'Method not allowed' });
    }

    try {
        const { license_key, mt_account, hardware_id, product_slug } = req.body;

        // Validate required fields
        if (!license_key || !mt_account || !hardware_id || !product_slug) {
            return res.status(400).json({
                valid: false,
                status: 'error',
                message: 'Missing required fields. Ensure license key is entered in EA settings.'
            });
        }

        // Rate limiting — max 20 validation attempts per hardware per 15 minutes
        const rateCheck = await checkRateLimit(hardware_id, 'validate', 20, 15);
        if (!rateCheck.allowed) {
            return res.status(429).json({
                valid: false,
                status: 'rate_limited',
                message: 'Too many validation attempts. Please wait and try again.'
            });
        }

        // Validate the license
        const result = await validateLicense(license_key, mt_account, hardware_id, product_slug);

        // Log the validation attempt
        await supabase
            .from('validation_logs')
            .insert({
                license_key: license_key,
                license_id: result.license ? result.license.id : null,
                mt_account: mt_account,
                hardware_id: hardware_id,
                result: result.status,
                ip_address: req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown'
            });

        // Return result to EA
        return res.status(result.valid ? 200 : 403).json({
            valid: result.valid,
            status: result.status,
            message: result.message
        });

    } catch (error) {
        console.error('Validation error:', error);
        return res.status(500).json({
            valid: false,
            status: 'server_error',
            message: 'License server temporarily unavailable. Please try again later.'
        });
    }
};
