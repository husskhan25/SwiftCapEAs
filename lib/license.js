const crypto = require('crypto');
const { supabase } = require('./supabase');

/**
 * Generate a random license key with product prefix
 * Format: SC-MST-XXXX-XXXX-XXXX
 * Uses cryptographically secure random generation
 */
function generateLicenseKey(prefix) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // removed 0,O,1,I to avoid confusion
    const groups = [];

    for (let g = 0; g < 3; g++) {
        let group = '';
        for (let i = 0; i < 4; i++) {
            const randomIndex = crypto.randomInt(0, chars.length);
            group += chars[randomIndex];
        }
        groups.push(group);
    }

    return `${prefix}-${groups.join('-')}`;
}

/**
 * Create a license for a user and product
 * Returns the created license object
 */
async function createLicense(userId, productId, type, source, whopMembershipId, maxAccountsOverride, maxHardwareOverride) {
    // Get product prefix
    const { data: product, error: productError } = await supabase
        .from('products')
        .select('key_prefix')
        .eq('id', productId)
        .single();

    if (productError || !product) {
        throw new Error('Product not found');
    }

    // Generate unique key (retry if collision, extremely unlikely)
    let licenseKey;
    let attempts = 0;
    const maxAttempts = 5;

    while (attempts < maxAttempts) {
        licenseKey = generateLicenseKey(product.key_prefix);

        const { data: existing } = await supabase
            .from('licenses')
            .select('id')
            .eq('license_key', licenseKey)
            .single();

        if (!existing) break;
        attempts++;
    }

    if (attempts >= maxAttempts) {
        throw new Error('Failed to generate unique license key');
    }

    // Calculate expiry
    let expiresAt = null;
    if (type === 'monthly') {
        expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    } else if (type === 'quarterly') {
        expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    }
    // lifetime = null (never expires)

    const { data: license, error } = await supabase
        .from('licenses')
        .insert({
            license_key: licenseKey,
            user_id: userId,
            product_id: productId,
            type: type,
            status: 'active',
            max_accounts: maxAccountsOverride || null,
            max_hardware: maxHardwareOverride || null,
            source: source,
            whop_membership_id: whopMembershipId || null,
            expires_at: expiresAt
        })
        .select()
        .single();

    if (error) {
        throw new Error(`Failed to create license: ${error.message}`);
    }

    return license;
}

/**
 * Validate a license from EA request
 * Returns { valid, status, message, license }
 *
 * Limit enforcement:
 *   - NEW activations: blocked if at or over limit
 *   - EXISTING activations (revalidation): re-checked against current limits
 *     so that admin-lowered limits take effect on next periodic check.
 *     Oldest activations (by created_at) have priority; newest get kicked.
 */
async function validateLicense(licenseKey, mtAccount, hardwareId, productSlug) {
    // Find the license with product info
    const { data: license, error } = await supabase
        .from('licenses')
        .select(`
            *,
            product:products(*)
        `)
        .eq('license_key', licenseKey)
        .single();

    if (error || !license) {
        return { valid: false, status: 'invalid_key', message: 'Invalid license key. Please check your key and try again.' };
    }

    // Check product match
    if (license.product.slug !== productSlug) {
        return { valid: false, status: 'product_mismatch', message: `This license key is for ${license.product.name}, not this EA.` };
    }

    // Check if revoked
    if (license.status === 'revoked') {
        return { valid: false, status: 'revoked', message: 'This license has been revoked. Contact support at team@swiftcapeas.com' };
    }

    // Check if expired
    if (license.status === 'expired') {
        return { valid: false, status: 'expired', message: 'Your license has expired. Renew at https://whop.com/swiftcap-eas/' };
    }
    // Check expiry date for subscription licenses
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
        await supabase
            .from('licenses')
            .update({ status: 'expired' })
            .eq('id', license.id);

        return {
            valid: false,
            status: 'expired',
            message: 'Your license has expired. Renew at https://whop.com/swiftcap-eas/'
        };
    }

    // Get effective limits
    const maxAccounts = license.max_accounts || license.product.max_accounts;
    const maxHardware = license.max_hardware || license.product.max_hardware;

    // Get current activations
    const { data: activations } = await supabase
        .from('activations')
        .select('*')
        .eq('license_id', license.id)
        .eq('is_active', true);

    const currentActivations = activations || [];

    // Unique counts (used by both existing and new activation paths)
    const uniqueHardware = [...new Set(currentActivations.map(a => a.hardware_id))];
    const uniqueAccounts = [...new Set(currentActivations.map(a => a.mt_account_number))];

    // Check if this exact combination already exists (returning user / periodic revalidation)
    const existingActivation = currentActivations.find(
        a => a.mt_account_number === mtAccount && a.hardware_id === hardwareId
    );

    if (existingActivation) {
        // ── Re-enforce hardware limit on revalidation ──
        // If admin lowered the limit, newest devices get kicked
        if (uniqueHardware.length > maxHardware) {
            // Build ordered list of hardware IDs by earliest activation
            const sorted = [...currentActivations].sort(
                (a, b) => new Date(a.created_at) - new Date(b.created_at)
            );
            const hardwareByAge = [];
            const seenHw = new Set();
            for (const act of sorted) {
                if (!seenHw.has(act.hardware_id)) {
                    seenHw.add(act.hardware_id);
                    hardwareByAge.push(act.hardware_id);
                }
            }
            // If this HWID is beyond the allowed count, reject and deactivate
            if (hardwareByAge.indexOf(hardwareId) >= maxHardware) {
                await supabase
                    .from('activations')
                    .update({ is_active: false })
                    .eq('id', existingActivation.id);

                return {
                    valid: false,
                    status: 'hardware_limit',
                    message: `Hardware limit is ${maxHardware} device(s). This device is no longer authorized. Manage devices at swiftcapeas.com/dashboard`
                };
            }
        }

        // ── Re-enforce account limit on revalidation ──
        if (uniqueAccounts.length > maxAccounts) {
            const sorted = [...currentActivations].sort(
                (a, b) => new Date(a.created_at) - new Date(b.created_at)
            );
            const accountsByAge = [];
            const seenAcct = new Set();
            for (const act of sorted) {
                if (!seenAcct.has(act.mt_account_number)) {
                    seenAcct.add(act.mt_account_number);
                    accountsByAge.push(act.mt_account_number);
                }
            }
            if (accountsByAge.indexOf(mtAccount) >= maxAccounts) {
                await supabase
                    .from('activations')
                    .update({ is_active: false })
                    .eq('id', existingActivation.id);

                return {
                    valid: false,
                    status: 'account_limit',
                    message: `Account limit is ${maxAccounts} account(s). This account is no longer authorized. Manage accounts at swiftcapeas.com/dashboard`
                };
            }
        }

        // Within limits — update last_seen and allow
        await supabase
            .from('activations')
            .update({ last_seen_at: new Date().toISOString() })
            .eq('id', existingActivation.id);

        return { valid: true, status: 'valid', message: 'License valid.', license: license };
    }

    // ── NEW activation — enforce limits strictly ──

    // Check hardware limit
    if (!uniqueHardware.includes(hardwareId) && uniqueHardware.length >= maxHardware) {
        return {
            valid: false,
            status: 'hardware_limit',
            message: `Hardware limit reached (${maxHardware} device(s)). Remove a device at swiftcapeas.com/dashboard`
        };
    }

    // Check account limit
    if (!uniqueAccounts.includes(mtAccount) && uniqueAccounts.length >= maxAccounts) {
        return {
            valid: false,
            status: 'account_limit',
            message: `Account limit reached (${maxAccounts} account(s)). Remove an account at swiftcapeas.com/dashboard`
        };
    }

    // All checks passed — create activation
    await supabase
        .from('activations')
        .insert({
            license_id: license.id,
            mt_account_number: mtAccount,
            hardware_id: hardwareId,
            is_active: true
        });

    return { valid: true, status: 'valid', message: 'License valid. Activation registered.', license: license };
}

module.exports = { generateLicenseKey, createLicense, validateLicense };
