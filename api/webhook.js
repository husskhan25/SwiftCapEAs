const crypto = require('crypto');
const { supabase } = require('../lib/supabase');
const { createLicense } = require('../lib/license');
const { generateSecureToken } = require('../lib/auth');
const { sendWelcomeEmail } = require('../lib/email');

const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET;

// Map your Whop product IDs to your database product slugs
const WHOP_PRODUCT_MAP = {
    'prod_VWiZe7trObFc9': 'master',
    'prod_DLdSA8WvKKNwM': 'breakout',
    'prod_SmKxaqg7bUe2H': 'grid',
    'prod_WQB8OIaKN8seQ': 'trinity',
    'prod_a7cAN7joMLn3h': 'bundle',
};

// Map Whop plan IDs to license types
const WHOP_PLAN_MAP = {
    // Master EA plans
    'plan_4rSGn5IJb6Wks': 'monthly',
    'plan_uczD64GL2WQA6': 'quarterly',
    'plan_nItuKRzbeS574': 'lifetime',
    // Breakout EA plans
    'plan_ZS1JTssBfXT1w': 'monthly',
    'plan_km3xjwdoD2Qfr': 'quarterly',
    'plan_2fAohMtqssxDq': 'lifetime',
    // Grid EA plans
    'plan_ZvsnGjMVsoNKQ': 'monthly',
    'plan_6zQC9pdMl5uu2': 'quarterly',
    'plan_AzXkwyvRmeKzR': 'lifetime',
    // Trinity EA plans
    'plan_5LOQE83J2jTRo': 'monthly',
    'plan_07N1SkAvDCu0K': 'quarterly',
    'plan_z4V6hGfCjHEAr': 'lifetime',
    // Bundle plans
    'plan_tIhsmtsVaUN04': 'monthly',
    'plan_9KCAFzeJkQnB1': 'quarterly',
    'plan_xZkY4s2U7DSUz': 'lifetime',
};

/**
 * Verify Whop webhook signature using Standard Webhooks spec
 * Signing payload = "{webhook-id}.{webhook-timestamp}.{body}"
 * Key = decoded from secret (strip prefix, decode hex or base64)
 * Signature header = "v1,{base64_hmac_sha256}"
 */
function verifyWhopSignature(body, headers) {
    if (!WHOP_WEBHOOK_SECRET) return false;

    try {
        const msgId = headers['webhook-id'] || '';
        const msgTimestamp = headers['webhook-timestamp'] || '';
        const msgSignature = headers['webhook-signature'] || '';

        if (!msgId || !msgTimestamp || !msgSignature) return false;

        // Build the signing payload per Standard Webhooks spec
        const signPayload = `${msgId}.${msgTimestamp}.${body}`;

        // Decode the secret key based on prefix
        let secretBytes;
        if (WHOP_WEBHOOK_SECRET.startsWith('whsec_')) {
            secretBytes = Buffer.from(WHOP_WEBHOOK_SECRET.substring(6), 'base64');
        } else if (WHOP_WEBHOOK_SECRET.startsWith('ws_')) {
            const hexPart = WHOP_WEBHOOK_SECRET.substring(3);
            secretBytes = Buffer.from(hexPart, 'hex');
        } else {
            secretBytes = Buffer.from(WHOP_WEBHOOK_SECRET, 'base64');
        }

        // Compute HMAC-SHA256
        const hmac = crypto.createHmac('sha256', secretBytes);
        hmac.update(signPayload);
        const computed = hmac.digest('base64');

        // The signature header can contain multiple signatures separated by spaces
        const signatures = msgSignature.split(' ');
        for (const sig of signatures) {
            const parts = sig.split(',');
            if (parts.length === 2 && parts[0] === 'v1') {
                if (computed === parts[1]) return true;
            }
        }

        return false;
    } catch (e) {
        console.error('Signature verification error:', e);
        return false;
    }
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const rawBody = JSON.stringify(req.body);
        const event = req.body;
        const eventType = event.type || event.event || 'unknown';

        // Log the raw event first so we can always debug
        await supabase.from('webhook_logs').insert({
            event_type: eventType,
            whop_membership_id: event.data?.id || event.data?.membership_id || null,
            payload: event,
            processed: false,
            error: null
        });

        // Verify webhook signature using Standard Webhooks spec
        if (WHOP_WEBHOOK_SECRET && !verifyWhopSignature(rawBody, req.headers)) {
            await supabase.from('webhook_logs').insert({
                event_type: 'signature_failed',
                payload: {
                    headers: {
                        'webhook-id': req.headers['webhook-id'] || null,
                        'webhook-timestamp': req.headers['webhook-timestamp'] || null,
                        'webhook-signature': req.headers['webhook-signature'] || null,
                    },
                    body_preview: rawBody.substring(0, 500)
                },
                processed: false,
                error: 'Invalid webhook signature'
            });
            return res.status(401).json({ error: 'Invalid signature' });
        }

        // Handle different event types
        // Whop V1: membership.activated / membership.deactivated
        if (eventType === 'membership.activated' ||
            eventType === 'payment.succeeded' ||
            eventType === 'membership.went_valid') {
            await handleNewPurchase(event);
        } else if (eventType === 'membership.deactivated' ||
                   eventType === 'membership.went_invalid' ||
                   eventType === 'membership.cancelled') {
            await handleCancellation(event);
        }

        // Mark as processed
        await supabase
            .from('webhook_logs')
            .update({ processed: true })
            .eq('whop_membership_id', event.data?.id || event.data?.membership_id);

        return res.status(200).json({ received: true });

    } catch (error) {
        console.error('Webhook error:', error);

        try {
            await supabase.from('webhook_logs').insert({
                event_type: 'processing_error',
                payload: req.body,
                processed: false,
                error: error.message
            });
        } catch (logErr) {
            console.error('Failed to log webhook error:', logErr);
        }

        return res.status(500).json({ error: 'Internal server error' });
    }
};

async function handleNewPurchase(event) {
    const data = event.data || {};

    // Whop V1 payload structure
    const customerEmail = data.user?.email || data.email;
    const customerName = data.user?.name || data.name || null;
    const whopUserId = data.user?.id || data.user_id;
    const whopProductId = data.product?.id || data.product_id;
    const whopMembershipId = data.id || data.membership_id;

    if (!customerEmail) {
        throw new Error('No customer email in webhook payload. Data keys: ' + Object.keys(data).join(', '));
    }

    // Check for duplicate — avoid creating license twice for same membership
    if (whopMembershipId) {
        const { data: existingLicense } = await supabase
            .from('licenses')
            .select('id')
            .eq('whop_membership_id', whopMembershipId)
            .single();

        if (existingLicense) {
            console.log(`License already exists for membership ${whopMembershipId}, skipping`);
            return;
        }
    }

    // Find or create user
    let { data: user } = await supabase
        .from('users')
        .select('*')
        .eq('email', customerEmail.toLowerCase())
        .single();

    let isNewUser = false;

    if (!user) {
        isNewUser = true;
        const { data: newUser, error } = await supabase
            .from('users')
            .insert({
                email: customerEmail.toLowerCase(),
                name: customerName,
                whop_user_id: whopUserId
            })
            .select()
            .single();

        if (error) throw new Error(`Failed to create user: ${error.message}`);
        user = newUser;
    } else {
        if (!user.whop_user_id && whopUserId) {
            await supabase
                .from('users')
                .update({ whop_user_id: whopUserId })
                .eq('id', user.id);
        }
    }

    // Determine which product(s) were purchased
    const productSlug = WHOP_PRODUCT_MAP[whopProductId];
    const isBundle = productSlug === 'bundle';

    let licensesToCreate = [];

    if (isBundle) {
        const { data: products } = await supabase
            .from('products')
            .select('*')
            .in('slug', ['master', 'breakout', 'grid', 'trinity']);

        licensesToCreate = products;
    } else if (productSlug) {
        const { data: product } = await supabase
            .from('products')
            .select('*')
            .eq('slug', productSlug)
            .single();

        if (product) licensesToCreate = [product];
    }

    if (licensesToCreate.length === 0) {
        throw new Error(`Unknown product ID: ${whopProductId}, slug: ${productSlug}`);
    }

    // Determine license type from Whop plan ID
    const whopPlanId = data.plan?.id || data.plan_id;
    let licenseType = WHOP_PLAN_MAP[whopPlanId];
    if (!licenseType) {
        console.warn(`Unknown plan ID: ${whopPlanId}, defaulting to lifetime`);
        licenseType = 'lifetime';
    }

    // Create licenses
    const createdLicenses = [];
    for (const product of licensesToCreate) {
        const license = await createLicense(
            user.id,
            product.id,
            licenseType,
            'whop',
            whopMembershipId,
            null,
            null
        );
        createdLicenses.push({
            licenseKey: license.license_key,
            productName: product.name
        });
    }

    // Generate password setup token
    const passwordToken = generateSecureToken();
    const tokenExpiry = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();

    await supabase
        .from('users')
        .update({
            password_reset_token: passwordToken,
            password_reset_expires: tokenExpiry
        })
        .eq('id', user.id);

    // Send welcome email
    await sendWelcomeEmail(
        user.email,
        user.name,
        createdLicenses,
        passwordToken
    );
}

async function handleCancellation(event) {
    const data = event.data || {};
    const whopMembershipId = data.id || data.membership_id;

    if (!whopMembershipId) return;

    const { data: licenses } = await supabase
        .from('licenses')
        .select('*')
        .eq('whop_membership_id', whopMembershipId)
        .in('status', ['active']);

    if (!licenses || licenses.length === 0) return;

    for (const license of licenses) {
        await supabase
            .from('licenses')
            .update({ status: 'expired' })
            .eq('id', license.id);
    }
}
