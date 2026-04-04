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
 * Verify Whop webhook signature
 */
function verifyWhopSignature(payload, signature) {
    if (!WHOP_WEBHOOK_SECRET) return false;
    const hmac = crypto.createHmac('sha256', WHOP_WEBHOOK_SECRET);
    hmac.update(payload);
    const expected = hmac.digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        // Verify webhook signature
        const signature = req.headers['whop-signature'] || req.headers['x-whop-signature'] || '';
        const rawBody = JSON.stringify(req.body);

        if (WHOP_WEBHOOK_SECRET && !verifyWhopSignature(rawBody, signature)) {
            // Log the failed attempt
            await supabase.from('webhook_logs').insert({
                event_type: 'signature_failed',
                payload: req.body,
                processed: false,
                error: 'Invalid webhook signature'
            });
            return res.status(401).json({ error: 'Invalid signature' });
        }

        const event = req.body;
        const eventType = event.type || event.event || 'unknown';

        // Log the webhook
        await supabase.from('webhook_logs').insert({
            event_type: eventType,
            whop_membership_id: event.data?.membership_id || event.data?.id || null,
            payload: event,
            processed: false
        });

        // Handle different event types
        if (eventType === 'payment.succeeded' || eventType === 'membership.went_valid') {
            await handleNewPurchase(event);
        } else if (eventType === 'membership.went_invalid' || eventType === 'membership.cancelled') {
            await handleCancellation(event);
        }

        // Mark as processed
        await supabase
            .from('webhook_logs')
            .update({ processed: true })
            .eq('whop_membership_id', event.data?.membership_id || event.data?.id);

        return res.status(200).json({ received: true });

    } catch (error) {
        console.error('Webhook error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

async function handleNewPurchase(event) {
    const data = event.data || {};
    const customerEmail = data.email || data.user?.email;
    const customerName = data.name || data.user?.name || null;
    const whopUserId = data.user_id || data.user?.id;
    const whopProductId = data.product_id || data.product?.id;
    const whopMembershipId = data.membership_id || data.id;

    if (!customerEmail) {
        throw new Error('No customer email in webhook payload');
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
        // Update whop_user_id if not set
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
        // Get all 4 products
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
        throw new Error(`Unknown product: ${whopProductId}`);
    }

    // Determine license type from Whop plan ID
    const whopPlanId = data.plan?.id || data.plan_id;
    let licenseType = WHOP_PLAN_MAP[whopPlanId] || 'lifetime'; // default to lifetime if plan not found

    // Create licenses
    const createdLicenses = [];
    for (const product of licensesToCreate) {
        const license = await createLicense(
            user.id,
            product.id,
            licenseType,
            'whop',
            whopMembershipId,
            null, // use product default max_accounts
            null  // use product default max_hardware
        );
        createdLicenses.push({
            licenseKey: license.license_key,
            productName: product.name
        });
    }

    // Generate password setup token (or new license email for existing users)
    const passwordToken = generateSecureToken();
    const tokenExpiry = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(); // 48 hours

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
    const whopMembershipId = data.membership_id || data.id;

    if (!whopMembershipId) return;

    // Find licenses with this membership ID
    const { data: licenses } = await supabase
        .from('licenses')
        .select('*')
        .eq('whop_membership_id', whopMembershipId)
        .in('status', ['active', 'expired_managing']);

    if (!licenses || licenses.length === 0) return;

    // Mark as expired_managing (stop new trades, manage existing)
    for (const license of licenses) {
        await supabase
            .from('licenses')
            .update({ status: 'expired_managing' })
            .eq('id', license.id);
    }
}
