const { supabase } = require('./supabase');

/**
 * Rate limiter using database
 * Prevents brute force attacks on license validation and login
 */
async function checkRateLimit(identifier, action, maxAttempts, windowMinutes) {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

    // Clean old entries
    await supabase
        .from('rate_limits')
        .delete()
        .lt('window_start', windowStart);

    // Count recent attempts
    const { data, error } = await supabase
        .from('rate_limits')
        .select('attempts')
        .eq('identifier', identifier)
        .eq('action', action)
        .gte('window_start', windowStart);

    const totalAttempts = (data || []).reduce((sum, row) => sum + row.attempts, 0);

    if (totalAttempts >= maxAttempts) {
        return { allowed: false, remaining: 0, retryAfterMinutes: windowMinutes };
    }

    // Record this attempt
    await supabase
        .from('rate_limits')
        .insert({
            identifier: identifier,
            action: action,
            attempts: 1,
            window_start: new Date().toISOString()
        });

    return { allowed: true, remaining: maxAttempts - totalAttempts - 1 };
}

module.exports = { checkRateLimit };
