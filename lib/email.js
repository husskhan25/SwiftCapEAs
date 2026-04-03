const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = 'SwiftCap EAs <team@swiftcapeas.com>';
const DASHBOARD_URL = 'https://swiftcapeas.com/dashboard';
const DISCORD_INVITE = 'https://discord.gg/gH3RJWRJKS';

/**
 * Send welcome email with license key(s) and password setup link
 */
async function sendWelcomeEmail(email, name, licenses, passwordSetupToken) {
    const passwordSetupUrl = `${DASHBOARD_URL}/set-password?token=${passwordSetupToken}`;

    // Build license keys section
    let licenseSection = '';
    if (licenses.length === 1) {
        licenseSection = `
            <div style="background: #0a1628; border: 1px solid #1a2a4a; border-radius: 8px; padding: 20px; margin: 20px 0;">
                <p style="color: #8a9bba; margin: 0 0 8px 0; font-size: 14px;">${licenses[0].productName}</p>
                <p style="color: #FFB91E; font-size: 24px; font-family: monospace; margin: 0; letter-spacing: 2px;">${licenses[0].licenseKey}</p>
            </div>
        `;
    } else {
        // Bundle — multiple keys
        licenseSection = '<div style="margin: 20px 0;">';
        for (const lic of licenses) {
            licenseSection += `
                <div style="background: #0a1628; border: 1px solid #1a2a4a; border-radius: 8px; padding: 16px; margin: 8px 0;">
                    <p style="color: #8a9bba; margin: 0 0 6px 0; font-size: 13px;">${lic.productName}</p>
                    <p style="color: #FFB91E; font-size: 18px; font-family: monospace; margin: 0; letter-spacing: 2px;">${lic.licenseKey}</p>
                </div>
            `;
        }
        licenseSection += '</div>';
    }

    const subject = licenses.length === 1
        ? `Your ${licenses[0].productName} License is Ready`
        : 'Your SwiftCap EAs Bundle — All License Keys Inside';

    const html = `
        <div style="background: #060e1c; color: #ffffff; font-family: Arial, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto;">
            <div style="text-align: center; margin-bottom: 30px;">
                <img src="https://swiftcapeas.com/logo.png" alt="SwiftCap EAs" style="height: 50px;" />
            </div>

            <h1 style="color: #FFB91E; font-size: 24px; margin-bottom: 10px;">Welcome to SwiftCap EAs!</h1>

            <p style="color: #c0c8d8; line-height: 1.6;">
                Hi ${name || 'Trader'},
            </p>

            <p style="color: #c0c8d8; line-height: 1.6;">
                Thank you for your purchase! Your license ${licenses.length > 1 ? 'keys are' : 'key is'} below:
            </p>

            ${licenseSection}

            <p style="color: #c0c8d8; line-height: 1.6;">
                To manage your license, activate trading accounts, and download set files, set up your dashboard password:
            </p>

            <div style="text-align: center; margin: 30px 0;">
                <a href="${passwordSetupUrl}" style="background: linear-gradient(135deg, #FFB91E, #e5a617); color: #060e1c; text-decoration: none; padding: 14px 40px; border-radius: 6px; font-weight: bold; font-size: 16px; display: inline-block;">
                    Set Your Password
                </a>
            </div>

            <p style="color: #8a9bba; font-size: 13px;">
                This link expires in 48 hours. If it expires, use "Forgot Password" on the dashboard login page.
            </p>

            <hr style="border: none; border-top: 1px solid #1a2a4a; margin: 30px 0;" />

            <p style="color: #c0c8d8; line-height: 1.6;">
                Need help? Send us an email at <a href="mailto:team@swiftcapeas.com" style="color: #FFB91E;">team@swiftcapeas.com</a>
                or join our <a href="${DISCORD_INVITE}" style="color: #FFB91E;">Discord community</a>.
            </p>

            <p style="color: #8a9bba; font-size: 12px; margin-top: 30px;">
                — SwiftCap EAs Team<br />
                <a href="https://swiftcapeas.com" style="color: #8a9bba;">swiftcapeas.com</a>
            </p>
        </div>
    `;

    try {
        await resend.emails.send({
            from: FROM_EMAIL,
            to: email,
            subject: subject,
            html: html
        });
        return { success: true };
    } catch (error) {
        console.error('Email send failed:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Send password reset email
 */
async function sendPasswordResetEmail(email, name, resetToken) {
    const resetUrl = `${DASHBOARD_URL}/reset-password?token=${resetToken}`;

    const html = `
        <div style="background: #060e1c; color: #ffffff; font-family: Arial, sans-serif; padding: 40px; max-width: 600px; margin: 0 auto;">
            <div style="text-align: center; margin-bottom: 30px;">
                <img src="https://swiftcapeas.com/logo.png" alt="SwiftCap EAs" style="height: 50px;" />
            </div>

            <h1 style="color: #FFB91E; font-size: 24px;">Password Reset</h1>

            <p style="color: #c0c8d8; line-height: 1.6;">
                Hi ${name || 'Trader'},
            </p>

            <p style="color: #c0c8d8; line-height: 1.6;">
                We received a request to reset your dashboard password. Click the button below to set a new password:
            </p>

            <div style="text-align: center; margin: 30px 0;">
                <a href="${resetUrl}" style="background: linear-gradient(135deg, #FFB91E, #e5a617); color: #060e1c; text-decoration: none; padding: 14px 40px; border-radius: 6px; font-weight: bold; font-size: 16px; display: inline-block;">
                    Reset Password
                </a>
            </div>

            <p style="color: #8a9bba; font-size: 13px;">
                This link expires in 1 hour. If you did not request this, ignore this email.
            </p>

            <hr style="border: none; border-top: 1px solid #1a2a4a; margin: 30px 0;" />

            <p style="color: #8a9bba; font-size: 12px;">
                — SwiftCap EAs Team<br />
                <a href="https://swiftcapeas.com" style="color: #8a9bba;">swiftcapeas.com</a>
            </p>
        </div>
    `;

    try {
        await resend.emails.send({
            from: FROM_EMAIL,
            to: email,
            subject: 'Reset Your SwiftCap Dashboard Password',
            html: html
        });
        return { success: true };
    } catch (error) {
        console.error('Password reset email failed:', error);
        return { success: false, error: error.message };
    }
}

module.exports = { sendWelcomeEmail, sendPasswordResetEmail };
