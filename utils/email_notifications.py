import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USERNAME', '')
SMTP_PASS = os.getenv('SMTP_PASSWORD', '')
FROM_EMAIL = os.getenv('SMTP_FROM', SMTP_USER)

def send_email(to_email, subject, html_body):
    if not SMTP_USER or not SMTP_PASS:
        logger.warning('SMTP not configured, skipping email')
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        return True
    except Exception as exc:
        logger.error('Email send failed: %s', exc)
        return False

def notify_scan_complete(user_email, project_name, findings_count, critical_count, project_id):
    subject = '[REDCON] Scan complete: ' + project_name
    html = (
        '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0d1117;color:#f0f3f6;border-radius:12px;overflow:hidden;">'
        '<div style="background:#c9353f;padding:20px 32px;">'
        '<h1 style="margin:0;font-size:1.4rem;color:#fff;">REDCON OFFENCE</h1>'
        '<p style="margin:4px 0 0;color:rgba(255,255,255,.7);font-size:.85rem;">Security Scanner</p>'
        '</div>'
        '<div style="padding:32px;">'
        '<h2 style="color:#f0f3f6;margin-top:0;">Scan Complete</h2>'
        '<p style="color:#9198a1;">Your security scan for <strong style="color:#f0f3f6;">' + project_name + '</strong> has finished.</p>'
        '<div style="background:#161b22;border:1px solid #2d333b;border-radius:10px;padding:20px;margin:20px 0;">'
        '<div style="display:flex;gap:24px;">'
        '<div><div style="font-size:2rem;font-weight:700;color:#f0f3f6;">' + str(findings_count) + '</div><div style="color:#9198a1;font-size:.85rem;">Total Findings</div></div>'
        '<div><div style="font-size:2rem;font-weight:700;color:#c9353f;">' + str(critical_count) + '</div><div style="color:#9198a1;font-size:.85rem;">Critical</div></div>'
        '</div></div>'
        '<a href="https://scanner.redconoffence.com/projects/' + str(project_id) + '" style="display:inline-block;background:#c9353f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;">View Results</a>'
        '</div></div>'
    )
    return send_email(user_email, subject, html)

def notify_critical_finding(user_email, project_name, finding_title, finding_id):
    subject = '[REDCON] Critical finding: ' + finding_title[:50]
    html = (
        '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0d1117;color:#f0f3f6;border-radius:12px;overflow:hidden;">'
        '<div style="background:#c9353f;padding:20px 32px;">'
        '<h1 style="margin:0;font-size:1.4rem;color:#fff;">REDCON OFFENCE</h1>'
        '</div>'
        '<div style="padding:32px;">'
        '<h2 style="color:#c9353f;margin-top:0;">Critical Finding Detected</h2>'
        '<p style="color:#9198a1;">A critical severity finding was discovered in <strong style="color:#f0f3f6;">' + project_name + '</strong>.</p>'
        '<div style="background:#161b22;border:1px solid rgba(201,53,63,.3);border-radius:10px;padding:16px;margin:20px 0;">'
        '<div style="font-weight:600;color:#f0f3f6;">' + finding_title + '</div>'
        '</div>'
        '<a href="https://scanner.redconoffence.com/findings/' + str(finding_id) + '" style="display:inline-block;background:#c9353f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;">View Finding</a>'
        '</div></div>'
    )
    return send_email(user_email, subject, html)


def send_invite_email(to_email, username, invited_by, invite_url):
    subject = 'You have been invited to REDCON OFFENCE Security Scanner'
    html = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0c10;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0c10;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#1a0608 0%,#2d0a0d 50%,#1a0608 100%);border-radius:16px 16px 0 0;padding:40px 48px 36px;border-bottom:3px solid #c9353f;text-align:center;">
            <div style="display:inline-block;background:rgba(201,53,63,0.15);border:1px solid rgba(201,53,63,0.4);border-radius:50%;width:64px;height:64px;line-height:64px;text-align:center;margin-bottom:20px;font-size:28px;">&#x1F6E1;</div>
            <div style="font-size:22px;font-weight:900;letter-spacing:0.2em;color:#c9353f;text-transform:uppercase;margin-bottom:4px;">REDCON OFFENCE</div>
            <div style="font-size:11px;letter-spacing:0.3em;color:#636c76;text-transform:uppercase;">Security Scanner Platform</div>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="background:#0d1117;padding:48px;border:1px solid #1e2530;border-top:none;border-radius:0 0 16px 16px;">

            <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:#f0f3f6;">You've been invited</h1>
            <p style="margin:0 0 32px;color:#636c76;font-size:14px;line-height:1.6;">
              <strong style="color:#9198a1;">""" + invited_by + """</strong> has granted you access to the REDCON OFFENCE Security Scanner — a professional security research and vulnerability management platform.
            </p>

            <!-- Account card -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#161b22;border:1px solid #2d333b;border-left:3px solid #c9353f;border-radius:10px;margin-bottom:32px;">
              <tr>
                <td style="padding:20px 24px;">
                  <div style="font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#636c76;margin-bottom:8px;">Your account</div>
                  <div style="font-size:20px;font-weight:700;color:#f0f3f6;margin-bottom:4px;">""" + username + """</div>
                  <div style="font-size:13px;color:#9198a1;">""" + to_email + """</div>
                </td>
                <td style="padding:20px 24px;text-align:right;vertical-align:middle;">
                  <span style="background:rgba(201,53,63,0.12);border:1px solid rgba(201,53,63,0.3);color:#c9353f;font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;padding:6px 14px;border-radius:20px;">Pending Activation</span>
                </td>
              </tr>
            </table>

            <!-- Expiry notice -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.2);border-radius:8px;margin-bottom:32px;">
              <tr>
                <td style="padding:14px 18px;font-size:13px;color:#d97706;">
                  &#x23F0;&nbsp; This invitation expires in <strong>24 hours</strong>. After that, a new invite will need to be sent.
                </td>
              </tr>
            </table>

            <!-- CTA -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center">
                  <a href="""" + invite_url + """" style="display:inline-block;background:linear-gradient(135deg,#c9353f,#e05561);color:#fff;text-decoration:none;font-size:15px;font-weight:700;padding:16px 48px;border-radius:10px;letter-spacing:0.04em;box-shadow:0 4px 24px rgba(201,53,63,0.4);">
                    Activate My Account &rarr;
                  </a>
                </td>
              </tr>
            </table>

            <!-- Divider -->
            <hr style="border:none;border-top:1px solid #1e2530;margin:36px 0;">

            <!-- Footer note -->
            <p style="margin:0;font-size:12px;color:#8b949e;line-height:1.6;text-align:center;">
              If you weren't expecting this invitation, you can safely ignore this email.<br>
              This message was sent by REDCON OFFENCE Security Scanner.
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:24px;text-align:center;">
            <div style="font-size:12px;font-weight:700;letter-spacing:0.2em;color:#636c76;text-transform:uppercase;margin-bottom:4px;">REDCON OFFENCE</div>
            <div style="font-size:11px;color:#636c76;letter-spacing:0.1em;">UNMATCHED PERCEPTION. UNBROKEN WILL.</div>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""
    return send_email(to_email, subject, html)

def send_password_reset_email(to_email, reset_url, username):
    subject = '[REDCON] Password Reset Request'
    html = (
        '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0d1117;color:#f0f3f6;border-radius:12px;overflow:hidden;">'
        '<div style="background:#c9353f;padding:20px 32px;">'
        '<h1 style="margin:0;font-size:1.4rem;color:#fff;">REDCON OFFENCE</h1>'
        '<p style="margin:4px 0 0;color:rgba(255,255,255,.7);font-size:.85rem;">Security Scanner</p>'
        '</div>'
        '<div style="padding:32px;">'
        '<h2 style="color:#f0f3f6;margin-top:0;">Password Reset</h2>'
        '<p style="color:#9198a1;">Hi <strong style="color:#f0f3f6;">' + username + '</strong>, we received a request to reset your password.</p>'
        '<p style="color:#9198a1;">Click the button below to set a new password. This link expires in <strong style="color:#f0f3f6;">1 hour</strong>.</p>'
        '<a href="' + reset_url + '" style="display:inline-block;background:#c9353f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;margin:16px 0;">Reset Password</a>'
        '<p style="color:#636c76;font-size:.8rem;margin-top:24px;">If you did not request this, ignore this email. Your password will not change.</p>'
        '<p style="color:#636c76;font-size:.75rem;word-break:break-all;">Link: ' + reset_url + '</p>'
        '</div></div>'
    )
    return send_email(to_email, subject, html)
