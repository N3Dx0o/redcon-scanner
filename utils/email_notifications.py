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
