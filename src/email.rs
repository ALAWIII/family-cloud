use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
};
use std::sync::OnceLock;
use tracing::{debug, error, instrument};
use uuid::Uuid;

use crate::{EmailConfig, EmailError};

static MAIL_CLIENT: OnceLock<AsyncSmtpTransport<Tokio1Executor>> = OnceLock::new();

#[derive(Debug, Default)]
pub struct EmailSender {
    from_sender: String,
    email_body: String,
    subject: String,
    email_recipient: String,
    msg_id: Option<String>,
}
impl EmailSender {
    pub fn from_sender(mut self, from_sender: String) -> Self {
        self.from_sender = from_sender;
        self
    }
    pub fn email_body(mut self, body: String) -> Self {
        self.email_body = body;
        self
    }
    pub fn subject(mut self, subject: String) -> Self {
        self.subject = subject;
        self
    }
    pub fn email_recipient(mut self, email_recipient: String) -> Self {
        self.email_recipient = email_recipient;
        self
    }

    pub fn msg_id(mut self, msg_id: String) -> Self {
        self.msg_id = Some(msg_id);
        self
    }
    #[instrument(skip_all, fields(
        email_sender=self.from_sender,
        user_email=self.email_recipient,
        subject=self.subject,
    ))]
    pub async fn send_email(
        self,
        client: AsyncSmtpTransport<Tokio1Executor>,
    ) -> Result<(), EmailError> {
        debug!("sending email message");
        let msg = Message::builder()
            .message_id(self.msg_id)
            .from(
                self.from_sender
                    .parse()
                    .inspect_err(|e| error!("failed to parse email sender: {}", e))
                    .map_err(EmailError::InvalidAddress)?,
            )
            .to(self
                .email_recipient
                .parse()
                .inspect_err(|e| error!("failed to parse user recipient email: {}", e))
                .map_err(EmailError::InvalidAddress)?)
            .subject(self.subject)
            .header(ContentType::TEXT_HTML)
            .body(self.email_body.to_string())
            .inspect_err(|e| error!("failed to build the email message: {}", e))
            .map_err(EmailError::MessageBuilder)?;

        client
            .send(msg)
            .await
            .map_err(EmailError::Transport)
            .inspect_err(|e| error!("failed to send the email message: {}", e))?;
        debug!("configuring the mail client successfully");
        Ok(())
    }
}

/// used to establish connection to the Email server and register the app as a viable client that will use the SMTP server to send emails.
#[instrument(skip_all,fields(name = email_cfg.username,
    init_id=%Uuid::new_v4(),
    host=email_cfg.host,
    port=email_cfg.port,
    protocol=email_cfg.protocol,
    email_sender=email_cfg.from_sender,
    tls_param=email_cfg.tls_param
))]
pub fn init_mail_client(email_cfg: &EmailConfig) -> Result<(), EmailError> {
    debug!("Initalizing the mail client.");
    let mail = AsyncSmtpTransport::<Tokio1Executor>::from_url(&email_cfg.url())
        .inspect_err(|e| error!("failed to initalize mail client: {}", e))
        .map_err(EmailError::Transport)?
        .build();
    MAIL_CLIENT
        .set(mail)
        .map_err(|_| EmailError::ClientAlreadyInitialized)
        .inspect_err(|e| error!("failed to set the mail client again: {}", e))
}
pub fn get_mail_client() -> Result<AsyncSmtpTransport<Tokio1Executor>, EmailError> {
    debug!("getting a mail client reference");
    Ok(MAIL_CLIENT
        .get()
        .ok_or(EmailError::ClientNotInitialized)
        .inspect_err(|e| error!("failed to get a clone of the mail client: {}", e))?
        .clone())
}

pub fn verification_body(username: &str, url_token: &str, minutes: u32, app: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ display: inline-block; padding: 12px 24px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <h2>Welcome to {app}!</h2>
    <p>Hi {username},</p>
    <p>Thank you for signing up! To get started, please verify your email address by clicking the button below:</p>
    <p><a id="verify-button" href="{url_token}" class="button">Verify Email Address</a></p>
    <p>Or copy and paste this link into your browser:<br>
    <code>{url_token}</code></p>
    <p><strong>This link expires in {minutes} minutes.</strong></p>
    <p>If you didn't create this account, you can safely ignore this email.</p>
    <div class="footer">
        <p>Best regards,<br>The {app} Team</p>
    </div>
</body>
</html>"#,
        username = username,
        url_token = url_token,
        minutes = minutes,
        app = app,
    )
}

pub fn password_reset_body(username: &str, reset_url: &str, minutes: u32, app: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ display: inline-block; padding: 12px 24px; background-color: #dc3545; color: #ffffff; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .warning {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <h2>Password Reset Request</h2>
    <p>Hi {username},</p>
    <p>We received a request to reset your password for your {app} account. Click the button below to create a new password:</p>
    <p><a id="verify-button" href="{reset_url}" class="button">Reset Password</a></p>
    <p>Or copy and paste this link into your browser:<br>
    <code>{reset_url}</code></p>
    <p><strong>This link expires in {minutes} minutes.</strong></p>
    <div class="warning">
        <strong>⚠️ Important:</strong> If you didn't request a password reset, please ignore this email. Your password will remain unchanged and your account is secure.
    </div>
    <div class="footer">
        <p>Best regards,<br>The {app} Team</p>
    </div>
</body>
</html>"#,
        username = username,
        reset_url = reset_url,
        minutes = minutes,
        app = app,
    )
}

pub fn email_change_body(username: &str, confirm_url: &str, minutes: u32, app: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ display: inline-block; padding: 12px 24px; background-color: #28a745; color: #ffffff; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .alert {{ background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 12px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <h2>Email Address Change Request</h2>
    <p>Hi {username},</p>
    <p>You requested to change your {app} account email address to this address. To confirm this change, please click the button below:</p>
    <p><a id="verify-button" href="{confirm_url}" class="button">Confirm Email Change</a></p>
    <p>Or copy and paste this link into your browser:<br>
    <code>{confirm_url}</code></p>
    <p><strong>This link expires in {minutes} minutes.</strong></p>
    <div class="alert">
        <strong>🚨 Security Alert:</strong> If you didn't request this email change, someone may be trying to access your account. Please contact our support team immediately and consider changing your password.
    </div>
    <div class="footer">
        <p>Best regards,<br>The {app} Team</p>
    </div>
</body>
</html>"#,
        username = username,
        confirm_url = confirm_url,
        minutes = minutes,
        app = app,
    )
}

pub fn email_cancel_body(username: &str, cancel_url: &str, minutes: u32, app: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{ display: inline-block; padding: 12px 24px; background-color: #dc3545; color: #ffffff; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .alert {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <h2>Email Change Request Detected</h2>
    <p>Hi {username},</p>
    <p>A request was made to change your {app} account email address. If this was you, no action is needed—simply verify the change using the link sent to your new email address.</p>
    <div class="alert">
        <strong>⚠️ Didn't request this change?</strong><br>
        If you did not initiate this email change, your account may be at risk. Click the button below to cancel this request immediately:
    </div>
    <p><a id="verify-button" href="{cancel_url}" class="button">Cancel Email Change</a></p>
    <p>Or copy and paste this link into your browser:<br>
    <code>{cancel_url}</code></p>
    <p><strong>This link expires in {minutes} minutes.</strong> After that, the change request will be automatically cancelled if not verified.</p>
    <p>If you cancelled this request or it expires, we recommend changing your password as a security precaution.</p>
    <div class="footer">
        <p>Best regards,<br>The {app} Team</p>
        <p style="color: #999;">This is an automated security notification. Please do not reply to this email.</p>
    </div>
</body>
</html>"#,
        username = username,
        cancel_url = cancel_url,
        minutes = minutes,
        app = app,
    )
}
