use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use std::{
    env::{VarError, var as env_var},
    sync::OnceLock,
};

static MAIL_CLIENT: OnceLock<AsyncSmtpTransport<Tokio1Executor>> = OnceLock::new();

pub fn verification_body(username: &str, url_token: &str, minutes: u32, app: &str) -> String {
    format!(
        "Hi {username},\n\n\
         Thank you for signing up! Please verify your email by clicking:\n\n\
         {url_token}\n\n\
         This link expires in {minutes} minutes.\n\n\
         If you didn't create this account, please ignore this email.\n\n\
         Best regards,\n\
         {app}",
        username = username,
        url_token = url_token,
        minutes = minutes,
        app = app,
    )
}
pub fn password_reset_body(
    username: &str,
    reset_url: &str,
    minutes: u32,
    app: &str,
    on_sginup: bool,
) -> String {
    let situation = if on_sginup {
        "You are trying to signup with an email that is already attached to existing account.\n
        If you forget your password consider reseting the password and try login again.\n"
    } else {
        "We received a request to reset your password."
    };
    format!(
        "Hi {username},\n\n\
         {situation} Click the link below to reset password:\n\n\
         {reset_url}\n\n\
         This link expires in {minutes} minutes.\n\n\
         If you didn't request this, please ignore this email. Your password won't change.\n\n\
         Best regards,\n\
         {app}",
        username = username,
        reset_url = reset_url,
        minutes = minutes,
        app = app,
        situation = situation
    )
}
pub fn email_change_body(username: &str, confirm_url: &str, minutes: u32, app: &str) -> String {
    format!(
        "Hi {username},\n\n\
         You requested to change your email to this address.\n\n\
         Click to confirm:\n\n\
         {confirm_url}\n\n\
         This link expires in {minutes} minutes.\n\n\
         If you didn't request this change, contact support immediately.\n\n\
         Best regards,\n\
         {app}",
        username = username,
        confirm_url = confirm_url,
        minutes = minutes,
        app = app,
    )
}

#[derive(Deserialize)]
struct EmailConfig {
    smtp_server: String,              // smtp.gmail.com, smtp.office365.com, etc.
    smtp_port: u16,                   // 587 or 465
    smtp_username: String,            // admin email from the smtp_server or an api key
    smtp_password: SecretBox<String>, // SMTP password
}
impl EmailConfig {
    fn from_env() -> Result<Self, VarError> {
        let smtp_server = env_var("SMTP_SERVER")?;
        let smtp_port = env_var("SMTP_PORT")?.parse::<u16>().unwrap_or(587);
        let smtp_username = env_var("SMTP_USERNAME")?;
        let smtp_password = env_var("SMTP_PASSWORD")?;
        Ok(Self {
            smtp_server,
            smtp_port,
            smtp_username,
            smtp_password: SecretBox::new(Box::new(smtp_password)),
        })
    }
}

fn smtp_cfg<'a>(smtp_port: u16) -> (&'a str, &'a str) {
    match smtp_port {
        465 => ("smtps", ""),
        1025 => ("smtp", ""),
        _ => ("smtp", "?tls=required"),
    }
}

fn init_mail_client() -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error>
{
    let email_cfg =
        EmailConfig::from_env().expect("Failed to get env variables and setup email config");
    let paswd_encoded = urlencoding::encode(email_cfg.smtp_password.expose_secret());
    let (scheme, tls_param) = smtp_cfg(email_cfg.smtp_port);
    let email_url = format!(
        "{}://{}:{}@{}:{}{}",
        scheme,
        email_cfg.smtp_username,
        paswd_encoded,
        email_cfg.smtp_server,
        email_cfg.smtp_port,
        tls_param
    );

    Ok(AsyncSmtpTransport::<Tokio1Executor>::from_url(&email_url)?.build())
}

pub fn get_mail_client() -> AsyncSmtpTransport<Tokio1Executor> {
    MAIL_CLIENT
        .get_or_init(|| init_mail_client().unwrap())
        .clone()
}

pub async fn send_email(
    from_sender: String,
    email_body: String,
    subject: &str,
    email_recipient: &str,
    client: AsyncSmtpTransport<Tokio1Executor>,
    msg_id: Option<String>,
) {
    let msg = Message::builder()
        .message_id(msg_id)
        .from(from_sender.parse().unwrap())
        .to(email_recipient.parse().unwrap())
        .subject(subject)
        .body(email_body.to_string())
        .unwrap();
    client.send(msg).await.expect("Failed to send message");
}
