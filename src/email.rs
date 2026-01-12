use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::AsyncSmtpTransportBuilder};
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use std::{
    env::{VarError, var as env_var},
    sync::OnceLock,
};

static MAIL_CLIENT: OnceLock<AsyncSmtpTransport<Tokio1Executor>> = OnceLock::new();

pub fn verification_body(user_name: &str, url_token: &str, minutes: u32, app: &str) -> String {
    format!(
        "Hi {user_name},\n\n\
         Thank you for signing up! Please verify your email by clicking:\n\n\
         {url_token}\n\n\
         This link expires in {minutes} minutes.\n\n\
         If you didn't create this account, please ignore this email.\n\n\
         Best regards,\n\
         {app}",
        user_name = user_name,
        url_token = url_token,
        minutes = minutes,
        app = app,
    )
}
pub fn password_reset_body(user_name: &str, reset_url: &str, minutes: u32, app: &str) -> String {
    format!(
        "Hi {user_name},\n\n\
         We received a request to reset your password. Click the link below:\n\n\
         {reset_url}\n\n\
         This link expires in {minutes} minutes.\n\n\
         If you didn't request this, please ignore this email. Your password won't change.\n\n\
         Best regards,\n\
         {app}",
        user_name = user_name,
        reset_url = reset_url,
        minutes = minutes,
        app = app,
    )
}
pub fn email_change_body(user_name: &str, confirm_url: &str, minutes: u32, app: &str) -> String {
    format!(
        "Hi {user_name},\n\n\
         You requested to change your email to this address.\n\n\
         Click to confirm:\n\n\
         {confirm_url}\n\n\
         This link expires in {minutes} minutes.\n\n\
         If you didn't request this change, contact support immediately.\n\n\
         Best regards,\n\
         {app}",
        user_name = user_name,
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
        9999 => ("smtp", ""),
        _ => ("smtp", "?tls=required"),
    }
}

fn init_mail_server() -> Result<AsyncSmtpTransport<Tokio1Executor>, lettre::transport::smtp::Error>
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
        .get_or_init(|| init_mail_server().unwrap())
        .clone()
}

#[cfg(test)]
mod mail {
    use super::env_var;
    use crate::email::{get_mail_client, verification_body};
    use lettre::{AsyncTransport, Message};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_send_email() {
        dotenv::dotenv().expect("Failed to load env variables ");
        let msg_id = Uuid::new_v4();
        let con = get_mail_client();
        let from_sender = env_var("SMTP_FROM_ADDRESS").unwrap();
        let body = verification_body("shawarma", "burger", 55, "family_cloud");
        let msg = Message::builder()
            .from(from_sender.parse().unwrap())
            .to("shawarma@potato.com".parse().unwrap())
            .subject(msg_id.to_string())
            .body(body)
            .unwrap();

        con.send(msg).await.expect("Failed to send email msg");
    }
}
