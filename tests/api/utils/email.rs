//! Email verification and token extraction utilities

use family_cloud::{EmailConfig, TokenType};
use scraper::{Html, Selector};
use serde_json::Value;
use testcontainers::{ContainerAsync, GenericImage};
use url::Url;

/// Extracts tokens from email messages for verification flows
pub struct EmailTokenExtractor;

impl EmailTokenExtractor {
    /// Extract all raw tokens matching subject from messages
    pub fn extract_raw_tokens(messages: &[Value], subject: &str) -> Vec<String> {
        messages
            .iter()
            .filter_map(|msg| Self::extract_from_message(msg, subject))
            .collect()
    }

    /// Extract token from single message if subject matches
    fn extract_from_message(message: &Value, subject: &str) -> Option<String> {
        let msg_subject = message["Content"]["Headers"]["Subject"][0].as_str()?;

        if msg_subject.contains(subject) {
            let body = message["Content"]["Body"].as_str()?;
            Self::extract_from_html_body(body)
        } else {
            None
        }
    }

    /// Extract token from HTML email body
    fn extract_from_html_body(email_body: &str) -> Option<String> {
        let decoded = Self::decode_quoted_printable(email_body);
        let document = Html::parse_document(&decoded);
        let selector = Selector::parse(r#"a[id="verify-button"]"#).ok()?;

        let href = document.select(&selector).next()?.value().attr("href")?;

        let parsed_url = Url::parse(href).ok()?;
        parsed_url
            .query_pairs()
            .find(|(key, _)| key == "token")
            .map(|(_, value)| value.to_string())
    }

    /// Decode quoted-printable email encoding
    fn decode_quoted_printable(body: &str) -> String {
        body.replace("=3D", "=")
            .replace("=\n", "")
            .replace("=\r\n", "")
    }

    /// Convert raw tokens to hashed tokens
    pub fn hash_tokens(
        raw_tokens: &[String],
        secret: &str,
        token_type: TokenType,
    ) -> anyhow::Result<Vec<String>> {
        use family_cloud::{decode_token, hash_token};

        Ok(raw_tokens
            .iter()
            .filter_map(|token| {
                let decoded = decode_token(token).ok().unwrap();
                hash_token(&decoded, secret)
                    .map(|v| format!("{}:{}", token_type, v))
                    .ok()
            })
            .collect())
    }
}

/// MailHog API client for email testing
pub struct MailHogClient {
    pub email_conf: EmailConfig,
    container: ContainerAsync<GenericImage>,
    client: reqwest::Client,
    url: String,
}

impl MailHogClient {
    /// Create new MailHog client
    pub fn new(
        base_url: impl Into<String>,
        emailconf: EmailConfig,
        container: ContainerAsync<GenericImage>,
    ) -> Self {
        Self {
            email_conf: emailconf,
            container,
            client: reqwest::Client::new(),
            url: base_url.into(),
        }
    }

    /// Fetch all messages from MailHog
    pub async fn get_all_messages(&self) -> anyhow::Result<Vec<Value>> {
        let response = self
            .client
            .get(format!("{}/api/v2/messages", self.url))
            .send()
            .await?;

        let json: Value = response.json().await?;
        let items = json["items"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("No messages found in MailHog"))?;

        Ok(items.clone())
    }

    /// Get messages filtered by subject
    pub async fn get_messages_by_subject(&self, subject: &str) -> anyhow::Result<Vec<Value>> {
        let messages = self.get_all_messages().await?;
        Ok(messages
            .into_iter()
            .filter(|msg| {
                msg["Content"]["Headers"]["Subject"][0]
                    .as_str()
                    .map(|s| s.contains(subject))
                    .unwrap_or(false)
            })
            .collect())
    }

    /// Delete a single message
    pub async fn delete_message(&self, message_id: &str) -> anyhow::Result<()> {
        self.client
            .delete(format!("{}/api/v1/messages/{}", self.url, message_id))
            .send()
            .await?;

        Ok(())
    }

    /// Delete all messages
    pub async fn delete_all_messages(&self) -> anyhow::Result<()> {
        self.client
            .delete(format!("{}/api/v1/messages", self.url))
            .send()
            .await?;

        Ok(())
    }

    /// Extract verification token from verification emails
    pub async fn get_verification_token(&self, subject: &str) -> anyhow::Result<String> {
        let messages = self.get_messages_by_subject(subject).await?;
        let tokens = EmailTokenExtractor::extract_raw_tokens(&messages, subject);

        tokens
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No verification token found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_quoted_printable() {
        let input = "test=3Dvalue=\nnext";
        let output = EmailTokenExtractor::decode_quoted_printable(input);
        assert_eq!(output, "test=valuenext");
    }

    #[test]
    fn test_extract_token_from_url() {
        let url_with_token = "http://localhost:3000/verify?token=abc123def456";
        let token = url_with_token.split("token=").nth(1).map(|s| s.to_string());
        assert_eq!(token, Some("abc123def456".to_string()));
    }
}
