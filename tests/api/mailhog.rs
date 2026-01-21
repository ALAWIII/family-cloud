use anyhow::Ok;
use family_cloud::{get_mail_client, verification_body};
use lettre::{AsyncTransport, Message};
use serde_json::Value;
use uuid::Uuid;

async fn test_send_email() -> anyhow::Result<()> {
    dotenv::dotenv().unwrap();
    let mail = get_mail_client()?;
    let msg_id = Uuid::new_v4();
    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();

    let body = verification_body(
        "shawarma",
        &format!("token={}", &msg_id.to_string()),
        55,
        "family_cloud",
    );
    let msg = Message::builder()
        .message_id(Some(msg_id.to_string()))
        .from(from_sender.parse().unwrap())
        .to("shawarma@potato.com".parse().unwrap())
        .subject("test send email")
        .body(body)
        .unwrap();
    mail.send(msg).await.expect("Failed to send email message");

    let client = reqwest::Client::new();
    let response = client
        .get("http://localhost:8025/api/v2/messages")
        .send()
        .await
        .expect("Failed to query MailHog API");
    let json: Value = response.json().await.expect("Failed to parse JSON");
    let messages = json["items"].as_array().expect("No messages found");
    //dbg!(&messages[0]);
    assert!(
        messages
            .iter()
            .any(|v| v["Content"]["Headers"]["Message-ID"][0] == msg_id.to_string())
    );
    Ok(())
}
