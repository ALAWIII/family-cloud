use family_cloud::{get_db, get_redis_pool};

use crate::{
    clean_mailhog, convert_raw_tokens_to_hashed, create_app,
    get_mailhog_msg_id_and_extract_raw_token_list, search_database_for_email,
    search_redis_for_hashed_token_id,
};

async fn account_signup() {
    let app = create_app().await;
    let resp = app.signup_request_new_account().await;
}

#[tokio::test]
async fn signup_new_account_verify_token() {
    //verify?token={}
    let app = create_app().await;
    let resp = app.signup_request_new_account().await;
    let body = resp.text();
    assert_eq!(
        body,
        "If this email is new, you'll receive a verification email"
    );

    let messages = app.get_all_messages_mailhog().await;
    //dbg!(&messages[0]);
    let msg_verify_id_list =
        get_mailhog_msg_id_and_extract_raw_token_list(&messages, "verification"); // official message id , and assigned raw token as a message id
    let hashed_tokens_list =
        convert_raw_tokens_to_hashed(msg_verify_id_list.iter().map(|(_, v)| v).collect());
    let pool = get_redis_pool();
    let mut con = pool.get().await.unwrap();
    let url = "/api/auth/verify/signup";

    for msg_id in hashed_tokens_list {
        // asserts that the token and pending account content are stored temporary in redis
        let token_payload = search_redis_for_hashed_token_id(&msg_id, &mut con).await;
        //dbg!(&token_payload);
        assert!(token_payload.is_some());
    }
    // verify new account by clicking the url+token inside email message
    for (_, raw_token) in &msg_verify_id_list {
        // verify the signup
        app.click_verify_url_in_email_message(url, raw_token)
            .await
            .assert_status_ok();
    }
    // clean mailhog messages list
    // used to make sure that the user account is stored after finishing the verification proccess
    assert!(
        search_database_for_email(&get_db(), &app.email)
            .await
            .is_some()
    );
    clean_mailhog(&msg_verify_id_list, &app).await;

    //dbg!(v);
}

//#[tokio::test]
async fn signup_existing_account_token() {
    // it must store the verified account in database so that it can continue to use is_email_exist
    let app = create_app().await;
    app.signup_request_new_account();
    app.signup_request_new_account();
}
