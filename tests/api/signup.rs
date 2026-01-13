use family_cloud::get_redis_pool;

use crate::{
    create_app, get_mailhog_msg_id_and_raw_token_list, get_msg_id_hashed_list,
    search_redis_for_hashed_token_id,
};

#[tokio::test]
async fn signup_new_account_verify_token() {
    //verify?token={}
    let app = create_app().await;
    let resp = app.signup_request_new_account().await;
    //dbg!(&resp);

    let messages = app.get_all_messages_mailhog().await;
    //dbg!(&messages[0]);
    let msg_verify_id_list = get_mailhog_msg_id_and_raw_token_list(&messages, "verification");
    let msg_verify_hashed_id_list =
        get_msg_id_hashed_list(msg_verify_id_list.iter().map(|(_, v)| v).collect());
    let pool = get_redis_pool();
    let mut con = pool.get().await.unwrap();
    for msg_id in msg_verify_hashed_id_list {
        assert!(
            search_redis_for_hashed_token_id(&msg_id, &mut con)
                .await
                .is_some()
        );
    }
    // cleaning up all messages from mailhog
    for (mmsg_id, _) in msg_verify_id_list {
        assert!(
            app.delete_messages_mailhog(mmsg_id)
                .await
                .status()
                .is_success()
        );
    }

    //dbg!(v);
}
//#[tokio::test]
async fn signup_existing_account_reset_password_token() {
    // it must store the verified account in database so that it can continue to use is_email_exist
    let app = create_app().await;
    app.signup_request_new_account();
    app.signup_request_new_account();
}
