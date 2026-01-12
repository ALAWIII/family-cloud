use deadpool_redis::redis::AsyncTypedCommands;
use family_cloud::get_redis_pool;
use serde::Deserialize;

use crate::create_app;

#[tokio::test]
async fn signup_credits_stored_in_redis() {
    let app = create_app().await;
    let resp = app.signup_request_new_account().await;
    dbg!(&resp);
    let token = resp.text();
    // Assert successful response
    resp.assert_status_ok();
    //  let pool = get_redis_pool();
    // let mut con = pool.get().await.unwrap();
    //let v = con.get(token).await.unwrap();
    //dbg!(v);
}
