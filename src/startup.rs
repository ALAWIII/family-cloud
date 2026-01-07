use crate::database::init_db;

pub async fn run() {
    init_db().await;
}
