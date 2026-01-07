use crate::database::init_db;

pub async fn run() -> Result<(), sqlx::Error> {
    dotenv::dotenv().ok();
    init_db().await
}
