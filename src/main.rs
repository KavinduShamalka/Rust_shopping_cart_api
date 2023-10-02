use actix_web::{web::Data, HttpServer, App, middleware::Logger};
use repository::repository::MongoRepo;

use crate::api::api::config;

mod models;
mod repository;
mod api;
mod auth;

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let db = MongoRepo::init().await;
    let db_data = Data::new(db);

    println!("Server started sucessfully!!!");

    HttpServer::new(move || {
        App::new()
        .app_data(db_data.clone())
        .wrap(Logger::default())
        .configure(config)
    })
    .bind(("127.0.0.1", 8060))?
    .run()
    .await
}