use actix_web::{get, Responder, HttpResponse, web::{self, Data, Json}, post, HttpRequest, put, delete};
use serde_json::json;

use crate::{repository::repository::MongoRepo, models::models::{User, LoginSchema, Product, UpdateCart}};

//Token
pub fn token(req: HttpRequest) -> String {

    let auth = req.headers().get("Authorization");
    let split: Vec<&str> = auth.unwrap().to_str().unwrap().split("Bearer").collect();    
    let token = split[1].trim().to_owned();

    token
}

#[get("/test")]
pub async fn test() -> impl Responder {
    const MESSAGE: &str = "Shopping Cart API";
    HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": MESSAGE}))
}

//Register user
#[post("/register")]
pub async fn register_user(db: Data<MongoRepo>, new_user: Json<User>) -> HttpResponse {

    let data = User {
        uid: None,
        name: new_user.name.to_owned(),
        email: new_user.email.to_owned(),
        password: new_user.password.to_owned(),
    };

    match db.register_user(data).await {
        Ok(_) => HttpResponse::Ok().json(json!({"status" : "success", "message" : "Registration successfull"})),
        Err(error) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error}))
    }
}

//Login
#[post("/cart/login")]
pub async fn user_login(data: Json<LoginSchema>, db: Data<MongoRepo>) -> HttpResponse {

    let user_data = db.login(data.into_inner());

    user_data.await

}

//Add product
#[post("/add/product")]
pub async fn add_product(data: Json<Product>, db: Data<MongoRepo>, req: HttpRequest) -> HttpResponse {

  let token = token(req);

  let product = Product {
    pid: None,
    uid: None,
    product: data.product.to_owned(),
    price: data.price,
    qty: data.qty,
    total: Some(data.price * data.qty),
    created_at: None,
  };

  match db.add_product(token.as_str(), product).await {
    Ok(list) => HttpResponse::Ok().json(json!({"status" : "success", "result" : list})),
    Err(err) => HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : err})),
  }

}

//Find all products
#[get("/all/products")]
pub async fn all_products(req: HttpRequest, db: Data<MongoRepo>) -> HttpResponse {

    let token = token(req);

    match db.product_list(token.as_str()).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),        
    }
}

//Update product
#[put("/product/update/{id}")]
pub async fn update_product(req: HttpRequest, data: Json<UpdateCart>, id: web::Path<String>, db: Data<MongoRepo>) -> HttpResponse {

    let token = token(req);

    let product_id = id.into_inner();

    let product = UpdateCart {

        qty: data.qty.clone(),

    };

    match db.update_product_by_id(token.as_str(), product, product_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"result" : result})),
        Err(err) => HttpResponse::Ok().json(err),
    }

}

//Delete product
#[delete("/product/delete/{id}")]
pub async fn delete_product(req: HttpRequest, db: Data<MongoRepo>, id: web::Path<String>) -> HttpResponse {

    let product_id = id.into_inner();

    let token = token(req);

    match db.delete_product(token.as_str(), product_id).await {
        Ok(result) => HttpResponse::Ok().json(json!({"status" : "success", "result" : result})),
        Err(error) =>  HttpResponse::ExpectationFailed().json(json!({"status" : "failed", "message" : error})),
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(test)
        .service(register_user)
        .service(user_login)
        .service(add_product)
        .service(all_products)
        .service(update_product)
        .service(delete_product);
}