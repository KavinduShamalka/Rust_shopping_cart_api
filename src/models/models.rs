use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use chrono::prelude::*;

//User structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename="_id", skip_serializing_if = "Option::is_none")]
    pub uid: Option<ObjectId>,
    pub name: String,
    pub email: String,
    pub password: String,
}

//Product structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Product {
    #[serde(rename="_id", skip_serializing_if="Option::is_none")]
    pub pid: Option<ObjectId>,
    #[serde(rename="_uid", skip_serializing_if="Option::is_none")]
    pub uid: Option<ObjectId>,
    pub product: String,
    pub price: f64,
    pub qty: f64,
    #[serde(rename="total", skip_serializing_if="Option::is_none")]
    pub total: Option<f64>,
    #[serde(rename="added_At", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

//Shopping cart structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Shoppingcart {
    pub shopping_cart: Vec<Product>,
}

//User login schema
#[derive(Debug, Deserialize)]
pub struct LoginSchema {
    pub email: String,
    pub password: String,
}

//Token claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

//Error response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub message: String,
    pub status: bool
}

//Success response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateCart {
    pub qty: f64,
}