use std::env;
extern crate dotenv;
use actix_web::{
    HttpResponse, cookie::Cookie,
    cookie::time::Duration as ActixWebDuration,
};
use chrono::{Utc, Duration};
use dotenv::dotenv;

use futures::StreamExt;
use jsonwebtoken::{encode, Header, EncodingKey, decode, DecodingKey, Validation, Algorithm};
use mongodb::{Collection, Client, results::{InsertOneResult, UpdateResult, DeleteResult}, bson::{doc, oid::ObjectId, extjson::de::Error}};
use serde_json::json;

use crate::models::models::{User, ErrorResponse, LoginSchema, TokenClaims, Product, UpdateCart};



//MongoRepo Structure
#[derive(Debug, Clone)]
pub struct MongoRepo {
    user: Collection<User>,
    product: Collection<Product>,
}

impl MongoRepo {

    pub async fn init() -> Self {

        dotenv().ok();

        let url = match env::var("MONGOURI"){
            Ok(url) => url,
            Err(_) => format!("Error loading env varibale")
        };

        let client = Client::with_uri_str(url).await.unwrap();
        let db = client.database("shopping_cart_api");
        let user = db.collection("user");
        let product = db.collection("products");

        MongoRepo {
            user,
            product
        }

    }

    //Found user by email
    pub async fn find_user_by_email(&self, email: String) -> String {

        let filter_email = doc! {
            "email" : email
        };

        let check_email = self
            .user
            .find_one(filter_email, None)
            .await.ok()
            .expect("Error finding email");

        match check_email{
            Some(user) => user.email,
            None => "No email found".to_string()
        }
    }

        //user find by email handler
        pub async fn find_by_email_and_password(&self, email: &String, password: &String) -> Result<Option<User>, Error> {
            
            let user = self
                .user
                .find_one( doc! {"email" : email, "password" : password}, None)
                .await.ok()
                .expect("Error finding user");
    
            Ok(user)
    
        }

    //Register user
    pub async fn register_user(&self, new_user: User) -> Result<InsertOneResult, ErrorResponse> {

        let email = self.find_user_by_email(new_user.email.clone()).await;

        let new_email = new_user.email.clone();

        if email == new_email {
            Err(
                ErrorResponse {
                    status: false,
                    message: "Email already exists".to_owned()
                }
            )
        } else {
            let doc = User {
                uid: None,
                name: new_user.name,
                email: new_user.email,
                password: new_user.password,
            };
    
            let user = self
                .user
                .insert_one(doc, None)
                .await.ok()
                .expect("Error inseting user");
    
            Ok(user)
        }
    }

    //handler to validate the user
    pub async fn validate_user(&self, token: &str) -> Result<Option<User>, HttpResponse>{

        let secret_key = "secret".to_owned();
    
        let var = secret_key;
        let key = var.as_bytes();
        let decode = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(key),
            &Validation::new(Algorithm::HS256),
        );

        println!("decode: {:?}", decode);

        match decode {
            Ok(decoded) => {

                println!("object_id{:?}", decoded.claims.sub.to_owned());

                let id = decoded.claims.sub;

                let bson_id = ObjectId::parse_str(id).unwrap(); //used to convert <String> to <bjectId>

                let user = self
                    .user
                    .find_one( doc! {"_id" : bson_id }, None)
                    .await.ok()
                    .expect("Error finding");

                println!("{:?}", user);
        
                Ok(user)

            }
            Err(_) => Err(
                //HttpResponse::BadRequest().json(json!({"status" :  "fail", "message": "Invalid token"})))
                HttpResponse::BadRequest().json(ErrorResponse{
                    status: false,
                    message: "Invalid token".to_owned()
                }))
        }
    }

    //finding product
    pub async fn finding_product(&self, token: &str, product_id: &ObjectId) -> Result<Option<Product>, ErrorResponse> {

        match self.validate_user(token).await.unwrap() {
            Some(user) => {
                
                let user_id = user.uid.unwrap();
        
                let product = self
                    .product
                    .find_one( doc! {
                        "_id" : product_id,
                        "_uid" : user_id
                    }, None)
                    .await.ok()
                    .expect("Error finding product");
        
                Ok(product)
            },
            None => Err(ErrorResponse{
                status: false,
                message: "User not found".to_string(),
            })
        }
    }

    //User login
    pub async fn login(&self, login: LoginSchema) -> HttpResponse {

        match self.find_by_email_and_password(&login.email, &login.password).await.unwrap() {

            Some(user) => {

                let jwt_secret = "secret".to_owned();

                let id = user.uid.unwrap();  //Convert Option<ObjectId> to ObjectId using unwrap()

                let now = Utc::now();
                let iat = now.timestamp() as usize;
                
                let exp = (now + Duration::minutes(1)).timestamp() as usize;
                let claims: TokenClaims = TokenClaims {
                    sub: id.to_string(),
                    exp,
                    iat,
                };

                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(jwt_secret.as_ref()),
                )
                .unwrap();

                let cookie = Cookie::build("token", token.to_owned())
                    .path("/")
                    .max_age(ActixWebDuration::new(60 * 60, 0))
                    .http_only(true)
                    .finish();
                
                HttpResponse::Ok()
                    .cookie(cookie)
                    .json(json!({"status" :  "success", "token": token}))
            },

            None => {
                return HttpResponse::BadRequest()
                .json(ErrorResponse{
                    status: false,
                    message: "Invalid username or password".to_owned()
                })
            }
        }

    }


    //Add product
    pub async fn add_product(&self, token: &str, new_product: Product) -> Result<InsertOneResult, ErrorResponse> {

        match self.validate_user(token).await.unwrap(){

            Some(user) => {

                let id = user.uid.unwrap();

                let new_product = Product {
                    pid: None,
                    uid: Some(id),
                    product: new_product.product,
                    price: new_product.price,
                    qty: new_product.qty,
                    total: Some(new_product.price * new_product.qty),
                    created_at: Some(Utc::now())
                };

                let product = self
                    .product
                    .insert_one(new_product, None)
                    .await
                    .ok()
                    .expect("Error inserting product");

                Ok(product)
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })               
            }
        }
    }

    //Get all products
    pub async fn product_list(&self, token: &str) -> Result<Vec<Product>, ErrorResponse> {

        match self.validate_user(token).await.unwrap(){

            Some(user) => {

                let user_id = user.uid.unwrap();

                let doc = doc! {
                    "_uid" : user_id
                };

                let mut product_list = self
                    .product
                    .find(doc, None)
                    .await
                    .ok()
                    .expect("Error finding products");

                let mut product_vec = Vec::new();

                while let Some(doc) = product_list.next().await {

                    match doc {
                        Ok(product) => {
                            product_vec.push(product)
                        },
                        Err(err) => {
                            eprintln!("Error finding product: {:?}", err)
                        },
                    }
                }

                Ok(product_vec)
            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })
            }
        }
    }

    //Update product
    pub async fn update_product_by_id(&self, token: &str, product: UpdateCart, product_id: String) -> Result<UpdateResult, ErrorResponse> {

        match self.validate_user(token).await.unwrap() {

            Some(_) => {

                let pid = ObjectId::parse_str(product_id).unwrap();

                match self.finding_product(&token, &pid).await.unwrap() {

                    Some(p) => {

                        let filter = doc! {
                            "_id" : pid
                        };

                        let updated_total = product.qty * p.price;

                        let update_product = doc! {
                            "$set":
                                {
                                    "qty" : product.qty,
                                    "total" : updated_total
                                },
                        };

                        let updated_product = self
                            .product
                            .update_one(filter, update_product, None)
                            .await
                            .ok()
                            .expect("Error updating product");

                        Ok(updated_product)

                    },
                    None => {
                        return Err(
                            ErrorResponse{
                                status: false,
                                message: "Product not found".to_owned()
                            }
                        )
                    }
                }

            },
            None => {
                Err(ErrorResponse {
                    status: false,
                    message: "Not found user".to_string(),
                })              
            }
        }
    }

    //Delete product
    pub async fn delete_product(&self, token: &str, product_id: String) -> Result<DeleteResult, ErrorResponse> {

        match self.validate_user(token).await.unwrap() {

            Some(_) => {

                let pid = ObjectId::parse_str(product_id).unwrap();

                match self.finding_product(&token, &pid).await.unwrap() {

                    Some(p) => {

                        let filter = doc! {
                            "_id" : p.pid.unwrap()
                        };

                        let delete_doc = self
                            .product
                            .delete_one(filter, None)
                            .await
                            .ok()
                            .expect("Error deleting product");

                        Ok(delete_doc)
                    },
                    None => {
                        return Err(ErrorResponse {
                            message: "Product Not found".to_owned(),
                            status: false
                        })                       
                    }
                }
            },
            None => Err(
                    ErrorResponse {
                        status: false,
                        message: "Not found user".to_string(),
                    }  
            )
        }
    }
}