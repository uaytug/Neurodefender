use actix_web::{web, Responder};
use serde::{Deserialize, Serialize};
use crate::utils::error::AppError;
use crate::storage::db::Database;
use crate::storage::repositories::faq_repo::FaqRepository;

/// FAQ Item representation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FaqItem {
    pub id: String,
    pub question: String,
    pub answer: String,
    pub category: String,
    pub last_updated: String,
}

/// Get all FAQ items
pub async fn get_faq_items(
    db: web::Data<Database>,
) -> Result<impl Responder, AppError> {
    // Get the FAQ repository
    let faq_repo = FaqRepository::new(db.get_ref().clone());
    
    // Get all FAQ items from the database
    let faq_items = faq_repo.find_all().await?;
    
    Ok(web::Json(faq_items))
}

/// Get a FAQ item by ID
pub async fn get_faq_item_by_id(
    db: web::Data<Database>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let id = path.into_inner();
    
    // Get the FAQ repository
    let faq_repo = FaqRepository::new(db.get_ref().clone());
    
    // Find the FAQ item by ID
    let faq_item = faq_repo.find_by_id(&id).await?;
    
    Ok(web::Json(faq_item))
} 