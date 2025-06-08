use mongodb::bson::{self, doc, oid::ObjectId, Document};
use futures::stream::TryStreamExt;
use crate::storage::db::Database;
use crate::utils::error::AppError;
use crate::api::handlers::faq::FaqItem;

/// Repository for managing FAQ items in the database
pub struct FaqRepository {
    /// MongoDB database connection
    db: Database,
    /// Collection name
    collection_name: String,
}

impl FaqRepository {
    /// Create a new FAQ repository
    pub fn new(db: Database) -> Self {
        Self {
            db,
            collection_name: "faq_items".to_string(),
        }
    }

    /// Find all FAQ items
    pub async fn find_all(&self) -> Result<Vec<FaqItem>, AppError> {
        let collection = self.db.collection::<Document>(&self.collection_name);
        
        // Sort by category and then by id
        let mut cursor = collection.find(None, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to retrieve FAQ items: {}", e)))?;
        
        let mut items = Vec::new();
        while let Some(doc) = cursor.try_next().await
            .map_err(|e| AppError::DatabaseError(format!("Failed to iterate FAQ items: {}", e)))? {
            items.push(self.document_to_faq_item(doc)?);
        }
        
        Ok(items)
    }

    /// Find a FAQ item by ID
    pub async fn find_by_id(&self, id: &str) -> Result<FaqItem, AppError> {
        let collection = self.db.collection::<Document>(&self.collection_name);
        
        // Try to convert the ID to ObjectId or use string matching
        let query = if let Ok(object_id) = ObjectId::parse_str(id) {
            doc! { "_id": object_id }
        } else {
            doc! { "id": id }
        };
        
        let doc = collection.find_one(query, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find FAQ item: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("FAQ item not found with ID: {}", id)))?;
        
        self.document_to_faq_item(doc)
    }

    /// Convert BSON document to FaqItem
    fn document_to_faq_item(&self, doc: Document) -> Result<FaqItem, AppError> {
        // Extract the ObjectId and convert to string
        let id = match doc.get("_id") {
            Some(bson::Bson::ObjectId(oid)) => oid.to_string(),
            _ => doc.get_str("id")
                .map_err(|_| AppError::DataError("Invalid FAQ item ID".to_string()))?
                .to_string(),
        };
        
        // Extract other fields
        let question = doc.get_str("question")
            .map_err(|_| AppError::DataError("Missing question in FAQ item".to_string()))?
            .to_string();
        
        let answer = doc.get_str("answer")
            .map_err(|_| AppError::DataError("Missing answer in FAQ item".to_string()))?
            .to_string();
        
        let category = doc.get_str("category")
            .map_err(|_| AppError::DataError("Missing category in FAQ item".to_string()))?
            .to_string();
        
        // Extract last_updated timestamp
        let last_updated = match doc.get("last_updated") {
            Some(bson::Bson::DateTime(dt)) => dt.to_chrono().to_rfc3339(),
            _ => chrono::Utc::now().to_rfc3339(), // Default to current time
        };
        
        Ok(FaqItem {
            id,
            question,
            answer,
            category,
            last_updated,
        })
    }
} 