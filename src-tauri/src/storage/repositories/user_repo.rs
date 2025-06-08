use std::str::FromStr;

use bson::{doc, Document};
use futures::StreamExt;
use log::warn;
use mongodb::{options::FindOptions, Collection};

use crate::storage::db::Database;
use crate::storage::models::user::{User, UserRole};
use crate::utils::error::AppError;

const USERS_COLLECTION: &str = "users";

/// Repository for User objects
pub struct UserRepository {
    /// Database connection
    db: Database,
    /// MongoDB collection
    collection: Collection<User>,
}

impl UserRepository {
    pub(crate) fn clone(&self) -> UserRepository {
        UserRepository {
            db: self.db.clone(),
            collection: self.collection.clone(),
        }
    }
}

impl UserRepository {
    /// Create a new user repository
    pub fn new(db: Database) -> Self {
        let collection = db.collection(USERS_COLLECTION);
        Self { db, collection }
    }

    /// Insert a new user
    pub async fn insert(&self, user: User) -> Result<User, AppError> {
        // Check if username already exists
        let username_filter = doc! { "username": &user.username };
        if self.collection.find_one(username_filter, None).await?.is_some() {
            return Err(AppError::ValidationError(format!("Username already exists: {}", user.username)));
        }

        // Check if email already exists
        let email_filter = doc! { "email": &user.email };
        if self.collection.find_one(email_filter, None).await?.is_some() {
            return Err(AppError::ValidationError(format!("Email already exists: {}", user.email)));
        }

        // Insert the user
        let result = self.collection.insert_one(user, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to insert user: {}", e)))?;

        // Get the inserted user
        let inserted_id = result.inserted_id;
        let filter = doc! { "_id": inserted_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find inserted user: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError("Inserted user not found".to_string()))
    }

    /// Find a user by ID
    pub async fn find_by_id(&self, id: &str) -> Result<User, AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("User not found with ID: {}", id)))
    }

    /// Find a user by username
    pub async fn find_by_username(&self, username: &str) -> Result<User, AppError> {
        let filter = doc! { "username": username };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("User not found with username: {}", username)))
    }

    /// Find a user by email
    pub async fn find_by_email(&self, email: &str) -> Result<User, AppError> {
        let filter = doc! { "email": email };

        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("User not found with email: {}", email)))
    }

    /// Update a user
    pub async fn update(&self, user: User) -> Result<User, AppError> {
        let id = user.id.ok_or_else(|| AppError::ValidationError("User ID is required".to_string()))?;

        // Check if username already exists (for another user)
        let username_filter = doc! { "username": &user.username, "_id": { "$ne": id } };
        if self.collection.find_one(username_filter, None).await?.is_some() {
            return Err(AppError::ValidationError(format!("Username already exists: {}", user.username)));
        }

        // Check if email already exists (for another user)
        let email_filter = doc! { "email": &user.email, "_id": { "$ne": id } };
        if self.collection.find_one(email_filter, None).await?.is_some() {
            return Err(AppError::ValidationError(format!("Email already exists: {}", user.email)));
        }

        let filter = doc! { "_id": id };
        let update_result = self.collection.replace_one(filter.clone(), user, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update user: {}", e)))?;

        if update_result.modified_count == 0 {
            return Err(AppError::NotFoundError(format!("User not found with ID: {}", id)));
        }

        // Get the updated user
        self.collection.find_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find updated user: {}", e)))?
            .ok_or_else(|| AppError::NotFoundError(format!("Updated user not found with ID: {}", id)))
    }

    /// Delete a user
    pub async fn delete(&self, id: &str) -> Result<(), AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };

        let delete_result = self.collection.delete_one(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete user: {}", e)))?;

        if delete_result.deleted_count == 0 {
            return Err(AppError::NotFoundError(format!("User not found with ID: {}", id)));
        }

        Ok(())
    }

    /// Find all users with optional filtering and pagination
    pub async fn find_all(
        &self,
        role: Option<UserRole>,
        is_active: Option<bool>,
        limit: Option<i64>,
        skip: Option<u64>,
        sort_field: Option<&str>,
        sort_order: Option<i32>,
    ) -> Result<Vec<User>, AppError> {
        // Build filter
        let mut filter = Document::new();

        if let Some(role) = role {
            filter.insert("role", role.to_string());
        }

        if let Some(active) = is_active {
            filter.insert("is_active", active);
        }

        // Build options
        let mut options = FindOptions::default();
        options.limit = limit;
        options.skip = skip;

        // Set sort order
        if let Some(field) = sort_field {
            let order = sort_order.unwrap_or(1); // Default to ascending
            options.sort = Some(doc! { field: order });
        } else {
            // Default sort by username
            options.sort = Some(doc! { "username": 1 });
        }

        // Execute query
        let mut cursor = self.collection.find(filter, options).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to find users: {}", e)))?;

        // Collect results
        let mut users = Vec::new();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(user) => users.push(user),
                Err(e) => warn!("Error retrieving user: {}", e),
            }
        }

        Ok(users)
    }

    /// Count users with optional filtering
    pub async fn count(
        &self,
        role: Option<UserRole>,
        is_active: Option<bool>,
    ) -> Result<u64, AppError> {
        // Build filter
        let mut filter = Document::new();

        if let Some(role) = role {
            filter.insert("role", role.to_string());
        }

        if let Some(active) = is_active {
            filter.insert("is_active", active);
        }

        // Execute count
        let count = self.collection.count_documents(filter, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count users: {}", e)))?;

        Ok(count)
    }

    /// Update user's last login time
    pub async fn update_last_login(&self, id: &str) -> Result<(), AppError> {
        let object_id = mongodb::bson::oid::ObjectId::from_str(id)
            .map_err(|e| AppError::ValidationError(format!("Invalid ID format: {}", e)))?;

        let filter = doc! { "_id": object_id };
        let update = doc! {
            "$set": {
                "last_login": bson::DateTime::now(),
            }
        };

        let update_result = self.collection.update_one(filter, update, None).await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update last login: {}", e)))?;

        if update_result.modified_count == 0 {
            return Err(AppError::NotFoundError(format!("User not found with ID: {}", id)));
        }

        Ok(())
    }
}