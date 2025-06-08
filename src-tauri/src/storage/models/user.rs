use std::fmt;
use serde::{Serialize, Deserialize};
use bson::DateTime;
use mongodb::bson::{self, oid::ObjectId};
use bcrypt::{hash, verify, DEFAULT_COST};
use crate::utils::error::AppError;

/// User roles within the system
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    SecurityAnalyst,
    Viewer,
}
impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Admin   => "admin",
            Self::SecurityAnalyst => "analyst",
            Self::Viewer  => "viewer",
        };
        write!(f, "{s}")
    }
}

/// Represents a user of the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// Username for login
    pub username: String,

    /// User's email address
    pub email: String,

    /// Hashed password
    pub password_hash: String,

    /// User's full name
    pub name: String,

    /// User's role
    pub role: UserRole,

    /// Time when the user account was created
    pub created_at: DateTime,

    /// Time when the user account was last updated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,

    /// Time of the user's last login
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime>,

    /// Whether the user account is active
    pub is_active: bool,
}

impl User {
    /// Create a new user
    pub fn new(
        username: String,
        email: String,
        password: String,
        name: String,
        role: UserRole,
    ) -> Result<Self, AppError> {
        // Hash the password
        let password_hash = hash_password(&password)?;

        let now = chrono::Utc::now();

        Ok(Self {
            id: None,
            username,
            email,
            password_hash,
            name,
            role,
            created_at: bson::DateTime::from_chrono(now),
            updated_at: None,
            last_login: None,
            is_active: true,
        })
    }

    /// Verify a password against the stored hash
    pub fn verify_password(&self, password: &str) -> Result<bool, AppError> {
        verify_password(password, &self.password_hash)
    }

    /// Update the user's password
    pub fn update_password(&mut self, password: &str) -> Result<(), AppError> {
        self.password_hash = hash_password(password)?;
        self.updated_at = Some(bson::DateTime::from_chrono(chrono::Utc::now()));
        Ok(())
    }

    /// Record a login
    pub fn record_login(&mut self) {
        self.last_login = Some(bson::DateTime::from_chrono(chrono::Utc::now()));
    }
}

/// Hash a password
fn hash_password(password: &str) -> Result<String, AppError> {
    hash(password, DEFAULT_COST)
        .map_err(|e| AppError::InternalError(format!("Failed to hash password: {}", e)))
}

/// Verify a password against a hash
fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    verify(password, hash)
        .map_err(|e| AppError::InternalError(format!("Failed to verify password: {}", e)))
}

/// Represents the data needed to create a new user
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub name: String,
    pub role: UserRole,
}

/// Represents the data returned after user creation
#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub created_at: DateTime,
    pub is_active: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.map(|id| id.to_hex()).unwrap_or_default(),
            username: user.username,
            email: user.email,
            name: user.name,
            role: user.role,
            created_at: user.created_at,
            is_active: user.is_active,
        }
    }
}