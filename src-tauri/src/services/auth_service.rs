use std::env;

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, DecodingKey, EncodingKey, Header, Validation};
use log::warn;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::storage::models::user::User;
use crate::storage::repositories::user_repo::UserRepository;
use crate::utils::error::AppError;

const JWT_SECRET: &str = "neurodefender_jwt_secret_change_in_production"; // Default, should be overridden
const REFRESH_SECRET: &str = "neurodefender_refresh_secret_change_in_production"; // Default, should be overridden

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user ID)
    pub exp: usize,  // Expiration time
    pub iat: usize,  // Issued at time
    pub username: String,
    pub name: String,
    pub role: String,
}

/// Refresh token Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String, // Subject (user ID)
    pub exp: usize,  // Expiration time
    pub iat: usize,  // Issued at time
    pub jti: String, // JWT ID (unique identifier for this token)
}

/// Authentication service
pub struct AuthService {
    user_repo: UserRepository,
    jwt_secret: String,
    refresh_secret: String,
    jwt_expiration: i64, // In seconds
    refresh_expiration: i64, // In seconds
}

impl AuthService {
    /// Create a new auth service
    pub fn new(user_repo: UserRepository) -> Self {
        // Get JWT secret from environment or use default
        let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| JWT_SECRET.to_string());
        let refresh_secret = env::var("REFRESH_SECRET").unwrap_or_else(|_| REFRESH_SECRET.to_string());
        let jwt_expiration = env::var("JWT_EXPIRATION")
            .map(|v| v.parse::<i64>().unwrap_or(3600)) // Default to 1 hour
            .unwrap_or(3600);
        let refresh_expiration = env::var("REFRESH_EXPIRATION")
            .map(|v| v.parse::<i64>().unwrap_or(604800)) // Default to 7 days
            .unwrap_or(604800);

        Self {
            user_repo,
            jwt_secret,
            refresh_secret,
            jwt_expiration,
            refresh_expiration,
        }
    }

    /// Authenticate a user and generate tokens
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<(User, String, String), AppError> {
        // Find user by username
        let user = self.user_repo.find_by_username(username).await
            .map_err(|_| AppError::AuthError("Invalid username or password".to_string()))?;

        // Check if user is active
        if !user.is_active {
            return Err(AppError::AuthError("Account is inactive".to_string()));
        }

        // Verify password
        let is_valid = user.verify_password(password)
            .map_err(|e| AppError::AuthError(format!("Authentication error: {}", e)))?;

        if !is_valid {
            return Err(AppError::AuthError("Invalid username or password".to_string()));
        }

        // Update last login time
        if let Some(id) = &user.id {
            if let Err(e) = self.user_repo.update_last_login(&id.to_hex()).await {
                warn!("Failed to update last login time: {}", e);
            }
        }

        // Generate tokens
        let user_id = user.id.as_ref().map(|id| id.to_hex()).unwrap_or_default();
        let access_token = self.generate_access_token(&user)?;
        let refresh_token = self.generate_refresh_token(&user_id)?;

        Ok((user, access_token, refresh_token))
    }

    /// Generate access token (JWT)
    fn generate_access_token(&self, user: &User) -> Result<String, AppError> {
        let user_id = user.id.as_ref().map(|id| id.to_hex()).unwrap_or_default();

        let now = Utc::now();
        let expiration = now + Duration::seconds(self.jwt_expiration);

        let claims = Claims {
            sub: user_id,
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
            username: user.username.clone(),
            name: user.name.clone(),
            role: format!("{:?}", user.role),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        ).map_err(|e| AppError::AuthError(format!("Failed to generate token: {}", e)))?;

        Ok(token)
    }

    /// Generate refresh token
    fn generate_refresh_token(&self, user_id: &str) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::seconds(self.refresh_expiration);

        let claims = RefreshClaims {
            sub: user_id.to_string(),
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.refresh_secret.as_bytes()),
        ).map_err(|e| AppError::AuthError(format!("Failed to generate refresh token: {}", e)))?;

        Ok(token)
    }

    /// Refresh an access token using a refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<(String, String), AppError> {
        // Validate refresh token
        let claims = decode::<RefreshClaims>(
            refresh_token,
            &DecodingKey::from_secret(self.refresh_secret.as_bytes()),
            &Validation::default(),
        ).map_err(|e| AppError::AuthError(format!("Invalid refresh token: {}", e)))?;

        // Get user from claims
        let user_id = claims.claims.sub;
        let user = self.user_repo.find_by_id(&user_id).await
            .map_err(|_| AppError::AuthError("User not found".to_string()))?;

        // Check if user is active
        if !user.is_active {
            return Err(AppError::AuthError("Account is inactive".to_string()));
        }

        // Generate new tokens
        let access_token = self.generate_access_token(&user)?;
        let refresh_token = self.generate_refresh_token(&user_id)?;

        Ok((access_token, refresh_token))
    }

    /// Validate an access token
    pub fn validate_token(&self, token: &str) -> Result<Claims, AppError> {
        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        ).map_err(|e| AppError::AuthError(format!("Invalid token: {}", e)))?;

        Ok(claims.claims)
    }

    /// Change user password
    pub async fn change_password(&self, user_id: &str, current_password: &str, new_password: &str) -> Result<(), AppError> {
        // Find user
        let mut user = self.user_repo.find_by_id(user_id).await?;

        // Verify current password
        let is_valid = user.verify_password(current_password)
            .map_err(|e| AppError::AuthError(format!("Authentication error: {}", e)))?;

        if !is_valid {
            return Err(AppError::AuthError("Current password is incorrect".to_string()));
        }

        // Update password
        user.update_password(new_password)?;

        // Save user
        self.user_repo.update(user).await?;

        Ok(())
    }

    /// Reset user password (admin function)
    pub async fn reset_password(&self, user_id: &str, new_password: &str) -> Result<(), AppError> {
        // Find user
        let mut user = self.user_repo.find_by_id(user_id).await?;

        // Update password
        user.update_password(new_password)?;

        // Save user
        self.user_repo.update(user).await?;

        Ok(())
    }
}