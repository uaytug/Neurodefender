use thiserror::Error;
use std::io;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("Authorization error: {0}")]
    AuthzError(String),

    #[error("Not found: {0}")]
    NotFoundError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Network capture error: {0}")]
    CaptureError(String),

    #[error("Detection engine error: {0}")]
    DetectionError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Prevention error: {0}")]
    PreventionError(String),

    #[error("Monitor error: {0}")]
    MonitorError(String),

    #[error("System operation error: {0}")]
    SystemError(String),

    #[error("Data conversion error: {0}")]
    DataError(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::InternalError(msg) => {
                log::error!("Internal server error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "An internal server error occurred".to_string(),
                    details: None,
                })
            }
            AppError::AuthError(msg) => {
                log::debug!("Authentication error: {}", msg);
                HttpResponse::Unauthorized().json(ErrorResponse {
                    error: "authentication_error".to_string(),
                    message: msg.clone(),
                    details: None,
                })
            }
            AppError::AuthzError(msg) => {
                log::debug!("Authorization error: {}", msg);
                HttpResponse::Forbidden().json(ErrorResponse {
                    error: "authorization_error".to_string(),
                    message: msg.clone(),
                    details: None,
                })
            }
            AppError::NotFoundError(msg) => {
                log::debug!("Not found error: {}", msg);
                HttpResponse::NotFound().json(ErrorResponse {
                    error: "not_found".to_string(),
                    message: msg.clone(),
                    details: None,
                })
            }
            AppError::ValidationError(msg) => {
                log::debug!("Validation error: {}", msg);
                HttpResponse::BadRequest().json(ErrorResponse {
                    error: "validation_error".to_string(),
                    message: msg.clone(),
                    details: None,
                })
            }
            AppError::DatabaseError(msg) => {
                log::error!("Database error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "database_error".to_string(),
                    message: "A database error occurred".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::CaptureError(msg) => {
                log::error!("Network capture error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "capture_error".to_string(),
                    message: "A network capture error occurred".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::DetectionError(msg) => {
                log::error!("Detection engine error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "detection_error".to_string(),
                    message: "A detection engine error occurred".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::ConfigError(msg) => {
                log::error!("Configuration error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "config_error".to_string(),
                    message: "A configuration error occurred".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::IoError(err) => {
                log::error!("IO error: {}", err);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "io_error".to_string(),
                    message: "An IO error occurred".to_string(),
                    details: Some(err.to_string()),
                })
            }
            AppError::PreventionError(msg) => {
                log::error!("Prevention error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "prevention_error".to_string(),
                    message: "A prevention action failed".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::MonitorError(msg) => {
                log::error!("Monitor error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "monitor_error".to_string(),
                    message: "A monitoring operation failed".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::SystemError(msg) => {
                log::error!("System operation error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "system_error".to_string(),
                    message: "A system operation failed".to_string(),
                    details: Some(msg.clone()),
                })
            }
            AppError::DataError(msg) => {
                log::error!("Data conversion error: {}", msg);
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "data_error".to_string(),
                    message: "A data conversion error occurred".to_string(),
                    details: Some(msg.clone()),
                })
            }
        }
    }
}

// Utility functions for error conversion
impl From<mongodb::error::Error> for AppError {
    fn from(err: mongodb::error::Error) -> Self {
        AppError::DatabaseError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::ValidationError(err.to_string())
    }
}

impl From<String> for AppError {
    fn from(message: String) -> Self {
        AppError::InternalError(message)
    }
}

impl From<&str> for AppError {
    fn from(message: &str) -> Self {
        AppError::InternalError(message.to_string())
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::InternalError(err.to_string())
    }
}