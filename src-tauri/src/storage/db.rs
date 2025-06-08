use mongodb::{Client, Database as MongoDatabase, options::ClientOptions};
use anyhow::{Result, Context};
use log::{info, debug, error};
use std::time::Duration;

/// Handles the MongoDB database connection
#[derive(Debug, Clone)]
pub struct Database {
    client: Client,
    database: MongoDatabase,
}

impl Database {
    /// Create a new database connection
    pub async fn new(connection_string: &str, no_connection_db_log: &str) -> Result<Self> {
        debug!("Connecting to MongoDB...");

        // Parse the connection string into options
        let mut client_options = ClientOptions::parse(connection_string)
            .await
            .context("Failed to parse MongoDB connection string")?;

        // Configure connection pool and timeouts
        client_options.connect_timeout = Some(Duration::from_secs(5));
        client_options.server_selection_timeout = Some(Duration::from_secs(5));
        client_options.max_pool_size = Some(10);

        // Create the client
        let client = Client::with_options(client_options)
            .context("Failed to create MongoDB client")?;

        // Get the database name from the connection string or use default
        let db_name = extract_database_name(connection_string)?;
        info!("Using database: {}", db_name);

        // Get a handle to the database
        let database = client.database(&db_name);

        // Test the connection by running a simple command
        match database.run_command(mongodb::bson::doc! {"ping": 1}, None).await {
            Ok(_) => {
                info!("Successfully connected to MongoDB");
            }
            Err(e) => {
                error!("Failed to ping MongoDB server: {}", e);
                // Attempt to write to the log file, ignore error if it fails as we are already in an error state.
                let _ = std::fs::write(no_connection_db_log, format!("Failed to connect to MongoDB: {}", e));
                // Return the error to the caller
                return Err(e).context("Failed to ping MongoDB server");
            }
        }

        Ok(Self {
            client,
            database,
        })
    }

    /// Get a reference to the MongoDB database
    pub fn db(&self) -> &MongoDatabase {
        &self.database
    }

    /// Get a reference to the MongoDB client
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get a collection by name
    pub fn collection<T>(&self, name: &str) -> mongodb::Collection<T>
    where
        T: serde::de::DeserializeOwned + serde::Serialize + Send + Sync,
    {
        self.database.collection(name)
    }
}

/// Extract the database name from a MongoDB connection string
fn extract_database_name(connection_string: &str) -> Result<String> {
    // Try to extract database name from the connection string
    if let Some(db_section) = connection_string.split('/').nth(3) {
        if let Some(db_name) = db_section.split('?').next() {
            if !db_name.is_empty() {
                return Ok(db_name.to_string());
            }
        }
    }

    // Default database name if not specified in the connection string
    Ok("neurodefender".to_string())
}