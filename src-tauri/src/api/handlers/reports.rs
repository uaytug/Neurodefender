use std::path::Path;
use std::fs;

use actix_web::{web, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use log;
use crate::services::report_service::{Report, ReportFormat, ReportRequest, ReportService, ReportStatus, ReportType};
use crate::storage::db::Database;
use crate::storage::repositories::alert_repo::AlertRepository;
use crate::storage::repositories::report_repo::ReportRepository;
use crate::utils::error::AppError;

const HANDLER_NAME: &'static str = "system";

/// Pagination parameters for reports
#[derive(Debug, Deserialize)]
pub struct ReportPaginationParams {
    #[serde(default)]
    pub page: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub sort_field: Option<String>,
    #[serde(default)]
    pub sort_order: Option<String>,
}

/// Filter parameters for reports
#[derive(Debug, Deserialize)]
pub struct ReportFilterParams {
    #[serde(default)]
    pub report_type: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub start_date: Option<String>,
    #[serde(default)]
    pub end_date: Option<String>,
}

/// Response for paginated reports
#[derive(Debug, Serialize)]
pub struct PaginatedReportsResponse {
    pub reports: Vec<Report>,
    pub total: u64,
    pub page: usize,
    pub limit: usize,
    pub total_pages: usize,
}

/// Get all reports with filtering and pagination
pub async fn get_reports(
    db: web::Data<Database>,
    pagination: web::Query<ReportPaginationParams>,
    filter: web::Query<ReportFilterParams>,
) -> Result<impl Responder, AppError> {
    let report_repo = ReportRepository::new(db.get_ref().clone());

    // Parse pagination params
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(20).min(100); // Max 100 items per page
    let skip = ((page - 1) * limit) as i64;

    // Parse sort params
    let sort_field = pagination.sort_field.as_deref();
    let sort_order = match pagination.sort_order.as_deref() {
        Some("desc") => Some(-1),
        Some("asc") => Some(1),
        _ => None,
    };

    // Parse filter params
    let report_type = match filter.report_type.as_deref() {
        Some("daily") => Some(ReportType::Daily),
        Some("weekly") => Some(ReportType::Weekly),
        Some("monthly") => Some(ReportType::Monthly),
        Some("custom") => Some(ReportType::Custom),
        Some("incident") => Some(ReportType::Incident),
        _ => None,
    };

    let status = match filter.status.as_deref() {
        Some("pending") => Some(ReportStatus::Pending),
        Some("inprogress") => Some(ReportStatus::InProgress),
        Some("completed") => Some(ReportStatus::Completed),
        Some("failed") => Some(ReportStatus::Failed),
        _ => None,
    };

    // Parse date filters
    let start_date = filter.start_date.as_deref().and_then(|d| {
        DateTime::parse_from_rfc3339(d)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    });

    let end_date = filter.end_date.as_deref().and_then(|d| {
        DateTime::parse_from_rfc3339(d)
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    });

    // Get reports
    let reports = report_repo.find_all(
        report_type,
        status,
        Some(HANDLER_NAME),
        start_date,
        end_date,
        Some(limit as i64),
        Some(skip),
        sort_field,
        sort_order,
    ).await?;

    // Count total reports for pagination
    let total = report_repo.count(report_type, status, start_date, end_date).await?;

    let total_pages = (total as f64 / limit as f64).ceil() as usize;

    Ok(web::Json(PaginatedReportsResponse {
        reports,
        total,
        page,
        limit,
        total_pages,
    }))
}

/// Request to generate a report
#[derive(Debug, Deserialize)]
pub struct GenerateReportRequest {
    pub report_type: String,
    pub format: String,
    pub title: Option<String>,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub incident_id: Option<String>,
}

/// Generate a new report
pub async fn generate_report(
    db: web::Data<Database>,
    report_req: web::Json<GenerateReportRequest>,
) -> Result<impl Responder, AppError> {
    log::info!("Received report generation request: {:?}", report_req);
    
    let alert_repo = AlertRepository::new(db.get_ref().clone());

    // Get the user's home directory and create reports folder there
    let reports_dir = match dirs::home_dir() {
        Some(home) => {
            let reports_path = home.join("NeuroDefender").join("reports");
            reports_path.to_string_lossy().to_string()
        }
        None => {
            // Fallback to a directory in the current working directory
            let cwd = std::env::current_dir()
                .map_err(|e| AppError::IoError(e))?;
            let reports_path = cwd.join("neurodefender_reports");
            reports_path.to_string_lossy().to_string()
        }
    };

    // Create the reports directory if it doesn't exist
    std::fs::create_dir_all(&reports_dir)
        .map_err(|e| AppError::IoError(e))?;

    log::info!("Reports directory: {}", reports_dir);

    let report_service = ReportService::new(alert_repo, &reports_dir);

    // Parse report type
    let report_type = match report_req.report_type.as_str() {
        "daily" => ReportType::Daily,
        "weekly" => ReportType::Weekly,
        "monthly" => ReportType::Monthly,
        "custom" => ReportType::Custom,
        "incident" => ReportType::Incident,
        _ => return Err(AppError::ValidationError("Invalid report type".to_string())),
    };

    // Parse report format
    let format = match report_req.format.as_str() {
        "pdf" => ReportFormat::PDF,
        "csv" => ReportFormat::CSV,
        "json" => ReportFormat::JSON,
        "html" => ReportFormat::HTML,
        _ => return Err(AppError::ValidationError("Invalid report format".to_string())),
    };

    // Parse date range for custom reports
    let period_start = if report_type == ReportType::Custom {
        Some(report_req.period_start.as_deref()
            .ok_or_else(|| AppError::ValidationError("Period start is required for custom reports".to_string()))?
            .parse::<DateTime<Utc>>()
            .map_err(|_| AppError::ValidationError("Invalid period start date format".to_string()))?)
    } else {
        None
    };

    let period_end = if report_type == ReportType::Custom {
        Some(report_req.period_end.as_deref()
            .ok_or_else(|| AppError::ValidationError("Period end is required for custom reports".to_string()))?
            .parse::<DateTime<Utc>>()
            .map_err(|_| AppError::ValidationError("Invalid period end date format".to_string()))?)
    } else {
        None
    };

    // Create report request
    let request = ReportRequest {
        report_type,
        format,
        title: report_req.title.clone(),
        period_start,
        period_end,
        incident_id: report_req.incident_id.clone(),
        generated_by: HANDLER_NAME.to_string(),
    };

    log::info!("Generating report with request: {:?}", request);

    // Generate the report
    let report = match report_service.generate_report(request).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to generate report: {:?}", e);
            return Err(e);
        }
    };

    log::info!("Report generated successfully: {}", report.report_id);

    // Save the report to the database
    let report_repo = ReportRepository::new(db.get_ref().clone());
    let saved_report = report_repo.insert(report).await?;

    log::info!("Report saved to database with ID: {:?}", saved_report.id);

    Ok(web::Json(saved_report))
}

/// Get a report by ID
pub async fn get_report_by_id(
    db: web::Data<Database>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let report_repo = ReportRepository::new(db.get_ref().clone());

    let id = path.into_inner();
    let report = report_repo.find_by_id(&id).await?;

    Ok(web::Json(report))
}

/// Download a report
pub async fn download_report(
    db: web::Data<Database>,
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let report_repo = ReportRepository::new(db.get_ref().clone());

    let id = path.into_inner();
    let report = report_repo.find_by_id(&id).await?;

    // Get the file path
    let file_path = report.file_path.ok_or_else(|| AppError::NotFoundError("Report file not found".to_string()))?;

    // Check if the file exists
    if !Path::new(&file_path).exists() {
        return Err(AppError::NotFoundError("Report file not found".to_string()));
    }

    // Read the file
    let file_content = std::fs::read(&file_path)
        .map_err(|e| AppError::IoError(e))?;

    // Determine content type based on format
    let content_type = match report.format {
        ReportFormat::PDF => "application/pdf",
        ReportFormat::CSV => "text/csv",
        ReportFormat::JSON => "application/json",
        ReportFormat::HTML => "text/html",
    };

    // Create a filename for download
    let filename = Path::new(&file_path).file_name()
        .and_then(|os_str| os_str.to_str())
        .unwrap_or("report");

    // Return the file
    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .append_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(file_content))
}

/// File system report info
#[derive(Debug, Serialize)]
pub struct FsReportInfo {
    pub file_name: String,
    pub file_path: String,
    pub report_type: String,
    pub format: String,
    pub generated_at: String,
    pub file_size: u64,
}

/// Get reports from filesystem
pub async fn get_fs_reports() -> Result<impl Responder, AppError> {
    // Get the same reports directory path
    let reports_dir = match dirs::home_dir() {
        Some(home) => {
            let reports_path = home.join("NeuroDefender").join("reports");
            reports_path.to_string_lossy().to_string()
        }
        None => {
            let cwd = std::env::current_dir()
                .map_err(|e| AppError::IoError(e))?;
            let reports_path = cwd.join("neurodefender_reports");
            reports_path.to_string_lossy().to_string()
        }
    };

    let mut fs_reports = Vec::new();
    
    // Check if directory exists
    let reports_path = Path::new(&reports_dir);
    if !reports_path.exists() {
        log::info!("Reports directory does not exist: {}", reports_dir);
        return Ok(web::Json(fs_reports));
    }

    // Read directory contents
    let entries = fs::read_dir(reports_path)
        .map_err(|e| AppError::IoError(e))?;

    for entry in entries {
        let entry = entry.map_err(|e| AppError::IoError(e))?;
        let path = entry.path();
        
        if path.is_file() {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                // Parse report info from filename (format: RPT-{id}_{start}_{end}.{ext})
                let parts: Vec<&str> = file_name.split('_').collect();
                
                let report_type = if file_name.contains("daily") || file_name.contains("Daily") {
                    "daily"
                } else if file_name.contains("weekly") || file_name.contains("Weekly") {
                    "weekly"
                } else if file_name.contains("monthly") || file_name.contains("Monthly") {
                    "monthly"
                } else if file_name.contains("incident") || file_name.contains("Incident") {
                    "incident"
                } else {
                    "custom"
                }.to_string();

                let format = path.extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Get file metadata
                let metadata = entry.metadata().map_err(|e| AppError::IoError(e))?;
                let file_size = metadata.len();
                
                // Get modification time as generated time
                let generated_at = metadata.modified()
                    .map(|time| {
                        let datetime: DateTime<Utc> = time.into();
                        datetime.to_rfc3339()
                    })
                    .unwrap_or_else(|_| Utc::now().to_rfc3339());

                fs_reports.push(FsReportInfo {
                    file_name: file_name.to_string(),
                    file_path: path.to_string_lossy().to_string(),
                    report_type,
                    format,
                    generated_at,
                    file_size,
                });
            }
        }
    }

    // Sort by modification time (newest first)
    fs_reports.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));

    log::info!("Found {} filesystem reports", fs_reports.len());
    Ok(web::Json(fs_reports))
}

/// Serve HTML report with enhanced styling
pub async fn serve_html_report(
    path: web::Path<String>,
) -> Result<impl Responder, AppError> {
    let file_name = path.into_inner();
    
    // Get the reports directory
    let reports_dir = match dirs::home_dir() {
        Some(home) => {
            let reports_path = home.join("NeuroDefender").join("reports");
            reports_path.to_string_lossy().to_string()
        }
        None => {
            let cwd = std::env::current_dir()
                .map_err(|e| AppError::IoError(e))?;
            let reports_path = cwd.join("neurodefender_reports");
            reports_path.to_string_lossy().to_string()
        }
    };

    let file_path = format!("{}/{}", reports_dir, file_name);
    let path_obj = Path::new(&file_path);

    // Security check - ensure file is in reports directory
    if !path_obj.starts_with(&reports_dir) {
        return Err(AppError::ValidationError("Invalid file path".to_string()));
    }

    // Check if file exists and is HTML
    if !path_obj.exists() {
        return Err(AppError::NotFoundError("Report file not found".to_string()));
    }

    if path_obj.extension().and_then(|ext| ext.to_str()) != Some("html") {
        return Err(AppError::ValidationError("File is not an HTML report".to_string()));
    }

    // Read the HTML file
    let html_content = fs::read_to_string(&file_path)
        .map_err(|e| AppError::IoError(e))?;

    // Enhance the HTML with better styling
    let enhanced_html = enhance_html_styling(&html_content);

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(enhanced_html))
}

/// Enhance HTML report with better styling matching the project design
fn enhance_html_styling(original_html: &str) -> String {
    // Modern CSS that matches the project's design language
    let enhanced_style = r#"
    <style>
        /* Reset and base styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            line-height: 1.6;
            color: #2c3e50;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        /* Main container */
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        /* Header section */
        .report-header {
            background: linear-gradient(135deg, #4a90e2 0%, #357abd 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .report-header h1 {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .report-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
        }

        .meta-item {
            text-align: center;
        }

        .meta-label {
            font-size: 0.9em;
            opacity: 0.8;
            margin-bottom: 5px;
        }

        .meta-value {
            font-size: 1.1em;
            font-weight: 600;
        }

        /* Content section */
        .report-content {
            padding: 40px;
        }

        h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 3px solid #4a90e2;
            position: relative;
        }

        h2::after {
            content: '';
            position: absolute;
            bottom: -3px;
            left: 0;
            width: 50px;
            height: 3px;
            background: #e74c3c;
        }

        h3 {
            color: #34495e;
            font-size: 1.4em;
            margin: 25px 0 15px 0;
        }

        /* Statistics cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .stat-card {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px;
            border-radius: 12px;
            border-left: 4px solid #4a90e2;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }

        .stat-value {
            font-size: 2em;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Enhanced table styles */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
        }

        thead {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
        }

        th {
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.85em;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
            transition: background-color 0.3s ease;
        }

        tbody tr:hover {
            background-color: #f8f9fa;
        }

        tbody tr:nth-child(even) {
            background-color: #fdfdfd;
        }

        /* Severity indicators */
        .severity-high { 
            color: #e74c3c; 
            font-weight: 600;
        }
        .severity-medium { 
            color: #f39c12; 
            font-weight: 600;
        }
        .severity-low { 
            color: #27ae60; 
            font-weight: 600;
        }

        /* Status indicators */
        .status-resolved { 
            color: #27ae60; 
            background: #d5f4e6;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status-new { 
            color: #e74c3c; 
            background: #ffeaea;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status-inprogress { 
            color: #f39c12; 
            background: #fff4e6;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }

        /* Responsive design */
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .report-header {
                padding: 20px;
            }
            
            .report-header h1 {
                font-size: 2em;
            }
            
            .report-content {
                padding: 20px;
            }
            
            .report-meta {
                grid-template-columns: 1fr;
            }
            
            table {
                font-size: 0.9em;
            }
            
            th, td {
                padding: 8px 6px;
            }
        }

        /* Print styles */
        @media print {
            body {
                background: white !important;
                padding: 0;
            }
            
            .report-container {
                box-shadow: none;
                border-radius: 0;
            }
            
            .report-header {
                background: #4a90e2 !important;
                -webkit-print-color-adjust: exact;
                color-adjust: exact;
            }
        }
    </style>
    "#;

    // If the HTML already has a proper structure, enhance it
    if original_html.contains("<body>") {
        // Replace the existing style section or add enhanced styling
        let style_start = original_html.find("<style>");
        let style_end = original_html.find("</style>");
        
        if let (Some(start), Some(end)) = (style_start, style_end) {
            // Replace existing styles
            let before_style = &original_html[..start];
            let after_style = &original_html[end + 8..]; // +8 for "</style>"
            
            // Wrap content in proper structure
            let wrapped_content = wrap_in_enhanced_structure(&original_html);
            format!("{}{}{}", before_style, enhanced_style, wrapped_content)
        } else {
            // Add enhanced style to head
            original_html.replace("<head>", &format!("<head>{}", enhanced_style))
        }
    } else {
        // Create a complete HTML structure if it doesn't exist
        wrap_in_enhanced_structure(original_html)
    }
}

/// Wrap content in enhanced HTML structure
fn wrap_in_enhanced_structure(content: &str) -> String {
    // Extract the body content if it exists
    let body_content = if let (Some(start), Some(end)) = (content.find("<body>"), content.find("</body>")) {
        &content[start + 6..end]
    } else {
        content
    };

    // Create enhanced structure
    format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NeuroDefender Security Report</title>
    {}
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1>🛡️ NeuroDefender Security Report</h1>
            <div class="report-meta">
                <div class="meta-item">
                    <div class="meta-label">Generated</div>
                    <div class="meta-value">{}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">System</div>
                    <div class="meta-value">NeuroDefender IDPS</div>
                </div>
            </div>
        </div>
        <div class="report-content">
            {}
        </div>
    </div>
</body>
</html>
"#, 
        r#"<style>/* Enhanced styles will be inserted here */</style>"#,
        Utc::now().format("%Y-%m-%d %H:%M UTC"),
        body_content
    )
}