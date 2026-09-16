use std::{env, sync::Arc};

use axum::{
    Json, Router,
    extract::{Form, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Months, NaiveDate, Utc};
use emi_core::{DeviceCommand, DeviceHealth};
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{fmt::Write as _, str::FromStr};
use tower_http::{compression::CompressionLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    db: SqlitePool,
    admin_password: Arc<str>,
    enrollment_key: Arc<str>,
}

impl AppState {
    /// Opens the SQLite store and applies embedded migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrated.
    pub async fn connect(
        database_url: &str,
        admin_password: String,
        enrollment_key: String,
    ) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5));
        let db = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&db).await?;
        Ok(Self {
            db,
            admin_password: admin_password.into(),
            enrollment_key: enrollment_key.into(),
        })
    }
}

/// Builds application state from `DATABASE_URL`, `ADMIN_PASSWORD`, and `ENROLLMENT_KEY`.
///
/// # Errors
///
/// Returns an error when required environment variables are absent or storage setup fails.
pub async fn state_from_env() -> anyhow::Result<AppState> {
    AppState::connect(
        &env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://emi-mdm.db?mode=rwc".into()),
        env::var("ADMIN_PASSWORD").map_err(|_| anyhow::anyhow!("ADMIN_PASSWORD is required"))?,
        env::var("ENROLLMENT_KEY").map_err(|_| anyhow::anyhow!("ENROLLMENT_KEY is required"))?,
    )
    .await
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/", get(dashboard))
        .route("/devices/{id}", get(device_detail))
        .route("/devices/{id}/plans", post(create_plan))
        .route("/devices/{id}/payments/{sequence}/paid", post(mark_paid))
        .route("/devices/{id}/commands/remind", post(send_reminder))
        .route("/api/v1/enroll", post(enroll))
        .route("/api/v1/devices/{id}/health", post(report_health))
        .route("/api/v1/devices/{id}/commands", get(poll_commands))
        .route(
            "/api/v1/devices/{id}/commands/{command_id}/complete",
            post(complete_command),
        )
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    let rows = match sqlx::query(
        "SELECT d.id, d.name, d.serial_number, d.last_seen_at, COUNT(p.id) periods, SUM(CASE WHEN p.paid_at IS NOT NULL THEN 1 ELSE 0 END) paid FROM devices d LEFT JOIN payment_periods p ON p.device_id=d.id GROUP BY d.id ORDER BY d.enrolled_at DESC"
    ).fetch_all(&state.db).await {
        Ok(rows) => rows,
        Err(error) => return internal(error),
    };
    let mut body = String::new();
    for row in rows {
        let id: String = row.get("id");
        let name: String = row.get("name");
        let serial: String = row.get("serial_number");
        let seen: Option<String> = row.get("last_seen_at");
        let periods: i64 = row.get("periods");
        let paid: i64 = row.get("paid");
        write!(body, "<tr><td><a href=\"/devices/{id}\">{}</a></td><td>{}</td><td>{paid}/{periods}</td><td>{}</td></tr>", escape(&name), escape(&serial), escape(seen.as_deref().unwrap_or("never"))).expect("writing to String cannot fail");
    }
    Html(layout("EMI devices", &format!("<header><h1>EMI Device Control</h1><p>Payment status and enrolled device health</p></header><main><table><thead><tr><th>Device</th><th>Serial</th><th>Paid</th><th>Last seen</th></tr></thead><tbody>{body}</tbody></table></main>"))).into_response()
}

async fn device_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    let device = match sqlx::query(
        "SELECT name, serial_number, last_seen_at, health_json FROM devices WHERE id=?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return internal(error),
    };
    let periods = match sqlx::query("SELECT sequence, amount_minor, currency, due_on, paid_at FROM payment_periods WHERE device_id=? ORDER BY sequence")
        .bind(&id).fetch_all(&state.db).await { Ok(rows) => rows, Err(error) => return internal(error) };
    let mut payments = String::new();
    for row in periods {
        let sequence: i64 = row.get("sequence");
        let amount: i64 = row.get("amount_minor");
        let currency: String = row.get("currency");
        let due: String = row.get("due_on");
        let paid: Option<String> = row.get("paid_at");
        let action = if paid.is_some() {
            "Paid".into()
        } else {
            format!(
                "<button hx-post=\"/devices/{id}/payments/{sequence}/paid\" hx-target=\"closest tr\" hx-swap=\"outerHTML\">Mark paid</button>"
            )
        };
        let major = amount / 100;
        let minor = amount.unsigned_abs() % 100;
        write!(payments, "<tr><td>{sequence}</td><td>{major}.{minor:02} {currency}</td><td>{due}</td><td>{action}</td></tr>").expect("writing to String cannot fail");
    }
    let name: String = device.get("name");
    let serial: String = device.get("serial_number");
    let health: Option<String> = device.get("health_json");
    let content = format!(
        "<header><a href=\"/\">← Devices</a><h1>{}</h1><p>Serial: {}</p></header><main><section><h2>Payments</h2><form method=\"post\" action=\"/devices/{id}/plans\"><input name=\"amount\" inputmode=\"decimal\" placeholder=\"Amount e.g. 2500.00\" required><input name=\"currency\" value=\"NPR\" minlength=\"3\" maxlength=\"3\" required><input name=\"periods\" type=\"number\" min=\"1\" max=\"120\" placeholder=\"Periods\" required><input name=\"first_due\" type=\"date\" required><button>Create plan</button></form><table><tr><th>#</th><th>Amount</th><th>Due</th><th>Status</th></tr>{payments}</table><button hx-post=\"/devices/{id}/commands/remind\" hx-target=\"#notice\">Send payment reminder</button><span id=\"notice\"></span></section><section><h2>Latest health</h2><pre>{}</pre></section></main>",
        escape(&name),
        escape(&serial),
        escape(health.as_deref().unwrap_or("No report received"))
    );
    Html(layout("Device", &content)).into_response()
}

#[derive(Deserialize)]
struct PlanForm {
    amount: String,
    currency: String,
    periods: u16,
    first_due: String,
}

async fn create_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<PlanForm>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    let Ok(amount) = rust_decimal::Decimal::from_str_exact(&form.amount) else {
        return (StatusCode::BAD_REQUEST, "invalid amount").into_response();
    };
    if amount.scale() > 2 {
        return (
            StatusCode::BAD_REQUEST,
            "amount must have at most two decimals",
        )
            .into_response();
    }
    let Some(amount_minor) = (amount * rust_decimal::Decimal::new(100, 0)).to_i64() else {
        return (
            StatusCode::BAD_REQUEST,
            "amount must have at most two decimals",
        )
            .into_response();
    };
    let currency = form.currency.trim().to_uppercase();
    let Ok(first_due) = NaiveDate::from_str(&form.first_due) else {
        return (StatusCode::BAD_REQUEST, "invalid first due date").into_response();
    };
    if amount_minor <= 0
        || form.periods == 0
        || form.periods > 120
        || currency.len() != 3
        || !currency.chars().all(|c| c.is_ascii_alphabetic())
    {
        return (StatusCode::BAD_REQUEST, "invalid plan").into_response();
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => return internal(error),
    };
    for offset in 0..form.periods {
        let Some(due) = first_due.checked_add_months(Months::new(u32::from(offset))) else {
            return (StatusCode::BAD_REQUEST, "due date overflow").into_response();
        };
        if let Err(error) = sqlx::query("INSERT INTO payment_periods(device_id,sequence,amount_minor,currency,due_on) VALUES(?,?,?,?,?)")
            .bind(&id).bind(i64::from(offset) + 1).bind(amount_minor).bind(&currency).bind(due.to_string()).execute(&mut *tx).await {
            tracing::warn!(%error, "plan creation rejected");
            return (StatusCode::CONFLICT, "device already has a plan").into_response();
        }
    }
    if let Err(error) = audit(
        &mut tx,
        "admin",
        "plan.created",
        &id,
        json!({"periods": form.periods, "amount_minor": amount_minor, "currency": currency}),
    )
    .await
    {
        return internal(error);
    }
    if let Err(error) = tx.commit().await {
        return internal(error);
    }
    axum::response::Redirect::to(&format!("/devices/{id}")).into_response()
}

async fn mark_paid(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, sequence)): Path<(String, i64)>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    let now = Utc::now().to_rfc3339();
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => return internal(error),
    };
    let result = sqlx::query(
        "UPDATE payment_periods SET paid_at=? WHERE device_id=? AND sequence=? AND paid_at IS NULL",
    )
    .bind(&now)
    .bind(&id)
    .bind(sequence)
    .execute(&mut *tx)
    .await;
    match result {
        Ok(done) if done.rows_affected() == 1 => {
            if let Err(error) = audit(
                &mut tx,
                "admin",
                "payment.marked_paid",
                &id,
                json!({"sequence": sequence}),
            )
            .await
            {
                return internal(error);
            }
            if let Err(error) = tx.commit().await {
                return internal(error);
            }
            Html(format!(
                "<tr><td>{sequence}</td><td colspan=\"2\">Payment recorded</td><td>Paid</td></tr>"
            ))
            .into_response()
        }
        Ok(_) => StatusCode::CONFLICT.into_response(),
        Err(error) => internal(error),
    }
}

async fn send_reminder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    let command = DeviceCommand::ShowPaymentReminder { title: "Payment reminder".into(), message: "Your EMI payment is due. Please contact the financing administrator if you have already paid.".into() };
    match queue_command(&state.db, &id, command, "admin").await {
        Ok(()) => Html("Reminder queued".to_owned()).into_response(),
        Err(error) => internal(error),
    }
}

#[derive(Deserialize)]
struct EnrollRequest {
    enrollment_key: String,
    name: String,
    serial_number: String,
}
#[derive(Serialize)]
struct EnrollResponse {
    device_id: Uuid,
    agent_token: String,
}

async fn enroll(State(state): State<AppState>, Json(request): Json<EnrollRequest>) -> Response {
    if request.enrollment_key != state.enrollment_key.as_ref()
        || request.name.trim().is_empty()
        || request.serial_number.trim().is_empty()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let id = Uuid::new_v4();
    let token = Uuid::new_v4().to_string();
    match sqlx::query(
        "INSERT INTO devices(id,name,serial_number,agent_token,enrolled_at) VALUES(?,?,?,?,?)",
    )
    .bind(id.to_string())
    .bind(request.name.trim())
    .bind(request.serial_number.trim())
    .bind(&token)
    .bind(Utc::now().to_rfc3339())
    .execute(&state.db)
    .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            Json(EnrollResponse {
                device_id: id,
                agent_token: token,
            }),
        )
            .into_response(),
        Err(_) => (StatusCode::CONFLICT, "serial number is already enrolled").into_response(),
    }
}

async fn report_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(health): Json<DeviceHealth>,
) -> Response {
    if !is_agent(&state, &headers, &id).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if health.device_id.to_string() != id {
        return (StatusCode::BAD_REQUEST, "device id mismatch").into_response();
    }
    match sqlx::query("UPDATE devices SET health_json=?, last_seen_at=? WHERE id=?")
        .bind(serde_json::to_string(&health).unwrap_or_default())
        .bind(Utc::now().to_rfc3339())
        .bind(id)
        .execute(&state.db)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => internal(error),
    }
}

#[derive(Serialize)]
struct QueuedCommand {
    id: String,
    command: DeviceCommand,
}

async fn poll_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !is_agent(&state, &headers, &id).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let rows = match sqlx::query("SELECT id, payload_json FROM commands WHERE device_id=? AND completed_at IS NULL ORDER BY created_at LIMIT 20").bind(&id).fetch_all(&state.db).await { Ok(rows) => rows, Err(error) => return internal(error) };
    let commands: Vec<QueuedCommand> = rows
        .into_iter()
        .filter_map(|row| {
            serde_json::from_str(row.get::<&str, _>("payload_json"))
                .ok()
                .map(|command| QueuedCommand {
                    id: row.get("id"),
                    command,
                })
        })
        .collect();
    Json(commands).into_response()
}

#[derive(Deserialize)]
struct Completion {
    result: String,
}
async fn complete_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, command_id)): Path<(String, String)>,
    Json(done): Json<Completion>,
) -> Response {
    if !is_agent(&state, &headers, &id).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match sqlx::query("UPDATE commands SET completed_at=?, result=? WHERE id=? AND device_id=? AND completed_at IS NULL")
        .bind(Utc::now().to_rfc3339()).bind(done.result.chars().take(1000).collect::<String>()).bind(command_id).bind(id).execute(&state.db).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(), Err(error) => internal(error)
    }
}

async fn queue_command(
    db: &SqlitePool,
    device_id: &str,
    command: DeviceCommand,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO commands(id,device_id,kind,payload_json,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(device_id)
    .bind(command_kind(&command))
    .bind(serde_json::to_string(&command)?)
    .bind(Utc::now().to_rfc3339())
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        actor,
        "command.queued",
        device_id,
        json!({"kind": command_kind(&command)}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn command_kind(command: &DeviceCommand) -> &'static str {
    match command {
        DeviceCommand::ShowPaymentReminder { .. } => "show_payment_reminder",
        DeviceCommand::SetManagedLockPin { .. } => "set_managed_lock_pin",
        DeviceCommand::RotateBiosPassword { .. } => "rotate_bios_password",
        DeviceCommand::ClearManagedRestrictions => "clear_managed_restrictions",
    }
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    actor: &str,
    action: &str,
    subject: &str,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO audit_events(id,actor,action,subject_id,details_json,occurred_at) VALUES(?,?,?,?,?,?)")
        .bind(Uuid::new_v4().to_string()).bind(actor).bind(action).bind(subject).bind(details.to_string()).bind(Utc::now().to_rfc3339()).execute(&mut **tx).await?;
    Ok(())
}

async fn is_agent(state: &AppState, headers: &HeaderMap, id: &str) -> bool {
    let Some(token) = bearer(headers) else {
        return false;
    };
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM devices WHERE id=? AND agent_token=?")
        .bind(id)
        .bind(token)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0)
        == 1
}

fn is_admin(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(value) else {
        return false;
    };
    decoded == format!("admin:{}", state.admin_password).as_bytes()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", "Basic realm=\"EMI Control\"")],
        "Authentication required",
    )
        .into_response()
}
fn internal(error: impl std::fmt::Display) -> Response {
    tracing::error!(%error, "request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn layout(title: &str, content: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.7/dist/htmx.min.js" integrity="sha384-ZBXiYtYQ6hJ2Y0ZNoYuI+Nq5MqWBr+chMrS/RkXpE8ya5/DOCV5zOQF3WnLSL7Z" crossorigin="anonymous"></script><style>{}</style></head><body>{content}</body></html>"#,
        include_str!("style.css")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_is_public_but_dashboard_is_protected() {
        let state = AppState::connect("sqlite::memory:", "secret".into(), "enroll".into())
            .await
            .unwrap();
        let app = app(state);
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/healthz")
                        .body(Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
