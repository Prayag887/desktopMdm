use std::{env, sync::Arc};

use argon2::{
    Argon2, PasswordHasher,
    password_hash::SaltString,
};
use axum::{
    Json, Router,
    extract::{Form, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Months, NaiveDate, Utc};
use emi_core::{BiosProvider, DeviceCommand, DeviceHealth};
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{
    Row, SqlitePool,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
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
        .route("/devices/{id}/commands/pin", post(set_managed_pin))
        .route(
            "/devices/{id}/commands/clear-restrictions",
            post(clear_restrictions),
        )
        .route("/devices/{id}/management", post(set_management))
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
        "SELECT d.id, d.name, d.serial_number, d.last_seen_at, d.management_enabled, COUNT(p.id) periods, SUM(CASE WHEN p.paid_at IS NOT NULL THEN 1 ELSE 0 END) paid FROM devices d LEFT JOIN payment_periods p ON p.device_id=d.id GROUP BY d.id ORDER BY d.enrolled_at DESC"
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
        let managed: bool = row.get("management_enabled");
        let mode = if managed { "Managed" } else { "Maintenance" };
        write!(body, "<tr><td><a class=\"device-link\" href=\"/devices/{id}\">{}</a></td><td class=\"mono\">{}</td><td><span class=\"pill {}\">{mode}</span></td><td>{paid}/{periods}</td><td>{}</td></tr>", escape(&name), escape(&serial), if managed { "good" } else { "warn" }, escape(seen.as_deref().unwrap_or("never"))).expect("writing to String cannot fail");
    }
    Html(layout("EMI devices", &format!("<header class=\"page-header\"><div><span class=\"eyebrow\">Fleet console</span><h1>EMI Device Control</h1><p>Payments, device health, and audited management controls.</p></div><div class=\"header-stat\"><strong>Secure admin</strong><span>Authenticated session</span></div></header><main><section><div class=\"section-title\"><div><h2>Enrolled devices</h2><p>Select a device to review health and controls.</p></div></div><div class=\"table-wrap\"><table><thead><tr><th>Device</th><th>Serial</th><th>Mode</th><th>Paid</th><th>Last seen</th></tr></thead><tbody>{body}</tbody></table></div></section></main>"))).into_response()
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
        "SELECT name, serial_number, last_seen_at, health_json, management_enabled FROM devices WHERE id=?",
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
    let commands = match sqlx::query("SELECT kind, created_at, completed_at, result FROM commands WHERE device_id=? ORDER BY created_at DESC LIMIT 8")
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
    let management_enabled: bool = device.get("management_enabled");
    let last_seen: Option<String> = device.get("last_seen_at");
    let health: Option<String> = device.get("health_json");
    let health_panel = render_health(health.as_deref(), last_seen.as_deref());
    let command_history = render_commands(commands);
    let mode_label = if management_enabled {
        "Managed"
    } else {
        "Maintenance"
    };
    let next_mode = !management_enabled;
    let mode_action = if management_enabled {
        "Enter maintenance"
    } else {
        "Enable managed mode"
    };
    let content = format!(
        "<nav><a href=\"/\">← All devices</a><span>Device console</span></nav><header class=\"device-hero\"><div><span class=\"eyebrow\">Windows endpoint</span><h1>{}</h1><p class=\"mono\">Serial {}</p></div><div><span class=\"pill {} large\">{mode_label}</span><p>Last seen {}</p></div></header><main><div id=\"notice\"></div>{health_panel}<section><div class=\"section-title\"><div><h2>Remote controls</h2><p>Commands are queued, audited, and acknowledged by the Windows service.</p></div></div><div class=\"control-grid\"><article><span class=\"control-icon\">↗</span><h3>Payment reminder</h3><p>Display a payment notice in the active Windows session.</p><button hx-post=\"/devices/{id}/commands/remind\" hx-target=\"#notice\">Send reminder</button></article><article><span class=\"control-icon\">••</span><h3>Managed lock PIN</h3><p>Set the app restriction PIN. This never changes a Windows account password.</p><form class=\"stack\" hx-post=\"/devices/{id}/commands/pin\" hx-target=\"#notice\"><input name=\"pin\" type=\"password\" inputmode=\"numeric\" minlength=\"4\" maxlength=\"12\" placeholder=\"4–12 digit PIN\" required><input name=\"confirm_pin\" type=\"password\" inputmode=\"numeric\" minlength=\"4\" maxlength=\"12\" placeholder=\"Confirm PIN\" required><button>Queue PIN update</button></form></article><article><span class=\"control-icon\">⚙</span><h3>Management mode</h3><p>Managed mode applies policy. Maintenance mode clears restrictions while keeping health and recovery online.</p><form hx-post=\"/devices/{id}/management\" hx-target=\"#notice\"><input type=\"hidden\" name=\"enabled\" value=\"{next_mode}\"><button class=\"secondary\">{mode_action}</button></form></article><article><span class=\"control-icon\">○</span><h3>Clear restrictions</h3><p>Remove the managed PIN and local restrictions without uninstalling the recovery agent.</p><button class=\"danger\" hx-post=\"/devices/{id}/commands/clear-restrictions\" hx-target=\"#notice\" hx-confirm=\"Clear managed restrictions on this device?\">Clear restrictions</button></article><article class=\"disabled-card\"><span class=\"control-icon\">BIOS</span><h3>Firmware password</h3><p>Requires an encrypted per-device secret and an approved Dell, HP, or Lenovo enterprise adapter.</p><button disabled>OEM adapter required</button></article></div></section><section><div class=\"section-title\"><div><h2>Payment plan</h2><p>Installment schedule and payment state.</p></div></div><form class=\"plan-form\" method=\"post\" action=\"/devices/{id}/plans\"><input name=\"amount\" inputmode=\"decimal\" placeholder=\"Amount e.g. 2500.00\" required><input name=\"currency\" value=\"NPR\" minlength=\"3\" maxlength=\"3\" required><input name=\"periods\" type=\"number\" min=\"1\" max=\"120\" placeholder=\"Periods\" required><input name=\"first_due\" type=\"date\" required><button>Create plan</button></form><div class=\"table-wrap\"><table><tr><th>#</th><th>Amount</th><th>Due</th><th>Status</th></tr>{payments}</table></div></section><section><div class=\"section-title\"><div><h2>Recent commands</h2><p>Latest audited actions and device acknowledgements.</p></div></div>{command_history}</section></main>",
        escape(&name),
        escape(&serial),
        if management_enabled { "good" } else { "warn" },
        escape(last_seen.as_deref().unwrap_or("never")),
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
struct PinForm {
    pin: String,
    confirm_pin: String,
}

async fn set_managed_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<PinForm>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    if form.pin != form.confirm_pin
        || !(4..=12).contains(&form.pin.len())
        || !form.pin.bytes().all(|byte| byte.is_ascii_digit())
    {
        return (StatusCode::BAD_REQUEST, "PIN must be 4–12 matching digits").into_response();
    }
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
        .expect("a UUID is a valid password salt");
    let hash = match Argon2::default().hash_password(form.pin.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(error) => return internal(error),
    };
    match queue_command(
        &state.db,
        &id,
        DeviceCommand::SetManagedLockPin { pin_hash: hash },
        "admin",
    )
    .await
    {
        Ok(()) => Html(notice("Managed PIN update queued", "success")).into_response(),
        Err(error) => internal(error),
    }
}

async fn clear_restrictions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    match queue_command(
        &state.db,
        &id,
        DeviceCommand::ClearManagedRestrictions,
        "admin",
    )
    .await
    {
        Ok(()) => Html(notice("Restriction removal queued", "success")).into_response(),
        Err(error) => internal(error),
    }
}

#[derive(Deserialize)]
struct ManagementForm {
    enabled: bool,
}

async fn set_management(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ManagementForm>,
) -> Response {
    if !is_admin(&state, &headers) {
        return unauthorized();
    }
    let command = DeviceCommand::SetManagementEnabled {
        enabled: form.enabled,
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => return internal(error),
    };
    let updated = match sqlx::query("UPDATE devices SET management_enabled=? WHERE id=?")
        .bind(form.enabled)
        .bind(&id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => result.rows_affected(),
        Err(error) => return internal(error),
    };
    if updated != 1 {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(error) = insert_command(&mut tx, &id, &command).await {
        return internal(error);
    }
    if let Err(error) = audit(
        &mut tx,
        "admin",
        "management.mode_changed",
        &id,
        json!({"enabled": form.enabled}),
    )
    .await
    {
        return internal(error);
    }
    if let Err(error) = tx.commit().await {
        return internal(error);
    }
    Html(notice(
        if form.enabled {
            "Managed mode enabled"
        } else {
            "Maintenance mode enabled; restrictions are being cleared"
        },
        "success",
    ))
    .into_response()
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
    insert_command(&mut tx, device_id, &command).await?;
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

async fn insert_command(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device_id: &str,
    command: &DeviceCommand,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO commands(id,device_id,kind,payload_json,created_at) VALUES(?,?,?,?,?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(device_id)
    .bind(command_kind(&command))
    .bind(serde_json::to_string(command)?)
    .bind(Utc::now().to_rfc3339())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn command_kind(command: &DeviceCommand) -> &'static str {
    match command {
        DeviceCommand::ShowPaymentReminder { .. } => "show_payment_reminder",
        DeviceCommand::SetManagedLockPin { .. } => "set_managed_lock_pin",
        DeviceCommand::RotateBiosPassword { .. } => "rotate_bios_password",
        DeviceCommand::SetManagementEnabled { .. } => "set_management_enabled",
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
        .replace('\'', "&#39;")
}

fn render_health(raw: Option<&str>, last_seen: Option<&str>) -> String {
    let Some(health) = raw.and_then(|value| serde_json::from_str::<DeviceHealth>(value).ok())
    else {
        return "<section><div class=\"section-title\"><div><h2>Device health</h2><p>Live telemetry reported by the Windows service.</p></div></div><div class=\"empty\"><strong>Waiting for the first check-in</strong><span>Health data will appear after the agent contacts this server.</span></div></section>".into();
    };

    let disk_gib = health.disk_free_bytes as f64 / 1_073_741_824.0;
    let battery = health
        .battery_percent
        .map_or_else(|| "Not reported".into(), |value| format!("{value}%"));
    let secure_boot = match health.secure_boot {
        Some(true) => "Enabled",
        Some(false) => "Disabled",
        None => "Unknown",
    };
    let bios = match health.bios_provider {
        BiosProvider::Dell => "Dell detected",
        BiosProvider::Hp => "HP detected",
        BiosProvider::Lenovo => "Lenovo detected",
        BiosProvider::Unsupported => "Unsupported",
    };
    let mode = if health.management_enabled {
        "Managed"
    } else {
        "Maintenance"
    };
    let cards = vec![
        (
            "Connection",
            last_seen.unwrap_or("never").to_owned(),
            "Latest check-in".to_owned(),
        ),
        ("Host", health.hostname, health.os_version),
        (
            "Storage free",
            format!("{disk_gib:.1} GiB"),
            "Across local disks".to_owned(),
        ),
        ("Battery", battery, "Agent reading".to_owned()),
        (
            "Secure Boot",
            secure_boot.to_owned(),
            "Firmware security".to_owned(),
        ),
        (
            "WinGet",
            if health.winget_available {
                "Available".to_owned()
            } else {
                "Unavailable".to_owned()
            },
            "Package bootstrap".to_owned(),
        ),
        (
            "BIOS provider",
            bios.to_owned(),
            "Firmware adapter status".to_owned(),
        ),
        ("Agent", health.agent_version, mode.to_owned()),
    ];
    let mut metrics = String::new();
    for (label, value, detail) in cards {
        write!(
            metrics,
            "<article class=\"metric\"><span>{}</span><strong>{}</strong><small>{}</small></article>",
            escape(label),
            escape(&value),
            escape(&detail)
        )
        .expect("writing to String cannot fail");
    }
    format!(
        "<section><div class=\"section-title\"><div><h2>Device health</h2><p>Live telemetry reported by the Windows service.</p></div><span class=\"pill good\">Reporting</span></div><div class=\"health-grid\">{metrics}</div></section>"
    )
}

fn render_commands(commands: Vec<SqliteRow>) -> String {
    if commands.is_empty() {
        return "<div class=\"empty\"><strong>No commands yet</strong><span>Remote actions will appear here with their completion result.</span></div>".into();
    }
    let mut rows = String::new();
    for row in commands {
        let kind: String = row.get("kind");
        let created: String = row.get("created_at");
        let completed: Option<String> = row.get("completed_at");
        let result: Option<String> = row.get("result");
        let label = match kind.as_str() {
            "show_payment_reminder" => "Payment reminder",
            "set_managed_lock_pin" => "Managed PIN update",
            "set_management_enabled" => "Management mode",
            "clear_managed_restrictions" => "Clear restrictions",
            "rotate_bios_password" => "Firmware password",
            _ => kind.as_str(),
        };
        let (status, class) = if completed.is_some() {
            ("Completed", "good")
        } else {
            ("Queued", "warn")
        };
        write!(
            rows,
            "<tr><td><strong>{}</strong><small class=\"table-detail\">{}</small></td><td><span class=\"pill {}\">{status}</span></td><td>{}</td></tr>",
            escape(label),
            escape(result.as_deref().unwrap_or("Waiting for device acknowledgement")),
            class,
            escape(&created)
        )
        .expect("writing to String cannot fail");
    }
    format!(
        "<div class=\"table-wrap\"><table><thead><tr><th>Action</th><th>Status</th><th>Queued at</th></tr></thead><tbody>{rows}</tbody></table></div>"
    )
}

fn notice(message: &str, kind: &str) -> String {
    format!(
        "<span class=\"notice {}\">{}</span>",
        escape(kind),
        escape(message)
    )
}

fn layout(title: &str, content: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title><script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.7/dist/htmx.min.js" integrity="sha384-ZBXiYtYQ6hJ2Y0ZNoYuI+Nq5MqWBr+chMrS/RkXpNzQCApHEhOt2aY8EJgqwHLkJ" crossorigin="anonymous"></script><style>{}</style></head><body>{content}</body></html>"#,
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
