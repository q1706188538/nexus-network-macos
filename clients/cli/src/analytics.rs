use crate::environment::Environment;
use crate::system::{estimate_peak_gflops, measure_gflops, num_cores};
use chrono::Datelike;
use chrono::Timelike;
use reqwest::header::ACCEPT;
use serde_json::{Value, json};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};
use std::time::Duration;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

#[derive(Debug, thiserror::Error)]
pub enum TrackError {
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    #[error("event_properties is not a valid JSON object")]
    InvalidEventProperties,

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Non-successful response: {status} - {body}")]
    FailedResponse {
        status: reqwest::StatusCode,
        body: String,
    },
}

pub const STAGING_MEASUREMENT_ID: &str = "G-T0M0Q3V6WN";
pub const BETA_MEASUREMENT_ID: &str = "G-GLH0GMEEFH";
pub const STAGING_API_SECRET: &str = "OI7H53soRMSDWfJf1ittHQ";
pub const BETA_API_SECRET: &str = "3wxu8FjVSPqOlxSsZEnBOw";

pub fn analytics_id(environment: &Environment) -> String {
    match environment {
        Environment::Staging => STAGING_MEASUREMENT_ID.to_string(),
        Environment::Beta => BETA_MEASUREMENT_ID.to_string(),
        Environment::Local => String::new(),
    }
}

pub fn analytics_api_key(environment: &Environment) -> String {
    match environment {
        Environment::Staging => STAGING_API_SECRET.to_string(),
        Environment::Beta => BETA_API_SECRET.to_string(),
        Environment::Local => String::new(),
    }
}

/// Track an event with the Firebase Measurement Protocol
///
/// # Arguments
/// * `event_name` - The name of the event to track.
/// * `event_properties` - A JSON object containing properties of the event.
/// * `environment` - The environment in which the application is running.
/// * `client_id` - A unique identifier for the client, typically a UUID or similar.
pub async fn track(
    event_name: String,
    properties: Value,
    environment: &Environment,
    client_id: String,
    proxy_url: &Option<String>,
    proxy_user_pwd: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let api_key = match environment {
        Environment::Dev => return Ok(()), // Do not send analytics in dev
        Environment::Staging => return Ok(()), // Do not send analytics in staging
        Environment::Beta => "m99QWAbAh4S63u0I2wsY1y4G5zKz26Ab",
        Environment::Prod => "m99QWAbAh4S63u0I2wsY1y4G5zKz26Ab",
    };

    let mut client_builder = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .no_proxy();

    if let (Some(url), Some(user_pwd)) = (proxy_url.clone(), proxy_user_pwd.clone()) {
        if !url.is_empty() {
            let proxy_str = crate::orchestrator::client::OrchestratorClient::generate_proxy_url(&url, &user_pwd);
            let proxy = reqwest::Proxy::all(proxy_str).expect("Failed to create proxy for analytics");
            client_builder = client_builder.proxy(proxy);
        }
    }

    let client = client_builder.build()?;

    let analytics_id = analytics_id(environment);
    let analytics_api_key = analytics_api_key(environment);
    if analytics_id.is_empty() {
        return Ok(());
    }
    let local_now = chrono::offset::Local::now();

    // For tracking events, we use the Firebase Measurement Protocol
    // Firebase is mostly designed for mobile and web apps, but for our use case of a CLI,
    // we can use the Measurement Protocol to track events by POST to a URL.
    // The only thing that may be unexpected is that the URL we use includes a firebase key

    // Firebase format for properties for Measurement protocol:
    // https://developers.google.com/analytics/devguides/collection/protocol/ga4/reference?client_type=firebase#payload
    // https://developers.google.com/analytics/devguides/collection/protocol/ga4/reference?client_type=firebase#payload_query_parameters

    let system_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let timezone = iana_time_zone::get_timezone().ok().map_or_else(
        || String::from("UTC"), // fallback to UTC
        |tz| tz,
    );

    let mut properties = json!({
        "time": system_time,
        "platform": "CLI",
        "os": env::consts::OS,
        "os_version": env::consts::OS,  // We could get more specific version if needed
        "app_version": env!("CARGO_PKG_VERSION"),
        "timezone": timezone,
        "local_hour": local_now.hour(),
        "day_of_week": local_now.weekday().number_from_monday(),
        "event_id": system_time,
        "measured_flops": measure_gflops(),
        "num_cores": num_cores(),
        "peak_flops": estimate_peak_gflops(num_cores()),
    });

    // Add event properties to the properties JSON
    // This is done by iterating over the key-value pairs in the event_properties JSON object
    // but checking that it is a valid JSON object first
    if let Some(obj) = properties.as_object() {
        for (k, v) in obj {
            properties[k] = v.clone();
        }
    } else {
        return Err(Box::new(TrackError::InvalidEventProperties));
    }

    // Format for events
    let body = json!({
        "client_id": client_id,
        "events": [{
            "name": event_name,
            "params": properties
        }],
    });

    let url = format!(
        "https://www.google-analytics.com/mp/collect?measurement_id={}&api_secret={}",
        analytics_id, analytics_api_key
    );

    let response = client
        .post(&url)
        .json(&body)
        .header(ACCEPT, "application/json")
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await?;
        return Err(Box::new(TrackError::FailedResponse {
            status,
            body: body_text,
        }));
    }

    Ok(())
}
