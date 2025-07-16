//! A lightweight HTTP server to expose CLI statistics.

use crate::orchestrator::{
    DUPLICATE_TASKS_FETCHED, FAILED_SUBMISSIONS, SUCCESSFUL_SUBMISSIONS, TOTAL_TASKS_FETCHED,
    UNIQUE_TASKS_FETCHED,
};
use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

#[derive(Serialize)]
struct StatsResponse {
    successful_submissions: usize,
    failed_submissions: usize,
    total_tasks_fetched: usize,
    duplicate_tasks_fetched: usize,
    unique_tasks_fetched: usize,
}

async fn get_stats() -> Json<StatsResponse> {
    let stats = StatsResponse {
        successful_submissions: SUCCESSFUL_SUBMISSIONS.load(Ordering::SeqCst),
        failed_submissions: FAILED_SUBMISSIONS.load(Ordering::SeqCst),
        total_tasks_fetched: TOTAL_TASKS_FETCHED.load(Ordering::SeqCst),
        duplicate_tasks_fetched: DUPLICATE_TASKS_FETCHED.load(Ordering::SeqCst),
        unique_tasks_fetched: UNIQUE_TASKS_FETCHED.load(Ordering::SeqCst),
    };
    Json(stats)
}

pub async fn run_stats_server() {
    let app = Router::new().route("/stats", get(get_stats));

    let addr = SocketAddr::from(([127, 0, 0, 1], 38080));
    println!("[统计服务] 正在监听于 http://{}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("[统计服务] 无法绑定到地址 {}: {}", addr, e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app.into_make_service()).await {
        eprintln!("[统计服务] 服务器错误: {}", e);
    }
} 