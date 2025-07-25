// Copyright (c) 2024 Nexus. All rights reserved.

mod analytics;
mod config;
mod consts;
mod environment;
mod error_classifier;
mod events;
mod keys;
mod logging;
#[path = "proto/nexus.orchestrator.rs"]
mod nexus_orchestrator;
mod orchestrator;
mod pretty;
mod prover;
mod prover_runtime;
mod register;
pub mod system;
mod stats_server;
mod task;
mod task_cache;
mod ui;
mod version_checker;
mod workers;

use crate::config::{Config, get_config_path};
use crate::environment::Environment;
use crate::orchestrator::{Orchestrator, OrchestratorClient};
use crate::prover_runtime::start_authenticated_workers;
use crate::register::{register_node, register_user};
use clap::{ArgAction, Parser, Subcommand};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ed25519_dalek::SigningKey;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{error::Error, io};
use tokio::sync::broadcast;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
/// Command-line arguments
struct Args {
    /// Command to execute
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the prover
    Start {
        /// Node ID
        #[arg(long, value_name = "NODE_ID", num_args = 1..)]
        node_ids: Vec<u64>,

        /// Run without the terminal UI
        #[arg(long = "headless", action = ArgAction::SetTrue)]
        headless: bool,

        /// Maximum number of threads to use for proving.
        #[arg(long = "max-threads", value_name = "MAX_THREADS")]
        max_threads: Option<u32>,

        /// proxy url
        #[arg(long, value_name = "PROXY_URL")]
        proxy_url: Option<String>,

        /// proxy user password
        #[arg(long, value_name = "PROXY_USER_PWD")]
        proxy_user_pwd: Option<String>,
    },
    /// Register a new user
    RegisterUser {
        /// User's public Ethereum wallet address. 42-character hex string starting with '0x'
        #[arg(long, value_name = "WALLET_ADDRESS")]
        wallet_address: String,
    },
    /// Register a new node to an existing user, or link an existing node to a user.
    RegisterNode {
        /// ID of the node to register. If not provided, a new node will be created.
        #[arg(long, value_name = "NODE_ID")]
        node_id: Option<u64>,
    },
    /// Clear the node configuration and logout.
    Logout,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let nexus_environment_str = std::env::var("NEXUS_ENVIRONMENT").unwrap_or_default();
    let environment = nexus_environment_str
        .parse::<Environment>()
        .unwrap_or(Environment::default());

    let config_path = get_config_path()?;

    let args = Args::parse();
    match args.command {
        Command::Start {
            node_ids,
            headless,
            max_threads,
            proxy_url,
            proxy_user_pwd,
        } => start(node_ids, environment, config_path, headless, max_threads, proxy_url, proxy_user_pwd).await,
        Command::Logout => {
            println!("正在登出并清除节点配置...");
            Config::clear_node_config(&config_path).map_err(Into::into)
        }
        Command::RegisterUser { wallet_address } => {
            println!("正在使用钱包地址注册用户: {}", wallet_address);
            let orchestrator = Box::new(OrchestratorClient::new(environment, None, None));
            register_user(&wallet_address, &config_path, orchestrator).await
        }
        Command::RegisterNode { node_id } => {
            let orchestrator = Box::new(OrchestratorClient::new(environment, None, None));
            register_node(node_id, &config_path, orchestrator).await
        }
    }
}

/// Starts the Nexus CLI application.
///
/// # Arguments
/// * `node_id` - This client's unique identifier, if available.
/// * `env` - The environment to connect to.
/// * `config_path` - Path to the configuration file.
/// * `headless` - If true, runs without the terminal UI.
/// * `max_threads` - Optional maximum number of threads to use for proving.
async fn start(
    node_ids: Vec<u64>,
    env: Environment,
    config_path: std::path::PathBuf,
    headless: bool,
    max_threads: Option<u32>,
    proxy_url: Option<String>,
    proxy_user_pwd: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Spawn the stats server in the background
    tokio::spawn(stats_server::run_stats_server());

    // 创建一个共享的OrchestratorClient实例
    let orchestrator_client = OrchestratorClient::new(env, proxy_url.clone(), proxy_user_pwd.clone());

    if node_ids.is_empty() {
        // If no node IDs are provided, try to load from config or fail.
        let config = Config::load_from_file(&config_path)?;
        let node_id = config.node_id.parse::<u64>().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "无法将配置文件中的 node_id {:?} 解析为 u64: {}",
                    config.node_id, e
                ),
            )
        })?;
        println!("从配置文件读取到节点ID: {}\n", node_id);
        run_for_node_id(
            node_id,
            orchestrator_client,
            config_path.clone(),
            headless,
            max_threads,
            proxy_url,
            proxy_user_pwd,
        )
        .await?;
    } else {
        let mut join_handles = Vec::new();
        for node_id in node_ids {
            let client_clone = orchestrator_client.clone();
            let config_path_clone = config_path.clone();
            let proxy_url_clone = proxy_url.clone();
            let proxy_user_pwd_clone = proxy_user_pwd.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = run_for_node_id(
                    node_id,
                    client_clone,
                    config_path_clone,
                    headless,
                    max_threads,
                    proxy_url_clone,
                    proxy_user_pwd_clone,
                )
                .await
                {
                    eprintln!("为节点 {} 运行时出错: {}", node_id, e);
                }
            });
            join_handles.push(handle);
        }

        for handle in join_handles {
            handle.await?;
        }
    }

    Ok(())
}

async fn run_for_node_id(
    node_id: u64,
    orchestrator_client: OrchestratorClient,
    config_path: std::path::PathBuf,
    headless: bool,
    max_threads: Option<u32>,
    proxy_url: Option<String>,
    proxy_user_pwd: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Create a signing key for the prover.
    let mut csprng = rand_core::OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let env = orchestrator_client.environment().clone();
    // Clamp the number of workers to [1,8]. Keep this low for now to avoid rate limiting.
    let num_workers: usize = max_threads.unwrap_or(1).clamp(1, 8) as usize;
    let (shutdown_sender, _) = broadcast::channel(1); // Only one shutdown signal needed

    // Load config to get client_id for analytics
    let client_id = if config_path.exists() {
        match Config::load_from_file(&config_path) {
            Ok(config) => {
                // If user has a node_id, use "cli-{node_id}" format
                if !config.node_id.is_empty() {
                    format!("cli-{}", config.node_id)
                } else if !config.user_id.is_empty() {
                    // Fallback to user_id if no node_id but user is registered
                    format!("cli-{}", config.user_id)
                } else {
                    // No node_id or user_id - this shouldn't happen with current flow
                    "anonymous".to_string()
                }
            }
            Err(_) => "anonymous".to_string(), // Fallback to anonymous
        }
    } else {
        "anonymous".to_string() // No config file = anonymous user
    };

    let (mut event_receiver, mut join_handles) = start_authenticated_workers(
        node_id,
        signing_key.clone(),
        orchestrator_client.clone(),
        num_workers,
        shutdown_sender.subscribe(),
        env,
        client_id,
        proxy_url,
        proxy_user_pwd,
    )
    .await;

    if !headless {
        // Terminal setup
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        // Initialize the terminal with Crossterm backend.
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create the application and run it.
        let app = ui::App::new(
            Some(node_id),
            *orchestrator_client.environment(),
            event_receiver,
            shutdown_sender,
        );
        let res = ui::run(&mut terminal, app).await;

        // Clean up the terminal after running the application.
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        res?;
    } else {
        // Headless mode: log events to console.

        // Trigger shutdown on Ctrl+C
        let shutdown_sender_clone = shutdown_sender.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = shutdown_sender_clone.send(());
            }
        });

        let mut shutdown_receiver = shutdown_sender.subscribe();
        loop {
            tokio::select! {
                Some(event) = event_receiver.recv() => {
                    println!("{}", event);
                }
                _ = shutdown_receiver.recv() => {
                    break;
                }
            }
        }
    }
    println!("\n正在退出...");
    for handle in join_handles.drain(..) {
        let _ = handle.await;
    }
    println!("Nexus CLI 应用已成功退出。");
    Ok(())
}
