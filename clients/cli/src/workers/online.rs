//! Online Workers
//!
//! Handles network-dependent operations including:
//! - Task fetching from the orchestrator
//! - Proof submission to the orchestrator
//! - Network error handling with exponential backoff

use crate::consts::prover::{
    BACKOFF_DURATION, BATCH_SIZE, LOW_WATER_MARK, MAX_404S_BEFORE_GIVING_UP, QUEUE_LOG_INTERVAL,
    TASK_QUEUE_SIZE,
};
use crate::error_classifier::{ErrorClassifier, LogLevel};
use crate::events::Event;
use crate::orchestrator::{
    error::OrchestratorError, Orchestrator,
    TOTAL_TASKS_FETCHED, DUPLICATE_TASKS_FETCHED, UNIQUE_TASKS_FETCHED,
};
use crate::task::Task;
use crate::task_cache::TaskCache;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nexus_sdk::stwo::seq::Proof;
use postcard;
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// State for managing task fetching behavior
pub struct TaskFetchState {
    last_fetch_time: std::time::Instant,
    backoff_duration: Duration,
    last_queue_log_time: std::time::Instant,
    queue_log_interval: Duration,
    error_classifier: ErrorClassifier,
}

impl TaskFetchState {
    pub fn new() -> Self {
        Self {
            last_fetch_time: std::time::Instant::now()
                - Duration::from_millis(BACKOFF_DURATION + 1000), // Allow immediate first fetch
            backoff_duration: Duration::from_millis(BACKOFF_DURATION), // Start with 30 second backoff
            last_queue_log_time: std::time::Instant::now(),
            queue_log_interval: Duration::from_millis(QUEUE_LOG_INTERVAL), // Log queue status every 30 seconds
            error_classifier: ErrorClassifier::new(),
        }
    }

    pub fn should_log_queue_status(&mut self) -> bool {
        // Log queue status every QUEUE_LOG_INTERVAL seconds regardless of queue level
        self.last_queue_log_time.elapsed() >= self.queue_log_interval
    }

    pub fn should_fetch(&self, tasks_in_queue: usize) -> bool {
        tasks_in_queue < LOW_WATER_MARK && self.last_fetch_time.elapsed() >= self.backoff_duration
    }

    pub fn record_fetch_attempt(&mut self) {
        self.last_fetch_time = std::time::Instant::now();
    }

    pub fn record_queue_log(&mut self) {
        self.last_queue_log_time = std::time::Instant::now();
    }

    pub fn reset_backoff(&mut self) {
        self.backoff_duration = Duration::from_millis(BACKOFF_DURATION);
    }

    pub fn increase_backoff_for_rate_limit(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 2,
            Duration::from_millis(BACKOFF_DURATION * 2),
        );
    }

    pub fn increase_backoff_for_error(&mut self) {
        self.backoff_duration = std::cmp::min(
            self.backoff_duration * 2,
            Duration::from_millis(BACKOFF_DURATION * 2),
        );
    }
}

/// Fetches tasks from the orchestrator and place them in the task queue.
/// Uses demand-driven fetching: only fetches when queue drops below LOW_WATER_MARK.
pub async fn fetch_prover_tasks(
    node_id: u64,
    verifying_key: VerifyingKey,
    orchestrator_client: Box<dyn Orchestrator>,
    sender: mpsc::Sender<Task>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    recent_tasks: TaskCache,
    completed_count: Arc<AtomicU64>,
) {
    let mut state = TaskFetchState::new();

    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();

                // Log queue status every QUEUE_LOG_INTERVAL seconds regardless of queue level
                if state.should_log_queue_status() {
                    state.record_queue_log();
                    log_queue_status(&event_sender, tasks_in_queue, &state).await;
                }

                // Attempt fetch if conditions are met
                if state.should_fetch(tasks_in_queue) {
                    if let Err(should_return) = attempt_task_fetch(
                        &*orchestrator_client,
                        &node_id,
                        verifying_key,
                        &sender,
                        &event_sender,
                        &recent_tasks,
                        &mut state,
                        &completed_count,
                    )
                    .await
                    {
                        if should_return {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Attempt to fetch tasks with timeout and error handling
async fn attempt_task_fetch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    completed_count: &Arc<AtomicU64>,
) -> Result<(), bool> {
    let count = completed_count.load(Ordering::SeqCst);
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            format!("\x1b[32m\t[任务进度 1/3] 正在获取新任务... (已完成: {} 个)\x1b[0m\n\t\t\t\t\t\t\t注意: CLI 任务难度更高，积分是网页版10倍", count),
            crate::events::EventType::Refresh,
            LogLevel::Debug,
        ))
        .await;

    // Add timeout to prevent hanging
    let fetch_future = fetch_task_batch(
        orchestrator_client,
        node_id,
        verifying_key,
        BATCH_SIZE,
        event_sender,
    );
    let timeout_duration = Duration::from_secs(60); // 60 second timeout

    match tokio::time::timeout(timeout_duration, fetch_future).await {
        Ok(fetch_result) => match fetch_result {
            Ok(tasks) => {
                // Record successful fetch attempt timing
                state.record_fetch_attempt();
                handle_fetch_success(tasks, sender, event_sender, recent_tasks, state, completed_count).await
            }
            Err(e) => {
                // Record failed fetch attempt timing
                state.record_fetch_attempt();
                handle_fetch_error(e, event_sender, state, completed_count).await;
                Ok(())
            }
        },
        Err(_timeout) => {
            // Handle timeout case
            state.record_fetch_attempt();
            let _ = event_sender
                .send(Event::task_fetcher_with_level(
                    format!("\t\t获取任务超时 ({}秒)", timeout_duration.as_secs()),
                    crate::events::EventType::Error,
                    LogLevel::Warn,
                ))
                .await;
            // Increase backoff for timeout
            state.increase_backoff_for_error();
            Ok(())
        }
    }
}

/// Log the current queue status
async fn log_queue_status(
    event_sender: &mpsc::Sender<Event>,
    tasks_in_queue: usize,
    state: &TaskFetchState,
) {
    let time_since_last = state.last_fetch_time.elapsed();
    let backoff_secs = state.backoff_duration.as_secs();

    let message = if state.should_fetch(tasks_in_queue) {
        format!(
            "\t\t任务队列容量低: {} 个任务待计算，准备获取新任务",
            tasks_in_queue
        )
    } else {
        let time_since_secs = time_since_last.as_secs();
        format!(
            "\t\t任务队列中: {} 个任务待计算，还需等待 {}秒 (每 {}秒 重试)",
            tasks_in_queue,
            backoff_secs.saturating_sub(time_since_secs),
            backoff_secs
        )
    };

    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            message,
            crate::events::EventType::Refresh,
            LogLevel::Debug,
        ))
        .await;
}

/// Handle successful task fetch
async fn handle_fetch_success(
    tasks: Vec<Task>,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
    state: &mut TaskFetchState,
    completed_count: &Arc<AtomicU64>,
) -> Result<(), bool> {
    if tasks.is_empty() {
        handle_empty_task_response(sender, event_sender, state).await;
        return Ok(());
    }

    let (added_count, duplicate_count) =
        process_fetched_tasks(tasks, sender, event_sender, recent_tasks).await?;

    log_fetch_results(
        added_count,
        duplicate_count,
        sender,
        event_sender,
        state,
        completed_count,
    )
    .await;
    Ok(())
}

/// Handle empty task response from server
async fn handle_empty_task_response(
    _sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    // let current_queue_level = TASK_QUEUE_SIZE - sender.capacity();
    let msg = "\t\t此节点暂无可用任务".to_string();
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Info,
        ))
        .await;

    // IMPORTANT: Reset backoff even when no tasks are available
    // Otherwise we get stuck in backoff loop when server has no tasks
    state.reset_backoff();
}

/// Process fetched tasks and handle duplicates
async fn process_fetched_tasks(
    tasks: Vec<Task>,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    recent_tasks: &TaskCache,
) -> Result<(usize, usize), bool> {
    let mut added_count = 0;
    let mut duplicate_count = 0;

    for task in tasks {
        if recent_tasks.contains(&task.task_id).await {
            duplicate_count += 1;
            DUPLICATE_TASKS_FETCHED.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        UNIQUE_TASKS_FETCHED.fetch_add(1, Ordering::SeqCst);

        // If we've reached this point, the task is new.
        recent_tasks.insert(task.task_id.clone()).await;

        if sender.send(task.clone()).await.is_err() {
            let _ = event_sender
                .send(Event::task_fetcher(
                    "Task queue is closed".to_string(),
                    crate::events::EventType::Shutdown,
                ))
                .await;
            return Err(true); // Signal caller to return
        }
        added_count += 1;
    }

    Ok((added_count, duplicate_count))
}

/// Log fetch results and handle backoff logic
async fn log_fetch_results(
    added_count: usize,
    duplicate_count: usize,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
    _completed_count: &Arc<AtomicU64>,
) {
    if added_count > 0 {
        log_successful_fetch(added_count, sender, event_sender).await;
        state.reset_backoff();
    } else if duplicate_count > 0 {
        handle_all_duplicates(duplicate_count, event_sender, state).await;
    }
}

/// Log successful task fetch with queue status
async fn log_successful_fetch(
    added_count: usize,
    sender: &mpsc::Sender<Task>,
    event_sender: &mpsc::Sender<Event>,
) {
    let tasks_in_queue = TASK_QUEUE_SIZE - sender.capacity();
    let msg = format!(
        "\t\t成功获取 {} 个新任务。队列中共有 {} 个任务。",
        added_count, tasks_in_queue
    );
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Info,
        ))
        .await;
}

/// Handle case where all fetched tasks were duplicates
async fn handle_all_duplicates(
    duplicate_count: usize,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
) {
    let msg = format!(
        "\t\t忽略 {} 个重复任务，队列未改变。",
        duplicate_count
    );
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Debug,
        ))
        .await;
    state.increase_backoff_for_error();
}

/// Handle fetch errors with appropriate backoff
async fn handle_fetch_error(
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
    state: &mut TaskFetchState,
    _completed_count: &Arc<AtomicU64>,
) {
    let log_level = state.error_classifier.classify_fetch_error(&error);
    let msg = format!("\t\t获取任务失败: {}", error);
    let _ = event_sender
        .send(Event::task_fetcher_with_level(
            msg,
            crate::events::EventType::Error,
            log_level,
        ))
        .await;

    // Apply backoff based on error type
    if let OrchestratorError::Http { status, .. } = error {
        if status == 429 {
            state.increase_backoff_for_rate_limit();
        } else if status >= 500 && status < 600 || status >= 400 && status < 500 {
            state.increase_backoff_for_error();
        }
    } else {
        state.increase_backoff_for_error();
    }
}

/// Fetch a batch of tasks from the orchestrator
async fn fetch_task_batch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    batch_size: usize,
    event_sender: &mpsc::Sender<Event>,
) -> Result<Vec<Task>, OrchestratorError> {
    // First try to get existing assigned tasks
    if let Some(existing_tasks) = try_get_existing_tasks(orchestrator_client, node_id).await? {
        return Ok(existing_tasks);
    }

    // If no existing tasks, try to get new ones
    fetch_new_tasks_batch(
        orchestrator_client,
        node_id,
        verifying_key,
        batch_size,
        event_sender,
    )
    .await
}

/// Try to get existing assigned tasks
async fn try_get_existing_tasks(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
) -> Result<Option<Vec<Task>>, OrchestratorError> {
    match orchestrator_client.get_tasks(&node_id.to_string()).await {
        Ok(tasks) => {
            if !tasks.is_empty() {
                Ok(Some(tasks))
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            // If getting existing tasks fails, try to get new ones
            if matches!(e, OrchestratorError::Http { status: 404, .. }) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Fetch a batch of new tasks from the orchestrator
async fn fetch_new_tasks_batch(
    orchestrator_client: &dyn Orchestrator,
    node_id: &u64,
    verifying_key: VerifyingKey,
    batch_size: usize,
    event_sender: &mpsc::Sender<Event>,
) -> Result<Vec<Task>, OrchestratorError> {
    let mut new_tasks = Vec::new();
    let mut consecutive_404s = 0;

    for i in 0..batch_size {
        match orchestrator_client
            .get_proof_task(&node_id.to_string(), verifying_key)
            .await
        {
            Ok(task) => {
                TOTAL_TASKS_FETCHED.fetch_add(1, Ordering::SeqCst);
                new_tasks.push(task);
                consecutive_404s = 0; // Reset counter on success
            }
            Err(OrchestratorError::Http { status: 429, .. }) => {
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        "\t\tEvery node in the Prover Network is rate limited to 3 tasks per 3 minutes".to_string(),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;
                // Rate limited, return what we have
                break;
            }
            Err(OrchestratorError::Http { status: 404, .. }) => {
                consecutive_404s += 1;
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!("\t\tfetch_task_batch: No task available (404) on attempt #{}, consecutive_404s: {}", i + 1, consecutive_404s),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;

                if consecutive_404s >= MAX_404S_BEFORE_GIVING_UP {
                    let _ = event_sender
                        .send(Event::task_fetcher_with_level(
                            format!(
                                "\t\tfetch_task_batch: Too many 404s ({}), giving up",
                                consecutive_404s
                            ),
                            crate::events::EventType::Refresh,
                            LogLevel::Debug,
                        ))
                        .await;
                    break;
                }
                // Continue trying more tasks
            }
            Err(e) => {
                let _ = event_sender
                    .send(Event::task_fetcher_with_level(
                        format!(
                            "\t\tfetch_task_batch: get_proof_task #{} failed with error: {:?}",
                            i + 1,
                            e
                        ),
                        crate::events::EventType::Refresh,
                        LogLevel::Debug,
                    ))
                    .await;
                return Err(e);
            }
        }
    }

    Ok(new_tasks)
}

/// Submits proofs to the orchestrator
pub async fn submit_proofs(
    signing_key: SigningKey,
    orchestrator: Box<dyn Orchestrator>,
    num_workers: usize,
    mut _results: mpsc::Receiver<(Task, Proof)>,
    event_sender: mpsc::Sender<Event>,
    mut shutdown: broadcast::Receiver<()>,
    successful_tasks: TaskCache,
    completed_count: Arc<AtomicU64>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut session_completed_count = 0;
        let mut last_stats_time = std::time::Instant::now();

        loop {
            tokio::select! {
                _ = shutdown.recv() => {
                    println!("\n收到关闭信号，正在退出证明提交循环。");
                    break;
                }
                result = _results.recv() => {
                    if let Some((task, proof)) = result {
                        let orchestrator_clone = orchestrator.recreate_with_new_proxy();
                        if process_proof_submission(
                            task,
                            proof,
                            &*orchestrator_clone,
                            &signing_key,
                            num_workers,
                            &event_sender,
                            &successful_tasks
                        ).await.is_none() {
                            // On success, increment counters
                            completed_count.fetch_add(1, Ordering::SeqCst);
                            session_completed_count += 1;
                        };

                        if session_completed_count >= 10 {
                            report_performance_stats(&event_sender, session_completed_count, last_stats_time).await;
                            session_completed_count = 0;
                            last_stats_time = std::time::Instant::now();
                        }
                    } else {
                        println!("结果通道已关闭，正在退出证明提交循环。");
                        break;
                    }
                }
            }
        }
    })
}

/// Reports the performance statistics of the prover.
async fn report_performance_stats(
    event_sender: &mpsc::Sender<Event>,
    completed_count: u64,
    last_stats_time: std::time::Instant,
) {
    let elapsed = last_stats_time.elapsed();
    let tasks_per_minute = if elapsed.as_secs() > 0 {
        (completed_count as f64 * 60.0) / elapsed.as_secs() as f64
    } else {
        0.0
    };

    let msg = format!(
        "\t\t性能状态: {} 个任务在 {:.1} 秒内完成 ({:.1} 个任务/分钟)",
        completed_count,
        elapsed.as_secs_f64(),
        tasks_per_minute
    );
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            msg,
            crate::events::EventType::Refresh,
            LogLevel::Info,
        ))
        .await;
}

/// Process a single proof submission
/// Returns Some(true) if successful, Some(false) if failed, None if should skip
async fn process_proof_submission(
    task: Task,
    proof: Proof,
    orchestrator: &dyn Orchestrator,
    signing_key: &SigningKey,
    num_workers: usize,
    event_sender: &mpsc::Sender<Event>,
    successful_tasks: &TaskCache,
) -> Option<bool> {
    // Check for duplicate submissions
    if successful_tasks.contains(&task.task_id).await {
        let msg = format!(
            "Ignoring proof for previously submitted task {}",
            task.task_id
        );
        let _ = event_sender
            .send(Event::proof_submitter(msg, crate::events::EventType::Error))
            .await;
        return None; // Skip this task
    }

    let proof_bytes = postcard::to_allocvec(&proof).expect("Failed to serialize proof");
    let mut hasher = Keccak256::new();
    hasher.update(&proof_bytes);
    let proof_hash = format!("0x{}", hex::encode(hasher.finalize()));
    let _ = event_sender
        .send(Event::proof_submitter(
            format!(
                "\t[任务进度 3/3] 正在提交任务 {} 的证明",
                task.task_id
            ),
            crate::events::EventType::Refresh,
        ))
        .await;

    let mut retries = 0;
    // let max_retries = 3; // 移除重试次数
    // let mut backoff_duration = Duration::from_secs(1); // 移除延迟
    
    // 只提交一次，不重试
    let current_orchestrator = orchestrator.recreate_with_new_proxy();
    match current_orchestrator
        .submit_proof(
            &task.task_id,
            &proof_hash,
            proof_bytes.clone(),
            signing_key.clone(),
            num_workers,
        )
        .await
    {
        Ok(()) => {
            handle_submission_success(&task, event_sender, successful_tasks).await;
            return None; // Success
        }
        Err(e) => {
            handle_submission_error(&task, e, event_sender).await;
            return Some(true); // 失败
        }
    }
}

/// Handle a successful proof submission.
async fn handle_submission_success(
    task: &Task,
    event_sender: &mpsc::Sender<Event>,
    successful_tasks: &TaskCache,
) {
    let msg = format!("\t\t成功提交任务 {} 的证明！", task.task_id);
    let _ = event_sender
        .send(Event::proof_submitter_with_level(
            msg,
            crate::events::EventType::Success,
            LogLevel::Info,
        ))
        .await;
    successful_tasks.insert(task.task_id.clone()).await;
}

/// Handle an error during proof submission.
async fn handle_submission_error(
    task: &Task,
    error: OrchestratorError,
    event_sender: &mpsc::Sender<Event>,
) {
    let msg = format!("\t\t任务 {} 证明提交失败: {}", task.task_id, error);
    let _ = event_sender
        .send(Event::prover_with_level(
            0, // worker_id is not available here, using 0 as placeholder
            msg,
            crate::events::EventType::Error,
            LogLevel::Error,
        ))
        .await;
}
