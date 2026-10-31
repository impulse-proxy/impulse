use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::Parser;
use impulse_config::{runtime::RuntimeConfig, validator::validate as validate_config};
use impulse_edge::runtime::{
    ingress::configure_async_runtime,
    privilege_drop::{apply_process_privilege_drop, current_process_privilege_state},
    supervisor::RuntimeSupervisor,
};
use log::{error, info, warn};

use crate::{
    listener_group::{
        allocate_worker_index_base, collect_finished_listener_groups, log_listener_startup,
        reconcile_listener_groups, shutdown_listener_groups, spawn_managed_listener_group,
    },
    runtime_guard,
};

#[derive(Parser)]
#[command(
    version,
    about = "Impulse QUIC/HTTP3 reverse proxy and load balancer",
    long_about = None
)]
struct Cli {
    #[arg(short, long)]
    config: Option<String>,
}

pub(crate) fn main_entry() {
    let cli = Cli::parse();

    const DEFAULT_CONFIG_PATH: &str = "/etc/impulse/config.yaml";
    let config_path = match cli.config {
        Some(path) => path,
        None if Path::new(DEFAULT_CONFIG_PATH).exists() => DEFAULT_CONFIG_PATH.to_string(),
        None => {
            fatal_startup_error(
                &format!(
                    "no --config provided and default config '{}' was not found.",
                    DEFAULT_CONFIG_PATH
                ),
                false,
                2,
            );
        }
    };

    let config_yaml = match impulse_config::loader::read_config(&config_path) {
        Ok(cfg) => cfg,
        Err(err_msg) => {
            fatal_startup_error(&format!("loading config failed: {}", err_msg), false, 1);
        }
    };

    impulse_utils::logger::init::init_logger(
        &config_yaml.log.level,
        config_yaml.log.file.enabled,
        &config_yaml.log.file.path,
        config_yaml.log.format == impulse_config::config::LogFormat::Json,
    );
    // NOTE: tracing is initialized inside the Tokio runtime (see `run`), not
    // here. The OTLP tonic exporter spawns a background task while building its
    // channel, which panics with "there is no reactor running" when constructed
    // before the runtime exists.
    runtime_guard::install_panic_hook();

    let privilege_state = current_process_privilege_state();

    if let Err(err) = validate_config(&config_yaml) {
        fatal_startup_error(&format!("Configuration validation failed: {err}"), true, 1);
    }

    let runtime_config = match RuntimeConfig::from_config(&config_yaml) {
        Ok(config) => config,
        Err(err) => {
            fatal_startup_error(
                &format!("Runtime configuration normalization failed: {err}"),
                true,
                1,
            );
        }
    };

    if !privilege_state.can_bind_privileged_ports()
        && runtime_config
            .listeners
            .iter()
            .any(|listener| listener.listen.port < 1024)
    {
        fatal_startup_error(
            "binding a privileged port requires root or CAP_NET_BIND_SERVICE. Use ports >= 1024 for unprivileged startup.",
            true,
            1,
        );
    }

    let control_plane_threads = runtime_config.performance.control_plane_threads.max(1);
    configure_async_runtime(control_plane_threads);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(control_plane_threads)
        .thread_name("impulse-control-plane")
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            fatal_startup_error(
                &format!(
                    "Failed to initialize Tokio control-plane runtime (threads={}): {}",
                    control_plane_threads, err
                ),
                true,
                1,
            );
        }
    };

    runtime.block_on(run(
        runtime_config,
        config_yaml.log.clone(),
        config_yaml.observability.tracing.clone(),
        privilege_state,
        config_path,
    ));
}

async fn run(
    runtime_config: RuntimeConfig,
    log_config: impulse_config::config::Log,
    tracing_config: impulse_config::config::Tracing,
    privilege_state: impulse_edge::runtime::privilege_drop::ProcessPrivilegeState,
    config_path: String,
) {
    // Must happen inside the runtime: the OTLP tonic exporter spawns a task on
    // the current reactor while building its channel.
    impulse_utils::telemetry::init::init_tracing(
        tracing_config.enabled,
        &tracing_config.service_name,
        tracing_config.otlp_endpoint.as_deref(),
        tracing_config.sample_ratio,
    );

    let worker_count = runtime_config.performance.worker_threads.max(1);
    let shard_count = runtime_config.performance.packet_shards_per_worker.max(1);
    let effective_worker_count = worker_count.saturating_mul(shard_count);
    let supervisor = match RuntimeSupervisor::start(
        config_path,
        log_config,
        &runtime_config,
        effective_worker_count,
    ) {
        Ok(supervisor) => supervisor,
        Err(err) => {
            error!("Failed to initialize runtime supervisor: {}", err);
            std::process::exit(1);
        }
    };
    let shared_state = supervisor.shared_state();
    let runtime_bundle = supervisor.runtime();

    let binds_privileged_port = runtime_config
        .listeners
        .iter()
        .any(|listener| listener.listen.port < 1024);
    if !privilege_state.can_bind_privileged_ports() && binds_privileged_port {
        fatal_startup_error(
            "binding a privileged port requires root or CAP_NET_BIND_SERVICE. Use ports >= 1024 for unprivileged startup.",
            true,
            1,
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();
    let shutdown_lifecycle = Arc::clone(&runtime_bundle);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        // Drive the runtime lifecycle state machine: Running/Draining ->
        // ShuttingDown. This also gates any concurrent reload commit (Phase 6).
        RuntimeSupervisor::begin_shutdown(&shutdown_lifecycle);
        shutdown_flag.store(true, Ordering::Relaxed);
    });

    let mut listener_groups = Vec::new();
    let mut worker_failed = false;
    for listener_config in runtime_config.listener_runtime_configs() {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let worker_count = listener_config.performance.worker_threads.max(1);
        let worker_index_base = allocate_worker_index_base(&listener_groups, worker_count);
        match spawn_managed_listener_group(
            listener_config,
            Arc::clone(&shared_state),
            Arc::clone(&runtime_bundle),
            worker_index_base,
        )
        .await
        {
            Ok(group) => {
                listener_groups.push(group);
            }
            Err(err) => {
                error!("{}", err);
                worker_failed = true;
                break;
            }
        }
    }

    if !shutdown.load(Ordering::Relaxed) && !worker_failed {
        log_listener_startup(&runtime_config, &listener_groups);
        if let Err(err) = apply_privilege_drop(privilege_state, &runtime_config) {
            error!("{}", err);
            worker_failed = true;
        }
    }

    while !shutdown.load(Ordering::Relaxed) && !worker_failed {
        collect_finished_listener_groups(&mut listener_groups, &mut worker_failed).await;
        if worker_failed {
            break;
        }
        reconcile_listener_groups(&runtime_bundle, &mut listener_groups, &mut worker_failed).await;

        // Reflect a watchdog-requested drain in the runtime lifecycle: once the
        // watchdog asks for a restart, workers begin draining, so move the process
        // Running -> Draining (idempotent while already draining). This keeps the
        // lifecycle state machine an accurate transition table for drain, not just
        // reload/shutdown (Phase 6).
        if runtime_bundle
            .current_view()
            .shared_services()
            .watchdog
            .restart_requested()
        {
            RuntimeSupervisor::begin_drain(&runtime_bundle);
        }

        if worker_failed {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Whether we exited via signal or a worker failure, the process is now
    // shutting down; ensure the lifecycle reflects it before draining workers.
    RuntimeSupervisor::begin_shutdown(&runtime_bundle);
    shutdown_listener_groups(&mut listener_groups, &mut worker_failed).await;
    RuntimeSupervisor::complete_shutdown(&runtime_bundle, Duration::from_secs(5));

    let panic_count = runtime_guard::panic_count();
    if panic_count > 0 {
        worker_failed = true;
        error!("Process captured {} panic(s) via panic hook", panic_count);
    }

    if worker_failed {
        impulse_utils::telemetry::init::shutdown_tracing();
        std::process::exit(1);
    }
    impulse_utils::telemetry::init::shutdown_tracing();
    info!("Impulse shutdown complete");
}
#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(err) => {
            warn!(
                "Failed to register SIGTERM handler ({}); falling back to Ctrl+C only",
                err
            );
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn fatal_startup_error(message: &str, logger_ready: bool, exit_code: i32) -> ! {
    if logger_ready {
        error!("{}", message);
    } else {
        eprintln!("Error: {}", message);
    }
    std::process::exit(exit_code);
}

fn apply_privilege_drop(
    privilege_state: impulse_edge::runtime::privilege_drop::ProcessPrivilegeState,
    runtime_config: &RuntimeConfig,
) -> Result<(), String> {
    match apply_process_privilege_drop(privilege_state, runtime_config) {
        Ok(Some(target)) => {
            info!(
                "Dropped process privileges to user='{}' group='{}'",
                target.user, target.group
            );
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(err) => {
            let user = runtime_config.security.privileges.user.trim();
            let group = runtime_config.security.privileges.group.trim();
            Err(format!(
                "Failed to drop process privileges to user='{}' group='{}': {}",
                user, group, err
            ))
        }
    }
}
