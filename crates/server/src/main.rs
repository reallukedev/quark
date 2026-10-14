//! The `quark` command: run the server, talk to a running one, or check a config.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "quark", version, about = "XMPP in a box")]
struct Cli {
    /// The config file.
    #[arg(long, short, env = "QUARK_CONFIG", default_value = quark::config::DEFAULT_CONFIG, global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (the default).
    Run,
    /// Send one admin request (JSON on stdin) to the running server; prints the JSON answer.
    Ctl,
    /// Serve the admin tools to an AI assistant (MCP over stdin/stdout), using the running
    /// server's admin socket.
    #[cfg(feature = "mcp")]
    Mcp {
        /// The admin socket (defaults to `<data_dir>/admin.sock` from the config).
        #[arg(long, env = "QUARK_ADMIN_SOCKET")]
        socket: Option<PathBuf>,
    },
    /// Check a config file and say what's wrong with it.
    CheckConfig {
        /// The file to check (defaults to --config).
        file: Option<PathBuf>,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("quark: couldn't start: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match cli.cmd.unwrap_or(Cmd::Run) {
        Cmd::Run => match rt.block_on(quark::run::run(cli.config)) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("quark: {e:#}");
                std::process::ExitCode::FAILURE
            }
        },
        Cmd::Ctl => std::process::ExitCode::from(rt.block_on(quark::admin::ctl(&cli.config)).clamp(0, 255) as u8),
        #[cfg(feature = "mcp")]
        Cmd::Mcp { socket } => {
            let socket = socket.unwrap_or_else(|| admin_socket(&cli.config));
            match rt.block_on(quark_mcp::serve_stdio(socket)) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("quark mcp: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Cmd::CheckConfig { file } => {
            let path = file.unwrap_or(cli.config);
            match quark::config::Config::load(&path) {
                Ok(c) => {
                    println!("{} is fine: {} domain(s).", path.display(), c.hosts.len());
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    match e.line() {
                        Some(l) => eprintln!("{}:{l}: {e}", path.display()),
                        None => eprintln!("{}: {e}", path.display()),
                    }
                    std::process::ExitCode::FAILURE
                }
            }
        }
    }
}

/// `<data_dir>/admin.sock`, reading the config without creating anything (stdout is for MCP).
#[cfg(feature = "mcp")]
fn admin_socket(config: &std::path::Path) -> PathBuf {
    let data_dir = match quark::config::Config::load(config) {
        Ok(mut c) => {
            let _ = c.apply_env(|k| std::env::var(k).ok());
            c.server.data_dir
        }
        Err(_) => std::env::var_os("QUARK_DATA_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| quark::config::ServerSection::default().data_dir),
    };
    quark::admin::socket_path(&data_dir)
}
