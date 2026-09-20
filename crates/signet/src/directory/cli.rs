//! `signet sync …` (§9).
//!
//! Introducing a CLI at all is a change for this binary: `main.rs` previously
//! ignored `argv` entirely and was configured purely from the environment. A
//! `None` subcommand therefore keeps the old behaviour (read env, serve HTTP), so
//! existing deployment scripts and container commands are unaffected.
//!
//! Every command needs the same database and encryption key as the server,
//! because the CLI runs the *same* engine — a dry run and a scheduled run cannot
//! drift apart if there is only one implementation.

use crate::directory::engine::{self, RunReport, SyncOptions, Trigger};
use crate::directory::source;
use crate::state::AppState;
use clap::{Parser, Subcommand};

/// How many individual entries the text report prints before summarizing.
/// `--json` always carries the complete list.
const MAX_LISTED: usize = 50;

#[derive(Debug, Parser)]
#[command(name = "signet", version, about = "Signet OIDC identity provider")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server (also the behaviour with no subcommand).
    Serve,
    /// Directory synchronisation.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Synchronise a source into the local user store.
    ///
    /// The connector is chosen by the source's `kind`, so the same command
    /// drives an LDAP or an HTTP JSON source; `ldap` is kept as an alias because
    /// that is the name the deployment docs and scripts already use.
    #[command(visible_alias = "ldap")]
    Run {
        /// Source code as configured in the dashboard (e.g. `corp-ldap`).
        #[arg(long)]
        source: String,
        /// Compute and print the differences without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Print the complete report as JSON.
        #[arg(long)]
        json: bool,
        /// Stop after this many entries. Also skips the absent-upstream pass: a
        /// partial snapshot cannot distinguish "deleted" from "past the limit".
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show the run history of a source.
    Runs {
        #[arg(long)]
        source: String,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 20)]
        limit: i64,
    },
    /// List the configured sources.
    Sources {
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(command: SyncCommand, state: &AppState) -> anyhow::Result<()> {
    match command {
        SyncCommand::Run {
            source,
            dry_run,
            json,
            limit,
        } => {
            let opts = SyncOptions { dry_run, limit };
            let report = engine::run_source(state, &source, Trigger::Cli, None, &opts).await?;
            print_report(&report, json)?;
            Ok(())
        }
        SyncCommand::Runs {
            source,
            json,
            limit,
        } => {
            let runs = engine::recent_runs(state, &source, limit).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&runs)?);
            } else if runs.is_empty() {
                println!("no runs recorded for {source}");
            } else {
                println!(
                    "{:<38} {:<20} {:<9} {:>7} {:>7} {:>7} {:>8}",
                    "id", "started (UTC)", "status", "created", "updated", "disabled", "conflicts"
                );
                for run in runs {
                    println!(
                        "{:<38} {:<20} {:<9} {:>7} {:>7} {:>7} {:>8}",
                        run.id,
                        run.started_at.format("%Y-%m-%d %H:%M:%S"),
                        run.status,
                        run.created_count,
                        run.updated_count,
                        run.disabled_count,
                        run.conflict_count,
                    );
                    if let Some(error) = run.error {
                        println!("    error: {error}");
                    }
                }
            }
            Ok(())
        }
        SyncCommand::Sources { json } => {
            let sources = source::list(&state.pool).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&sources)?);
            } else if sources.is_empty() {
                println!("no directory sources configured");
            } else {
                println!(
                    "{:<20} {:<10} {:<8} {:>8} {:<10} credential",
                    "code", "kind", "enabled", "priority", "interval"
                );
                for s in sources {
                    let interval = match s.interval_minutes {
                        Some(m) => format!("{m}m"),
                        None => "manual".to_string(),
                    };
                    println!(
                        "{:<20} {:<10} {:<8} {:>8} {:<10} {}",
                        s.code,
                        s.kind,
                        s.enabled,
                        s.priority,
                        interval,
                        if s.credential_set { "set" } else { "MISSING" },
                    );
                }
            }
            Ok(())
        }
    }
}

fn print_report(report: &RunReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let c = &report.counts;
    println!("source:   {}", report.source);
    println!(
        "mode:     {}",
        if report.dry_run {
            "dry run — nothing was written"
        } else {
            "applied"
        }
    );
    println!("status:   {}", report.status);
    println!(
        "scanned:  {}  created: {}  updated: {}  disabled: {}  skipped: {}  conflicts: {}  errors: {}",
        report.scanned, c.created, c.updated, c.disabled, c.skipped, c.conflicts, c.errors
    );
    if !report.reconciled {
        println!(
            "note:     absent-upstream reconciliation was skipped (limited run), so nobody \
             was disabled"
        );
    }

    let notable: Vec<_> = report
        .changes
        .iter()
        .filter(|change| change.outcome.is_noteworthy())
        .collect();
    if notable.is_empty() {
        println!("\nnothing to do — the local store already matches the directory");
        return Ok(());
    }

    println!();
    for change in notable.iter().take(MAX_LISTED) {
        let who = change
            .fields
            .as_ref()
            .map(|f| f.email.clone())
            .or_else(|| change.user_id.map(|id| id.to_string()))
            .unwrap_or_else(|| change.external_id.clone());
        let mut line = format!(
            "  {:<9} {:<40} {}",
            change.outcome.label(),
            change.external_id,
            who
        );
        if !change.reason.is_empty() {
            line.push_str(&format!("\n            ↳ {}", change.reason));
        }
        println!("{line}");
    }
    if notable.len() > MAX_LISTED {
        println!(
            "\n… and {} more (use --json for the complete list)",
            notable.len() - MAX_LISTED
        );
    }
    Ok(())
}
