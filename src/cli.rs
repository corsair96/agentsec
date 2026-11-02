use crate::finding::{Layer, Severity};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "agentsec",
    version,
    about = "Unified AI Agent Security Scanner",
    long_about = "Static security scanner for AI agent stacks: MCP configs, agent code, skills, RAG pipelines, secrets and model endpoints."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run the main static scan.
    Scan(ScanArgs),
    /// Manage baselines (drift detection / rug-pull).
    Baseline(BaselineArgs),
    /// List every built-in rule with its description.
    ListRules,
    /// Generate a project-level agentsec.yaml configuration file.
    Init(InitArgs),
    /// Run an optional dynamic probe against an endpoint.
    Probe(ProbeArgs),
    /// Print the version.
    Version,
}

#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    /// File or directory to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Discover known MCP configs, skills, CI configs, .env files, ...
    #[arg(long)]
    pub auto: bool,

    /// Restrict the scan to one or more layers (comma separated).
    #[arg(long, value_delimiter = ',', value_enum, default_value = "all")]
    pub layer: Vec<LayerArg>,

    /// Minimum severity to report.
    #[arg(long, value_enum, default_value = "low")]
    pub min_severity: Severity,

    /// Output format.
    #[arg(long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,

    /// Write the report to a file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Exit with code 1 when a finding at or above this severity is present.
    #[arg(long, value_enum, default_value = "high")]
    pub fail_on: Severity,

    /// Preview mechanical fixes (dry-run).
    #[arg(long)]
    pub fix: bool,

    /// Apply mechanical fixes to disk.
    #[arg(long)]
    pub apply_fix: bool,

    /// Compare the current scan with a baseline JSON file.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Save the current scan as a baseline JSON file.
    #[arg(long)]
    pub baseline_save: Option<PathBuf>,

    /// Timeout per sub-scan (e.g. 30s, 500ms, 2m).
    #[arg(long, default_value = "30s")]
    pub timeout: String,

    /// Increase verbosity (repeatable).
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable ANSI colors.
    #[arg(long)]
    pub no_color: bool,
}

impl ScanArgs {
    /// Resolve the requested layers, expanding `all`.
    pub fn layers(&self) -> Vec<Layer> {
        if self.layer.is_empty() || self.layer.contains(&LayerArg::All) {
            return Layer::ALL.to_vec();
        }

        let mut layers = Vec::new();
        for arg in &self.layer {
            if let Some(layer) = arg.as_layer() {
                if !layers.contains(&layer) {
                    layers.push(layer);
                }
            }
        }
        layers
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LayerArg {
    All,
    Mcp,
    Agent,
    Model,
    Rag,
    Secrets,
    Skills,
}

impl LayerArg {
    pub fn as_layer(self) -> Option<Layer> {
        match self {
            LayerArg::All => None,
            LayerArg::Mcp => Some(Layer::Mcp),
            LayerArg::Agent => Some(Layer::Agent),
            LayerArg::Model => Some(Layer::Model),
            LayerArg::Rag => Some(Layer::Rag),
            LayerArg::Secrets => Some(Layer::Secrets),
            LayerArg::Skills => Some(Layer::Skills),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Markdown,
    Html,
}

#[derive(Debug, Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub action: BaselineAction,
}

#[derive(Debug, Subcommand)]
pub enum BaselineAction {
    /// Save the current scan as a baseline.
    Save {
        /// Path of the baseline file to write.
        #[arg(default_value = "agentsec-baseline.json")]
        output: PathBuf,
        /// Directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Compare the current scan against a baseline.
    Check {
        /// Baseline file to compare against.
        #[arg(long, default_value = "agentsec-baseline.json")]
        baseline: PathBuf,
        /// Directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show the difference between a baseline and the current scan.
    Diff {
        /// Baseline file to compare against.
        #[arg(long, default_value = "agentsec-baseline.json")]
        baseline: PathBuf,
        /// Directory to scan.
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Directory in which to create agentsec.yaml.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Overwrite an existing file.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ProbeArgs {
    /// Endpoint to probe.
    #[arg(long)]
    pub endpoint: Option<String>,
}
