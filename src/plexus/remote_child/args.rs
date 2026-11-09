//! `--child` and its company as clap arguments (feature `clap`), flattened
//! into any service's own: every service spells them the same.

use std::path::PathBuf;
use std::time::Duration;

use super::spec::{parse_duration, ChildError, ChildOptions, ChildSpec};
use super::RemoteChild;

/// The child seam's flags.
///
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Args {
///     #[command(flatten)]
///     children: plexus_core::plexus::ChildArgs,
/// }
/// let children = args.children.connect_all("menger").await?;   // before the service is shared
/// ```
#[derive(clap::Args, Debug, Clone)]
#[command(next_help_heading = "Children")]
pub struct ChildArgs {
    /// An activation in another process, mounted under NAME:
    /// `NAME=stdio:CMD ARGS…` (split as a shell would, run without one, with
    /// a cleared environment) or `NAME=ws://HOST:PORT` (dialed with
    /// `--child-key`'s proof). Repeatable; `;`-separated in the environment.
    #[arg(long = "child", value_name = "NAME=stdio:CMD | NAME=ws://…", env = "PLEXUS_CHILDREN", value_delimiter = ';')]
    pub child: Vec<ChildSpec>,

    /// How long a child has to answer its `_info` and schema at start, and
    /// each call's open after (`5s`, `500ms`).
    #[arg(long = "child-timeout", value_name = "DURATION", default_value = "5s", value_parser = parse_duration, hide_short_help = true)]
    pub child_timeout: Duration,

    /// Calls open on one child at once; past it a call is `too_many_calls`.
    #[arg(long = "child-max-calls", value_name = "N", default_value_t = 1024, hide_short_help = true)]
    pub child_max_calls: usize,

    /// A variable of this service's environment passed to every stdio
    /// child (beyond PATH, HOME, LANG and PLEXUS_CHILD_NAME). Repeatable.
    #[arg(long = "child-env", value_name = "KEY", hide_short_help = true)]
    pub child_env: Vec<String>,

    /// The key file a WebSocket child is dialed with (synapse's
    /// `~/.plexus/keys/<name>.key`, 0600): its proof on the upgrade, its
    /// principal the hop's. A path, never the key.
    #[arg(long = "child-key", value_name = "PATH", hide_short_help = true)]
    pub child_key: Option<PathBuf>,

    /// How many levels of a child's static children its mount walks (NEST-4);
    /// a deeper child fails the mount, naming its path.
    #[arg(long = "child-max-depth", value_name = "N", default_value_t = 8, hide_short_help = true)]
    pub child_max_depth: usize,

    /// How many dynamic children's schemas a mount keeps, one per name,
    /// asked of the child the first time (NEST-6); the least recently used
    /// goes first. 0 keeps none.
    #[arg(long = "child-schema-cache", value_name = "N", default_value_t = 1024, hide_short_help = true)]
    pub child_schema_cache: usize,
}

/// The flags' own defaults (a derived `Default` would say 0 for each
/// count, and a mount of depth 0 or a cache of 0 is not what no flag means).
impl Default for ChildArgs {
    fn default() -> Self {
        let d = ChildOptions::default();
        Self {
            child: Vec::new(),
            child_timeout: d.timeout,
            child_max_calls: d.max_calls,
            child_env: Vec::new(),
            child_key: None,
            child_max_depth: d.max_depth,
            child_schema_cache: d.schema_cache,
        }
    }
}

impl ChildArgs {
    /// The options these flags say, for the service named `service`.
    pub fn options(&self, service: &str) -> ChildOptions {
        ChildOptions {
            timeout: self.child_timeout,
            max_calls: self.child_max_calls,
            env: self.child_env.clone(),
            key: self.child_key.clone(),
            max_depth: self.child_max_depth,
            schema_cache: self.child_schema_cache,
            ..ChildOptions::for_service(service)
        }
    }

    /// Every `--child`, connected in order: the first that fails stops the
    /// start, naming it and why.
    pub async fn connect_all(&self, service: &str) -> Result<Vec<RemoteChild>, ChildError> {
        let opts = self.options(service);
        let mut out = Vec::with_capacity(self.child.len());
        for spec in &self.child {
            out.push(RemoteChild::connect(spec.clone(), opts.clone()).await?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        children: ChildArgs,
    }

    #[test]
    fn the_flags_read() {
        let c = Cli::try_parse_from(["svc", "--child", "echo=stdio:python3 -I x.py", "--child", "far=ws://127.0.0.1:4480", "--child-timeout", "250ms", "--child-max-calls", "8", "--child-env", "RUST_LOG", "--child-key", "/k"]).unwrap();
        assert_eq!(c.children.child.len(), 2);
        assert_eq!(c.children.child[1], ChildSpec::Ws { name: "far".into(), url: "ws://127.0.0.1:4480".into() });
        let o = c.children.options("menger");
        assert_eq!((o.timeout, o.max_calls, o.principal.as_str(), o.env.clone()), (Duration::from_millis(250), 8, "service:menger", vec!["RUST_LOG".to_string()]));
        assert_eq!(o.key.as_deref(), Some(std::path::Path::new("/k")));
        let d = Cli::try_parse_from(["svc"]).unwrap().children;
        let o = ChildArgs::default();
        assert_eq!((o.child_timeout, o.child_max_calls, o.child_max_depth, o.child_schema_cache), (d.child_timeout, d.child_max_calls, d.child_max_depth, d.child_schema_cache), "Default is the flags' defaults");
        assert!(d.child.is_empty());
        assert_eq!((d.child_timeout, d.child_max_calls, d.child_max_depth), (Duration::from_secs(5), 1024, 8));
        let deep = Cli::try_parse_from(["svc", "--child-max-depth", "3"]).unwrap().children;
        assert_eq!(deep.options("menger").max_depth, 3);
        assert_eq!(d.options("menger").schema_cache, 1024);
        let few = Cli::try_parse_from(["svc", "--child-schema-cache", "16"]).unwrap().children;
        assert_eq!(few.options("menger").schema_cache, 16);
        let e = Cli::try_parse_from(["svc", "--child", "a.b=stdio:x"]).err().unwrap().to_string();
        assert!(e.contains("dotted"), "{e}");
    }
}
