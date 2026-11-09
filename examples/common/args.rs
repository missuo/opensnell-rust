//! `--name value` / `--flag` argument parsing shared by the examples.

use std::collections::HashMap;

pub struct Args(HashMap<String, String>);

impl Args {
    /// Parses the command line; `flags` take no value. Exits with `usage` on
    /// `--help` or a malformed command line.
    pub fn parse(usage: &str, flags: &[&str]) -> Self {
        let mut map = HashMap::new();
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            let Some(name) = arg
                .strip_prefix("--")
                .filter(|n| !n.is_empty() && *n != "help")
            else {
                eprint!("{usage}");
                std::process::exit(if arg == "--help" { 0 } else { 2 });
            };
            let (name, value) = match name.split_once('=') {
                Some((n, v)) => (n.to_owned(), v.to_owned()),
                None if flags.contains(&name) => (name.to_owned(), "true".to_owned()),
                None => match it.next() {
                    Some(v) => (name.to_owned(), v),
                    None => {
                        eprintln!("missing value for --{name}");
                        std::process::exit(2);
                    }
                },
            };
            map.insert(name, value);
        }
        Args(map)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub fn get_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.get(name).unwrap_or(default)
    }

    pub fn required(&self, name: &str) -> &str {
        self.get(name).unwrap_or_else(|| {
            eprintln!("--{name} is required (see --help)");
            std::process::exit(2);
        })
    }

    pub fn flag(&self, name: &str) -> bool {
        matches!(self.get(name), Some("true" | "1" | "yes" | "on"))
    }
}
