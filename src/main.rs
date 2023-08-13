/******************************************************************************\
    permitd - enforces permissions on directory tree
    Copyright (C) 2022 Max Maisel

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
\******************************************************************************/
#![forbid(unsafe_code)]

use clap::Parser;
use daemonize::Daemonize;
use exacl::{setfacl, AclEntry, Perm};
use futures_util::StreamExt;
use inotify::{Event, EventMask, Inotify, WatchDescriptor, WatchMask};
use nix::unistd::{chown, Gid, Uid};
use serde::Deserialize;
use slog::{debug, error, info, trace, warn, Logger};
use sloggers::{
    file::FileLoggerBuilder,
    terminal::{Destination, TerminalLoggerBuilder},
    types::OverflowStrategy,
    Build,
};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::read_dir;
use std::path::Path;
use std::process;
use tokio::runtime::Runtime;

#[derive(Debug, Parser)]
struct Args {
    /// Run in foreground
    #[clap(short, long)]
    debug: bool,
    /// Verbose mode
    #[clap(short, long)]
    verbose: bool,
    /// Config file
    #[clap(short, long, default_value = "/etc/permitd/permitd.conf")]
    config_file: String,
}

#[derive(Debug, Deserialize)]
struct WatchedTreeCfg {
    path: String,
    unix: String,
    #[serde(default)]
    acl: String,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct Settings {
    pub daemonize: bool,
    pub pid_file: String,
    pub wrk_dir: String,
    pub logfile: String,
    pub log_level: sloggers::types::Severity,
    #[serde(rename = "dir")]
    pub directories: Vec<WatchedTreeCfg>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            daemonize: false,
            pid_file: "/run/permitd/pid".into(),
            wrk_dir: "/".into(),
            logfile: "/var/log/permitd.log".into(),
            log_level: sloggers::types::Severity::Info,
            directories: Vec::new(),
        }
    }
}

impl Settings {
    pub fn load_from_file(filename: &str) -> Result<Settings, String> {
        let toml = std::fs::read_to_string(filename).map_err(|e| {
            format!("Could not read config file '{}': {}", &filename, e)
        })?;
        toml::from_str(&toml)
            .map_err(|e| format!("Could not parse config: {}", e))
    }
}

#[derive(Debug)]
struct Ownership {
    uid: Uid,
    gid: Gid,
}

#[derive(Debug)]
struct Permission {
    owner: Ownership,
    acl: Vec<AclEntry>,
    acl_dir: Vec<AclEntry>,
}

impl Permission {
    pub fn apply(&self, path: &OsStr) -> Result<(), String> {
        if let Err(e) = chown(path, Some(self.owner.uid), Some(self.owner.gid))
        {
            return Err(format!("chown '{:#?}' failed: {}", &path, e));
        }
        if Path::new(&path).is_dir() {
            if let Err(e) = setfacl(&[&path], &self.acl_dir, None) {
                return Err(format!("setfacl '{:#?}' failed: {}", &path, e));
            }
        } else if let Err(e) = setfacl(&[&path], &self.acl, None) {
            return Err(format!("setfacl '{:#?}' failed: {}", &path, e));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PermissionMap(HashMap<String, Permission>);

impl TryFrom<&Settings> for PermissionMap {
    type Error = String;

    fn try_from(settings: &Settings) -> Result<Self, Self::Error> {
        let mut result = HashMap::new();
        for dir in &settings.directories {
            let tokens: Vec<&str> =
                dir.unix.split(|c| c == ':' || c == ' ').collect();
            if tokens.len() != 3 {
                return Err(format!("Invalid format: {:?}", tokens));
            }
            let uid = match users::get_user_by_name(tokens[0]) {
                Some(x) => Uid::from_raw(x.uid()),
                None => {
                    return Err(format!("User {} does not exist", tokens[0]))
                }
            };
            let gid = match users::get_group_by_name(tokens[1]) {
                Some(x) => Gid::from_raw(x.gid()),
                None => {
                    return Err(format!("Group {} does not exist", tokens[1]))
                }
            };
            let mode = match u32::from_str_radix(tokens[2], 8) {
                Ok(x) => x & 0o777,
                Err(e) => return Err(format!("Could not parse mode: {}", e)),
            };

            let mut acl = exacl::from_mode(mode);
            if !dir.acl.is_empty() {
                match exacl::from_str(
                    &dir.acl.replace(',', "\n").replace('_', ""),
                ) {
                    Ok(mut x) => acl.append(&mut x),
                    Err(e) => {
                        return Err(format!(
                            "Could not parse acl '{}', {}",
                            &dir.acl, e
                        ))
                    }
                }
            };

            let acl_dir = acl
                .clone()
                .into_iter()
                .map(|mut x| {
                    if x.perms.contains(Perm::READ) {
                        x.perms.insert(Perm::EXECUTE);
                    }
                    x
                })
                .collect();

            result.insert(
                dir.path.clone(),
                Permission {
                    owner: Ownership { uid, gid },
                    acl,
                    acl_dir,
                },
            );
        }
        Ok(PermissionMap(result))
    }
}

impl PermissionMap {
    pub fn longest_match<'a>(
        &'a self,
        path: &OsStr,
    ) -> Result<&'a Permission, String> {
        let path = path
            .to_owned()
            .into_string()
            .map_err(|e| format!("'{:#?}' is no valid unicode string", e))?;
        let longest_match = self.0.keys().fold(String::new(), |result, key| {
            if path.starts_with(key) && key.len() > result.len() {
                key.into()
            } else {
                result
            }
        });

        match self.0.get(&longest_match) {
            Some(x) => Ok(x),
            None => Err(format!("Did not find '{}' in permission map", path)),
        }
    }
}

#[derive(Debug)]
struct TreeWatcher(HashMap<WatchDescriptor, OsString>);

impl TreeWatcher {
    const WATCH_MASK: WatchMask = WatchMask::from_bits_truncate(
        WatchMask::CREATE.bits()
            | WatchMask::ATTRIB.bits()
            | WatchMask::DELETE_SELF.bits(),
    );

    pub fn new() -> Self {
        TreeWatcher(HashMap::new())
    }

    pub fn add_directory_tree(
        &mut self,
        inotify: &mut Inotify,
        dir: &Path,
    ) -> Result<(), String> {
        if !dir.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }

        self.add_watch(inotify, dir.to_path_buf().into_os_string())?;
        for entry in read_dir(dir).map_err(|e| {
            format!("Read directory '{}' failed: {}", &dir.display(), e)
        })? {
            let dir = entry
                .map_err(|e| format!("Read directory entry failed: {}", e))?
                .path();
            if dir.is_dir() {
                self.add_watch(inotify, dir.to_path_buf().into_os_string())?;
                self.add_directory_tree(inotify, &dir)?;
            }
        }
        Ok(())
    }

    pub fn add_watch(
        &mut self,
        inotify: &mut Inotify,
        path: OsString,
    ) -> Result<(), String> {
        match inotify.add_watch(&path, Self::WATCH_MASK) {
            Ok(x) => {
                self.0.insert(x, path);
                Ok(())
            }
            Err(e) => Err(format!("Add watch failed: {}", e)),
        }
    }

    pub fn remove_watch(&mut self, wd: &WatchDescriptor) -> Result<(), String> {
        // inotify removes deleted directories on its own
        match self.0.remove(wd) {
            Some(_) => Ok(()),
            None => {
                Err(format!("No watch was found for descriptor '{:?}'", wd))
            }
        }
    }

    pub fn get_event_path(&self, ev: &Event<OsString>) -> Option<&OsString> {
        self.0.get(&ev.wd)
    }
}

fn apply_tree_permissions(
    permissions: &PermissionMap,
    dir: &Path,
) -> Result<(), String> {
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let permission = permissions.longest_match(dir.as_os_str())?;

    for entry in read_dir(dir).map_err(|e| {
        format!("Read directory '{}' failed: {}", &dir.display(), e)
    })? {
        let path = entry
            .map_err(|e| format!("Read directory entry failed: {}", e))?
            .path();

        if path.is_symlink() {
            continue;
        }

        permission.apply(path.as_os_str())?;
        if path.is_dir() {
            apply_tree_permissions(permissions, &path)?;
        }
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    let settings = match Settings::load_from_file(&args.config_file) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Could not load config: {}", e);
            process::exit(1);
        }
    };

    if settings.daemonize && !args.debug {
        let daemon = Daemonize::new()
            .pid_file(&settings.pid_file)
            .chown_pid_file(true)
            .working_directory(&settings.wrk_dir);

        if let Err(e) = daemon.start() {
            eprintln!("Daemonize failed: {}", e);
            process::exit(1);
        }
    }

    let log_level = if args.verbose {
        sloggers::types::Severity::Trace
    } else {
        settings.log_level
    };

    let root_logger = if settings.daemonize && !args.debug {
        FileLoggerBuilder::new(&settings.logfile)
            .level(log_level)
            .overflow_strategy(OverflowStrategy::Block)
            .build()
    } else {
        TerminalLoggerBuilder::new()
            .level(log_level)
            .overflow_strategy(OverflowStrategy::Block)
            .destination(Destination::Stdout)
            .build()
    };
    let root_logger = root_logger.unwrap();

    info!(root_logger, "Starting permitd");
    debug!(root_logger, "Settings: {:?}", &settings);

    let retval = match Runtime::new() {
        Ok(rt) => rt.block_on(tokio_main(settings, root_logger.clone())),
        Err(e) => {
            error!(root_logger, "Failed to create tokio runtime: {}", e);
            1
        }
    };
    trace!(root_logger, "Exiting with result {}", retval);
    drop(root_logger);
    process::exit(retval);
}

async fn tokio_main(settings: Settings, logger: Logger) -> i32 {
    let permissions: PermissionMap = match (&settings).try_into() {
        Ok(x) => x,
        Err(e) => {
            error!(logger, "Processing config failed: {}", e);
            return 2;
        }
    };
    debug!(logger, "Permission Map: {:?}\n", permissions);

    info!(logger, "Applying initial permissions");
    for dir in &settings.directories {
        if let Err(e) =
            apply_tree_permissions(&permissions, Path::new(&dir.path))
        {
            error!(
                logger,
                "Could not set initial permissions on directory tree '{}': {}",
                &dir.path,
                e
            );
            return 2;
        }
    }

    info!(logger, "Initializing inotify watches");
    let mut inotify = match Inotify::init() {
        Ok(x) => x,
        Err(e) => {
            error!(logger, "Could not init inotify: {}", e);
            return 2;
        }
    };

    let mut watcher = TreeWatcher::new();
    for dir in &settings.directories {
        if let Err(e) =
            watcher.add_directory_tree(&mut inotify, Path::new(&dir.path))
        {
            error!(
                logger,
                "Could not watch directory tree '{}': {}", &dir.path, e
            );
            return 2;
        }
    }

    let mut buffer = [0; 16 * 1024];
    let mut stream = match inotify.event_stream(&mut buffer) {
        Ok(x) => x,
        Err(e) => {
            error!(logger, "Streaming events failed: {}", e);
            return 2;
        }
    };
    let mut ignored = HashSet::<OsString>::new();

    info!(logger, "Permitd ready to watch for events");
    while let Some(event) = stream.next().await {
        let event = match event {
            Ok(x) => x,
            Err(e) => {
                error!(logger, "Reading event failed: {}", e);
                return 3;
            }
        };
        trace!(logger, "Received event: {:?}", &event);
        let path = if let Some(path) = watcher.get_event_path(&event) {
            let mut path = path.to_owned();
            if let Some(name) = event.name {
                path.push("/");
                path.push(name);
            }
            path
        } else if event.mask.contains(EventMask::IGNORED) {
            continue;
        } else {
            warn!(logger, "Received unexpected event: {:?}", event);
            continue;
        };

        if event.mask.contains(EventMask::ISDIR | EventMask::CREATE) {
            trace!(logger, "watching {:?}", &path);
            if let Err(e) = watcher.add_watch(&mut inotify, path) {
                error!(logger, "{}", e)
            }
        } else if event.mask.contains(EventMask::DELETE_SELF) {
            trace!(logger, "unwatching {:?}", &path);
            if let Err(e) = watcher.remove_watch(&event.wd) {
                error!(logger, "{}", e)
            }
        } else if event.mask.intersects(EventMask::CREATE | EventMask::ATTRIB) {
            if ignored.remove(&path) {
                trace!(logger, "Ignoring event for {:?} once", &path);
                continue;
            }

            if Path::new(&path).is_symlink() {
                trace!(logger, "Skipping symlink: {:?}", &path);
                continue;
            }

            trace!(logger, "Setting permissions on '{:?}'", &path);
            let permission = match permissions.longest_match(&path) {
                Ok(x) => x,
                Err(e) => {
                    error!(logger, "{}", e);
                    return 3;
                }
            };
            match permission.apply(&path) {
                Ok(()) => {
                    // setfacl causes an additional ATTRIB event, ignore it to
                    // avoid an infinite loop
                    ignored.insert(path);
                }
                Err(e) => error!(logger, "{}", e),
            }
        }
    }

    0
}
