include!("../support/linux.rs");

#[cfg(target_env = "gnu")]
#[path = "linux/cancellation.rs"]
mod cancellation;

#[path = "linux/inspect.rs"]
mod inspect;
#[path = "linux/kill.rs"]
mod kill;
#[path = "linux/list.rs"]
mod list;
#[path = "linux/tui.rs"]
mod tui;
#[path = "linux/watch.rs"]
mod watch;
#[path = "linux/why.rs"]
mod why;
