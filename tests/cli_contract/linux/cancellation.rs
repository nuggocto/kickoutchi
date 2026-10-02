use super::*;
use std::os::unix::process::ExitStatusExt;

/// Stop the real CLI at the exit of a successful pidfd signal syscall. This
/// gives cancellation a deterministic place in the freeze/delivery interval,
/// including in optimized binaries, without adding a hook to production code.
fn interrupt_after_signal(
    target_pid: u32,
    scope: Option<&str>,
    delivery_signal: libc::c_int,
    interrupt: libc::c_int,
) -> Output {
    let config = super::super::TemporaryDirectory::new("interrupt-kill");
    let config_path = config.path().join("config.toml");
    fs::write(&config_path, "").unwrap();
    let mut child = spawn_traced_kill(target_pid, scope, &config_path);
    let pid = libc::pid_t::try_from(child.child_mut().id()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    wait_for_trace_stop(pid, deadline, &mut child);
    // SAFETY: pid is our stopped tracee; these options require no memory access.
    assert_eq!(
        unsafe {
            libc::ptrace(
                libc::PTRACE_SETOPTIONS,
                pid,
                0,
                libc::PTRACE_O_TRACESYSGOOD
                    | libc::PTRACE_O_EXITKILL
                    | libc::PTRACE_O_TRACESECCOMP
                    | libc::PTRACE_O_TRACEEXIT,
            )
        },
        0
    );
    let mut matching_entry = false;
    loop {
        assert!(
            Instant::now() < deadline,
            "CLI never reached the signal boundary"
        );
        // SAFETY: resume our tracee only until its next syscall boundary.
        let request = if matching_entry {
            libc::PTRACE_SYSCALL
        } else {
            libc::PTRACE_CONT
        };
        assert_eq!(unsafe { libc::ptrace(request, pid, 0, 0) }, 0);
        wait_for_trace_stop(pid, deadline, &mut child);
        // SAFETY: libc supplies the kernel ABI layout and the exact writable
        // buffer size. The op discriminant selects the active union member.
        let info = unsafe {
            let mut info: libc::ptrace_syscall_info = std::mem::zeroed();
            assert!(
                libc::ptrace(
                    libc::PTRACE_GET_SYSCALL_INFO,
                    pid,
                    std::mem::size_of_val(&info),
                    &raw mut info
                ) > 0
            );
            info
        };
        match info.op {
            libc::PTRACE_SYSCALL_INFO_SECCOMP => {
                // SAFETY: the kernel set the SECCOMP discriminant.
                let entry = unsafe { info.u.seccomp };
                matching_entry = entry.nr == u64::try_from(libc::SYS_pidfd_send_signal).unwrap()
                    && entry.args[1] == u64::try_from(delivery_signal).unwrap();
            }
            libc::PTRACE_SYSCALL_INFO_EXIT if matching_entry => {
                // SAFETY: the kernel set the EXIT discriminant.
                assert_eq!(unsafe { info.u.exit.sval }, 0, "target signal must succeed");
                break;
            }
            _ => {}
        }
    }
    if delivery_signal == libc::SIGSTOP {
        wait_for_pid_state(target_pid, 'T');
    }

    // SAFETY: queue the interrupt for our paused CLI. Keep tracing until exit
    // so every later seccomp event still executes the real syscall.
    assert_eq!(unsafe { libc::kill(pid, interrupt) }, 0);
    let mut forward_signal = 0;
    loop {
        // SAFETY: resume the owned tracee, forwarding actual delivery stops.
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, forward_signal) },
            0
        );
        let status = wait_for_trace_stop(pid, deadline, &mut child);
        if status >> 16 == libc::PTRACE_EVENT_EXIT {
            break;
        }
        forward_signal = if status >> 16 == libc::PTRACE_EVENT_SECCOMP {
            0
        } else {
            libc::WSTOPSIG(status)
        };
    }

    // SAFETY: at the exit event all target cleanup has finished. Detach so
    // Child can reap the real signal exit status through the shared runner.
    assert_eq!(unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) }, 0);
    let output = collect_child_output(child.0.take().unwrap(), None, KICK_EXIT_WAIT)
        .expect("interrupted CLI must exit after cleanup");
    assert_eq!(output.status.signal(), Some(interrupt), "{output:?}");
    output
}

fn spawn_traced_kill(target_pid: u32, scope: Option<&str>, config_path: &Path) -> CommandChild {
    let mut command = Command::new(kick_binary());
    command
        .arg("--config")
        .arg(config_path)
        .args(["kill", "--pid", &target_pid.to_string()])
        .stdin(if scope == Some("--group") {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(scope) = scope {
        command.arg(scope);
    }
    if scope != Some("--group") {
        command.arg("--yes");
    }

    // SAFETY: the post-fork callback calls only async-signal-safe libc APIs.
    // TRACEME allows this test to trace only its own child, starting at exec.
    unsafe {
        command.pre_exec(trace_pidfd_signals);
    }
    let mut child = CommandChild(Some(command.spawn().expect("traced CLI must start")));
    if let Some(mut stdin) = child.child_mut().stdin.take() {
        // The orphan can be classified as a service on native CI hosts. Always
        // confirm the group explicitly, regardless of its warning profile.
        stdin
            .write_all(b"group\n")
            .expect("group confirmation must be writable");
    }
    child
}

fn wait_for_trace_stop(
    pid: libc::pid_t,
    deadline: Instant,
    child: &mut CommandChild,
) -> libc::c_int {
    loop {
        let mut status = 0;
        // SAFETY: wait for the specific owned tracee into a live status buffer.
        let result = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        assert!(
            result >= 0,
            "trace wait failed: {}",
            io::Error::last_os_error()
        );
        if result == pid {
            if !libc::WIFSTOPPED(status) {
                let mut stderr = String::new();
                child
                    .child_mut()
                    .stderr
                    .take()
                    .unwrap()
                    .take(64 * 1024)
                    .read_to_string(&mut stderr)
                    .unwrap();
                child.disarm();
                panic!("CLI exited before injection: {status}; {stderr}");
            }
            return status;
        }
        assert!(Instant::now() < deadline, "tracee exceeded its deadline");
        thread::sleep(Duration::from_micros(50));
    }
}

// Run after fork: stack-only setup and libc calls, with no allocation or locks.
fn trace_pidfd_signals() -> io::Result<()> {
    let mut filter = [
        libc::sock_filter {
            code: u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS).unwrap(),
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K).unwrap(),
            jt: 0,
            jf: 1,
            k: u32::try_from(libc::SYS_pidfd_send_signal).unwrap(),
        },
        libc::sock_filter {
            code: u16::try_from(libc::BPF_RET | libc::BPF_K).unwrap(),
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_TRACE,
        },
        libc::sock_filter {
            code: u16::try_from(libc::BPF_RET | libc::BPF_K).unwrap(),
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: 4,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: the filter reads only seccomp_data.nr at offset zero. It notifies
    // our tracer for pidfd_send_signal and permits all other syscalls. The
    // kernel copies the complete, live stack buffer during prctl.
    unsafe {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            if libc::signal(signal, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
        if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &raw const program,
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[test]
fn interrupt_after_single_stop_resumes_target_without_terminating_it() {
    let _host_observation = lock_host_observation();
    let (mut helper, port, ready) = spawn_listener_process();
    let _ready = FileGuard(ready);
    interrupt_after_signal(helper.id(), None, libc::SIGSTOP, libc::SIGINT);
    assert_helper_survived_refusal(&mut helper);
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
}

#[test]
fn interrupted_tree_resumes_root_and_preserves_previously_stopped_child() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, child_pid, ready) = spawn_tree_process("root-owns-port");
    let _ready = FileGuard(ready);
    let _child = PidGuard::new(child_pid);
    stop_pid(child_pid);
    wait_for_pid_state(child_pid, 'T');
    interrupt_after_signal(helper.id(), Some("--tree"), libc::SIGSTOP, libc::SIGINT);
    assert_helper_survived_refusal(&mut helper);
    assert!(!matches!(process_state(helper.id()), Some('T' | 't')));
    assert_eq!(process_state(child_pid), Some('T'));
}

#[test]
fn interrupt_after_delivery_allows_pending_sigterm_to_run() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, ready) = spawn_listener_process();
    let _ready = FileGuard(ready);
    interrupt_after_signal(helper.id(), None, libc::SIGTERM, libc::SIGINT);
    wait_for_child_exit(&mut helper);
    assert!(!matches!(process_state(helper.id()), Some('T' | 't')));
}

#[test]
fn sigterm_during_group_freeze_resumes_root_and_leaves_members_alive() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, orphan_pid, ready) = spawn_group_process();
    let _ready = FileGuard(ready);
    let _orphan = PidGuard::new(orphan_pid);
    interrupt_after_signal(helper.id(), Some("--group"), libc::SIGSTOP, libc::SIGTERM);
    assert_helper_survived_refusal(&mut helper);
    assert!(!pid_is_terminated(orphan_pid));
    assert!(!matches!(process_state(orphan_pid), Some('T' | 't')));
}
