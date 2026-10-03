use super::*;

#[test]
fn kernel_truncated_unicode_name_remains_protected_and_terminable() {
    let _host_observation = lock_host_observation();
    let name = "aaaaaaaaaaaaaaé";
    let (mut helper, _port, ready_file) = spawn_listener_process_with_options(true, Some(name));
    let _ready_file = FileGuard(ready_file);
    let pid_text = helper.id().to_string();
    let comm = fs::read(format!("/proc/{pid_text}/comm")).expect("helper comm must be readable");
    assert_eq!(&comm[..comm.len() - 1], &name.as_bytes()[..15]);
    assert!(std::str::from_utf8(&comm).is_err());

    let protected = kickoutchi_with_config(
        &["kill", "--pid", &pid_text, "--yes"],
        &format!("protected_processes = [\"{name}\"]\n"),
    );
    assert_eq!(protected.status.code(), Some(6), "{}", stderr(&protected));
    assert_helper_survived_refusal(&mut helper);

    let killed = kickoutchi_with_config(&["kill", "--pid", &pid_text, "--yes"], "");
    assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
    assert!(
        stderr(&killed).contains("sent SIGTERM"),
        "{}",
        stderr(&killed)
    );
    wait_for_child_exit(&mut helper);
}

#[test]
fn protected_name_that_renders_empty_cannot_be_confirmed_by_an_empty_answer() {
    let _host_observation = lock_host_observation();
    let name = "\u{1b}[31m";
    let (mut helper, _port, ready_file) = spawn_listener_process_with_options(true, Some(name));
    let _ready_file = FileGuard(ready_file);
    let pid_text = helper.id().to_string();
    let config = "protected_processes = [\"\\u001b[31m\"]\n";

    let listed = kickoutchi_with_config(
        &["list", "--json", "--filter", &format!("pid:{pid_text}")],
        config,
    );
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    assert!(
        stdout(&listed).contains("\"protected\": true"),
        "{}",
        stdout(&listed)
    );

    for answer in ["\n", ""] {
        let output =
            kickoutchi_with_config_and_stdin(&["kill", "--pid", &pid_text], config, answer);
        assert_eq!(
            output.status.code(),
            Some(5),
            "{answer:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(&format!("type PID {pid_text} to confirm")),
            "{}",
            stderr(&output),
        );
        assert!(
            !stderr(&output).contains("sent SIGTERM"),
            "{}",
            stderr(&output)
        );
        assert_helper_survived_refusal(&mut helper);
    }

    let confirmed = kickoutchi_with_config_and_stdin(
        &["kill", "--pid", &pid_text],
        config,
        &format!("{pid_text}\n"),
    );
    assert_eq!(confirmed.status.code(), Some(0), "{}", stderr(&confirmed));
    wait_for_child_exit(&mut helper);
}

#[test]
fn configured_protected_process_refuses_yes_kill_with_exit_6() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, ready_file) = spawn_listener_process();
    let pid = helper.id();
    let pid_text = pid.to_string();
    let process_name = fs::read_to_string(format!("/proc/{pid}/comm"))
        .expect("helper process comm must be readable")
        .trim_end()
        .to_owned();
    let config = format!(
        "protected_processes = [\"{}\"]\n",
        toml_string(&process_name),
    );

    let output = kickoutchi_with_config(&["kill", "--pid", pid_text.as_str(), "--yes"], &config);

    assert_eq!(output.status.code(), Some(6));
    assert!(stderr(&output).contains("protected"));
    // The refusal lands before the target banner, which proves protection was
    // resolved while the rows were projected rather than only at delivery.
    // Delivery re-checks protection independently, so without this the whole
    // projection-time policy could be unwired and the exit code would still
    // be 6. The only symptom would be a banner announcing a kill that never
    // runs.
    assert!(
        !stderr(&output).contains("Command: kill"),
        "a protected target must be refused before its banner is printed: {}",
        stderr(&output),
    );
    assert!(
        helper
            .child
            .try_wait()
            .expect("helper status must be readable")
            .is_none(),
        "protected helper must still be running",
    );
    let _ = fs::remove_file(ready_file);
}

#[test]
fn overlong_confirmation_cannot_be_truncated_into_force() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, ready_file) = spawn_listener_process();
    let pid_text = helper.id().to_string();
    let input = format!("force{}\n", " ".repeat(1024));

    let output = kickoutchi_with_stdin(&["kill", "--pid", pid_text.as_str(), "--force"], &input);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("confirmation input exceeds"),
        "{}",
        stderr(&output),
    );
    assert!(
        helper
            .child
            .try_wait()
            .expect("helper status must be readable")
            .is_none(),
        "overlong confirmation must not terminate the helper",
    );
    let _ = fs::remove_file(ready_file);
}

#[test]
fn kill_pid_yes_sends_real_sigterm_and_port_disappears() {
    let _host_observation = lock_host_observation();
    let (mut helper, port, ready_file) = spawn_listener_process();
    let port_text = port.to_string();
    let pid_text = helper.id().to_string();

    let before = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(before.status.code(), Some(0));
    assert!(stdout(&before).contains(port_text.as_str()));
    assert!(stdout_table_has_pid(&before, helper.id()));

    let killed = kickoutchi(&["kill", "--pid", pid_text.as_str(), "--yes"]);
    let killed_stderr = stderr(&killed);
    assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
    assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
    // The target banner (identity + equivalent command) prints even on the
    // `--yes` path, so a scripted kill still leaves the safety context and
    // warning lines on stderr instead of signalling silently.
    assert!(
        killed_stderr.contains(&format!("Terminate PID {pid_text}")),
        "{killed_stderr}"
    );
    assert!(
        killed_stderr.contains(&format!("Command: kill {pid_text}")),
        "{killed_stderr}"
    );
    wait_for_child_exit(&mut helper);

    let after = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(after.status.code(), Some(3));
    assert!(stdout(&after).contains("no open ports match the filter"));

    let _ = fs::remove_file(ready_file);
}

#[test]
fn host_port_kill_signals_only_with_complete_owner_evidence() {
    let _host_observation = lock_host_observation();
    let (mut helper, port, ready_file) = spawn_listener_process();
    let port_text = port.to_string();

    let killed = kickoutchi(&["kill", "--port", port_text.as_str(), "--yes"]);
    let killed_stderr = stderr(&killed);
    if port_kill_refused_for_incomplete_authority(&killed) {
        assert_helper_survived_refusal(&mut helper);
        let _ = fs::remove_file(ready_file);
        return;
    }
    assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
    assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
    wait_for_child_exit(&mut helper);
    let _ = fs::remove_file(ready_file);
}

#[test]
fn isolated_namespace_port_kill_signals_or_refuses_without_delivery() {
    let test_binary = std::env::current_exe().expect("test binary path resolves");
    let ready_file = temp_file_path("namespace-listener-ready");
    let script = r#"KICKOUTCHI_TEST_HELPER_LISTENER=1 KICKOUTCHI_TEST_HELPER_BIND_ANY=1 KICKOUTCHI_TEST_HELPER_PORT=0 KICKOUTCHI_TEST_HELPER_READY="$3" "$1" --exact linux::helper_tcp_listener_process --ignored --nocapture & helper=$!; attempts=0; delay=0.001; while test ! -s "$3"; do attempts=$((attempts+1)); test "$attempts" -lt 100 || exit 90; sleep "$delay"; case "$delay" in 0.001) delay=0.002;; 0.002) delay=0.004;; 0.004) delay=0.008;; 0.008) delay=0.016;; 0.016) delay=0.032;; *) delay=0.050;; esac; done; port=$(cat "$3"); XDG_CONFIG_HOME="$3-config" "$2" kill --port "$port" --yes; kick_status=$?; if test "$kick_status" -eq 0; then wait "$helper"; helper_status=$?; rm -f "$3"; test "$helper_status" -eq 143; exit; fi; if test "$kick_status" -eq 1 || test "$kick_status" -eq 4; then kill -0 "$helper" || exit 91; kill "$helper"; wait "$helper"; helper_status=$?; rm -f "$3"; test "$helper_status" -eq 143; exit; fi; kill "$helper"; wait "$helper"; rm -f "$3"; exit "$kick_status""#;
    let output = run_command_with_deadline(
        Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--net",
                "--pid",
                "--fork",
                "--mount-proc",
                "sh",
                "-c",
                script,
                "sh",
            ])
            .arg(test_binary)
            .arg(kickoutchi_binary())
            .arg(&ready_file),
        None,
        CHILD_EXIT_WAIT,
    );
    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            assert!(
                !required_linux_capabilities(),
                "required unshare capability is unavailable: {error}"
            );
            eprintln!("unshare unavailable: {error}");
            return;
        }
        Err(error) => panic!("unshare must start: {error}"),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && (stderr.contains("Operation not permitted")
            || stderr.contains("Permission denied")
            || stderr.contains("unshare failed"))
    {
        assert!(
            !required_linux_capabilities(),
            "required user/network namespaces are unavailable: {stderr}"
        );
        eprintln!("user/network namespaces unavailable: {stderr}");
        return;
    }
    assert!(output.status.success(), "{stderr}");
    let signalled = stderr.contains("sent SIGTERM");
    let refused_during_collection =
        stderr.contains("collecting ports before kill failed: socket set is partial");
    let refused_during_revalidation = stderr.contains("ownership for PID")
        && stderr.contains("became unavailable before SIGTERM")
        && stderr.contains("no termination was sent");
    let refused_before_prompt = stderr.contains("is the only holder of port");
    assert!(
        signalled
            || refused_during_collection
            || refused_during_revalidation
            || refused_before_prompt,
        "{stderr}"
    );
    if refused_during_collection || refused_during_revalidation || refused_before_prompt {
        assert!(!signalled, "{stderr}");
    }
}

#[test]
fn tree_kill_by_port_signals_only_with_complete_owner_evidence() {
    let _host_observation = lock_host_observation();
    let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
    let _child_cleanup = PidGuard::new(child_pid);
    let port_text = port.to_string();
    let root_pid_text = helper.id().to_string();

    let before = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(before.status.code(), Some(0));
    assert!(stdout(&before).contains(root_pid_text.as_str()));

    let killed = kickoutchi_with_stdin(&["kill", "--port", port_text.as_str(), "--tree"], "tree\n");

    let killed_stderr = stderr(&killed);
    if port_kill_refused_for_incomplete_authority(&killed) {
        assert_helper_survived_refusal(&mut helper);
        assert!(pid_exists(child_pid), "child PID {child_pid} must survive");
        assert_ne!(
            process_state(child_pid),
            Some('T'),
            "child PID {child_pid} must not remain frozen after refusal",
        );
        let _ = fs::remove_file(ready_file);
        return;
    }
    assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
    assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
    assert!(killed_stderr.contains("2 processes"), "{killed_stderr}");
    assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
    wait_for_child_exit(&mut helper);
    wait_for_pid_gone(child_pid);

    let after = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(after.status.code(), Some(3));
    let _ = fs::remove_file(ready_file);
}

/// Declining the typed-word prompt must leave the whole tree alive and
/// *running*: confirmation happens before any freeze, so no member may be
/// left `SIGSTOP`ped in state `T`. This pins that ordering end to end. A
/// refactor that froze the tree before prompting (say, to make the count
/// exact) would fail here by leaving a frozen member behind.
#[test]
fn tree_kill_declined_at_prompt_leaves_tree_running_and_unfrozen() {
    let _host_observation = lock_host_observation();
    let (helper, _port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
    let _child_cleanup = PidGuard::new(child_pid);
    let root_pid = helper.id();
    let root_pid_text = root_pid.to_string();

    // Select by PID: an unprivileged port selection can be refused before the
    // prompt when unreadable host processes could share the socket.
    let declined = kickoutchi_with_stdin(&["kill", "--pid", &root_pid_text, "--tree"], "\n");

    assert_eq!(declined.status.code(), Some(5), "{}", stderr(&declined));
    let declined_stderr = stderr(&declined);
    // The preview printed and the prompt was really reached before the
    // cancel. This declined after enumeration, not before it.
    assert!(declined_stderr.contains("Scope: tree"), "{declined_stderr}");
    assert!(
        declined_stderr.contains("kill cancelled"),
        "{declined_stderr}"
    );

    for pid in [root_pid, child_pid] {
        assert!(pid_exists(pid), "PID {pid} must survive a declined kill");
        let state = process_state(pid);
        assert!(state.is_some(), "PID {pid} state must be readable");
        assert_ne!(state, Some('T'), "PID {pid} must not be left frozen");
    }

    let _ = fs::remove_file(ready_file);
}

#[test]
fn tree_kill_by_pid_terminates_previously_stopped_child() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
    let _child_cleanup = PidGuard::new(child_pid);
    let root_pid_text = helper.id().to_string();
    stop_pid(child_pid);
    wait_for_pid_state(child_pid, 'T');

    let killed = kickoutchi_with_stdin(
        &["kill", "--pid", root_pid_text.as_str(), "--tree"],
        "tree\n",
    );

    assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
    wait_for_child_exit(&mut helper);
    wait_for_pid_gone(child_pid);
    let _ = fs::remove_file(ready_file);
}

#[test]
fn tree_kill_by_pid_force_uses_sigkill_wording() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
    let _child_cleanup = PidGuard::new(child_pid);
    let root_pid_text = helper.id().to_string();

    let killed = kickoutchi_with_stdin(
        &["kill", "--pid", root_pid_text.as_str(), "--tree", "--force"],
        "force\n",
    );

    assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
    let killed_stderr = stderr(&killed);
    assert!(
        killed_stderr.contains("Force-kill process tree"),
        "{killed_stderr}"
    );
    assert!(killed_stderr.contains("sent SIGKILL"), "{killed_stderr}");
    wait_for_child_exit(&mut helper);
    wait_for_pid_gone(child_pid);
    let _ = fs::remove_file(ready_file);
}

#[test]
fn tree_kill_by_pid_allows_portless_parent_when_child_owns_port() {
    let _host_observation = lock_host_observation();
    let (mut helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
    let _child_cleanup = PidGuard::new(child_pid);
    let port_text = port.to_string();
    let root_pid_text = helper.id().to_string();

    let before = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(before.status.code(), Some(0));
    assert!(
        stdout_table_has_pid(&before, child_pid),
        "{}",
        stdout(&before)
    );
    assert!(
        !stdout_table_has_pid(&before, helper.id()),
        "{}",
        stdout(&before)
    );

    let killed = kickoutchi_with_stdin(
        &["kill", "--pid", root_pid_text.as_str(), "--tree"],
        "tree\n",
    );

    assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
    let killed_stderr = stderr(&killed);
    assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
    assert!(killed_stderr.contains("2 processes"), "{killed_stderr}");
    wait_for_child_exit(&mut helper);
    wait_for_pid_gone(child_pid);

    let after = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(after.status.code(), Some(3));
    let _ = fs::remove_file(ready_file);
}

#[test]
fn tree_kill_by_pid_reaches_deep_static_chain() {
    let _host_observation = lock_host_observation();
    let mut helper = spawn_deep_chain_process(DEEP_CHAIN_DEPTH);
    let root_pid_text = helper.root_id().to_string();

    let killed = kickoutchi_with_stdin(
        &["kill", "--pid", root_pid_text.as_str(), "--tree"],
        "tree\n",
    );

    assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
    let killed_stderr = stderr(&killed);
    assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
    assert!(
        killed_stderr.contains(&format!("{DEEP_CHAIN_DEPTH} processes")),
        "{killed_stderr}",
    );
    helper.wait_for_all_gone();
}

#[test]
fn tree_kill_converges_on_active_spawner_and_clears_group() {
    let _host_observation = lock_host_observation();
    let (mut helper, ready_file) = spawn_live_spawner_process();
    let root_pid = helper.id();
    let root_pid_text = root_pid.to_string();

    let killed = kickoutchi_with_stdin(
        &["kill", "--pid", root_pid_text.as_str(), "--tree"],
        "tree\n",
    );

    assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
    let killed_stderr = stderr(&killed);
    assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
    assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
    wait_for_child_exit(&mut helper);
    wait_for_process_group_clear(root_pid);
    let _ = fs::remove_file(ready_file);
}

#[test]
fn tree_kill_recollects_after_prompt_and_kills_late_fork() {
    let _host_observation = lock_host_observation();
    let (mut helper, first_child_pid, ready_file) = spawn_fork_on_trigger_process();
    let _first_child_cleanup = PidGuard::new(first_child_pid);
    let root_pid_text = helper.id().to_string();
    let mut kick = InteractiveKick::spawn(&["kill", "--pid", root_pid_text.as_str(), "--tree"]);

    kick.wait_for_stderr("Type tree");
    let trigger_file = ready_file.with_extension("trigger");
    fs::write(&trigger_file, "go").expect("fork trigger file must be written");
    let second_file = ready_file.with_extension("second");
    wait_for_file(&second_file);
    let late_pid = fs::read_to_string(&second_file)
        .expect("late fork ready file must be readable")
        .trim()
        .parse::<u32>()
        .expect("late fork pid must be a u32");
    let _late_cleanup = PidGuard::new(late_pid);

    kick.send_stdin("tree\n");
    let (code, transcript) = kick.finish();

    assert_eq!(code, Some(0), "{transcript}");
    assert!(transcript.contains("Scope: tree"), "{transcript}");
    assert!(transcript.contains("sent SIGTERM"), "{transcript}");
    wait_for_child_exit(&mut helper);
    wait_for_pid_gone(first_child_pid);
    wait_for_pid_gone(late_pid);
    let _ = fs::remove_file(ready_file);
    let _ = fs::remove_file(trigger_file);
    let _ = fs::remove_file(second_file);
}

/// A double-forked member leaves the root's tree after reparenting but remains
/// in its process group. Group scope must show and terminate that member.
#[test]
fn group_kill_by_port_signals_only_with_complete_owner_evidence() {
    let _host_observation = lock_host_observation();
    let (mut helper, port, orphan_pid, ready_file) = spawn_group_process();
    let _orphan_cleanup = PidGuard::new(orphan_pid);
    let root_pid = helper.id();
    let port_text = port.to_string();

    // Prove the premise: the orphan is alive but no longer our helper's
    // child, so it is invisible to a parent-link walk from the root.
    let orphan_parent = read_ppid(orphan_pid);
    assert_ne!(orphan_parent, root_pid, "orphan must have reparented");

    let killed = kickoutchi_with_stdin(
        &["kill", "--port", port_text.as_str(), "--group"],
        "group\n",
    );

    let killed_stderr = stderr(&killed);
    if port_kill_refused_for_incomplete_authority(&killed) {
        assert_helper_survived_refusal(&mut helper);
        assert!(
            pid_exists(orphan_pid),
            "orphan PID {orphan_pid} must survive"
        );
        assert_ne!(
            process_state(orphan_pid),
            Some('T'),
            "orphan PID {orphan_pid} must not remain frozen after refusal",
        );
        let _ = fs::remove_file(ready_file);
        return;
    }
    assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
    assert!(killed_stderr.contains("Scope: group"), "{killed_stderr}");
    assert!(
        killed_stderr.contains(&format!("PID {orphan_pid}")),
        "{killed_stderr}",
    );
    assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
    wait_for_child_exit(&mut helper);
    wait_for_pid_gone(orphan_pid);
    wait_for_process_group_clear(root_pid);

    let after = kickoutchi(&["list", "--port", port_text.as_str()]);
    assert_eq!(after.status.code(), Some(3));
    let _ = fs::remove_file(ready_file);
}

fn read_ppid(pid: u32) -> u32 {
    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).expect("orphan status must be readable");
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .expect("status must carry PPid")
        .trim()
        .parse::<u32>()
        .expect("PPid must be numeric")
}

#[test]
fn pid_kill_reports_the_exit_separately_from_the_closed_port() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, ready_file) = spawn_listener_process();
    let _ready_file = FileGuard(ready_file);
    let pid_text = helper.id().to_string();

    let killed = kickoutchi(&["kill", "--pid", &pid_text, "--yes"]);

    let text = stderr(&killed);
    assert_eq!(killed.status.code(), Some(0), "{text}");
    assert!(text.contains(&format!("PID {pid_text} (")), "{text}");
    assert!(text.contains(") exited\n"), "{text}");
    assert!(
        text.contains("confirmed target ports are no longer visible"),
        "{text}"
    );
    assert!(!text.contains("still running"), "{text}");
    wait_for_child_exit(&mut helper);
}

#[test]
fn pid_kill_warns_when_the_port_closes_but_the_process_keeps_running() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, ready_file) = spawn_lingering_listener_process();
    let _ready_file = FileGuard(ready_file);
    let pid_text = helper.id().to_string();

    let killed = kickoutchi(&["kill", "--pid", &pid_text, "--yes"]);

    let text = stderr(&killed);
    // The signal was accepted, so the exit code is unchanged; the report must
    // not claim the process exited.
    assert_eq!(killed.status.code(), Some(0), "{text}");
    assert!(
        text.contains("is still running 2.0s after SIGTERM"),
        "{text}"
    );
    assert!(
        text.contains("rerun with --force to send SIGKILL"),
        "{text}"
    );
    assert!(
        text.contains("confirmed target ports are no longer visible"),
        "{text}"
    );
    assert!(!text.contains(") exited"), "{text}");
    assert!(
        helper
            .child
            .try_wait()
            .expect("helper status must be readable")
            .is_none(),
        "the lingering helper must still be running"
    );
}

#[test]
fn batch_pid_kill_confirms_once_and_prints_one_summary() {
    let _host_observation = lock_host_observation();
    let (mut first, _first_port, first_ready) = spawn_listener_process();
    let _first_ready = FileGuard(first_ready);
    let (mut second, _second_port, second_ready) = spawn_listener_process();
    let _second_ready = FileGuard(second_ready);
    let pids = format!("{},{}", first.id(), second.id());

    let killed = kickoutchi_with_stdin(&["kill", "--pid", &pids], "y\n");

    let text = stderr(&killed);
    assert_eq!(killed.status.code(), Some(0), "{text}");
    assert!(text.contains("Terminate 2 processes:"), "{text}");
    assert_eq!(text.matches("to confirm").count(), 1, "{text}");
    assert!(
        text.contains(
            "summary: sent SIGTERM to 2 of 2 process(es); 2 exited; 2 of 2 confirmed port(s) no longer visible; 0 failed"
        ),
        "{text}"
    );
    // A clean batch has no per-process result lines.
    assert!(!text.contains("sent SIGTERM to PID"), "{text}");
    wait_for_child_exit(&mut first);
    wait_for_child_exit(&mut second);
}

#[test]
fn batch_kill_with_an_unknown_target_sends_nothing() {
    let _host_observation = lock_host_observation();
    let (mut helper, _port, ready_file) = spawn_listener_process();
    let _ready_file = FileGuard(ready_file);
    // PID 0 is never a valid kill target.
    let pids = format!("{},0", helper.id());

    let refused = kickoutchi(&["kill", "--pid", &pids, "--yes"]);

    let text = stderr(&refused);
    assert_eq!(refused.status.code(), Some(1), "{text}");
    assert!(
        text.contains("1 of 2 target(s) cannot be killed, so no signal was sent"),
        "{text}"
    );
    assert!(!text.contains("summary:"), "{text}");
    assert_helper_survived_refusal(&mut helper);
}
