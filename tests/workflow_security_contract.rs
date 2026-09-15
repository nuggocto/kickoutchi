include!("support/workflow.rs");

use std::collections::BTreeSet;

fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.map(str::to_owned).into_iter().collect()
}

#[test]
fn workflows_pin_actions_and_keep_credentials_and_permissions_narrow() {
    for workflow in [CI_WORKFLOW, FUZZ_WORKFLOW, RELEASE_WORKFLOW] {
        assert_workflow_security(workflow);
    }

    assert_release_job_permissions(&parsed_workflow(RELEASE_WORKFLOW));
}

#[test]
fn ci_covers_native_platforms_nix_arch_and_supply_chain_policy() {
    const LANES: [&str; 6] = ["msrv", "supply-chain", "linux", "nix", "windows", "macos"];

    let ci = parsed_workflow(CI_WORKFLOW);
    let triggers = mapping_value(workflow_root(&ci), "on")
        .map(|value| required_mapping(value, "CI triggers"))
        .expect("CI must define triggers");
    let push = mapping_value(triggers, "push")
        .map(|value| required_mapping(value, "CI push trigger"))
        .expect("CI must define a push trigger");
    assert_eq!(yaml_sequence(push, "branches"), ["shrek"]);
    assert!(mapping_value(triggers, "pull_request").is_some());
    assert!(mapping_value(triggers, "schedule").is_some());

    for lane in LANES {
        assert!(
            job_needs(workflow_job(&ci, lane)).is_empty(),
            "CI lane {lane} must start independently"
        );
    }

    let complete = workflow_job(&ci, "ci-complete");
    assert_eq!(
        job_needs(complete).into_iter().collect::<BTreeSet<_>>(),
        strings(LANES)
    );
    assert!(yaml_scalar(complete, "if").is_some_and(|condition| condition.contains("always()")));

    let linux = workflow_job(&ci, "linux");
    job_step_running(linux, "cargo fmt");
    let msrv = workflow_job(&ci, "msrv");
    assert!(step_script(job_step_running(msrv, "--no-run")).contains("+\"$MSRV\""));
    assert!(step_script(job_step_running(msrv, "--lib")).contains("+\"$MSRV\""));
    for platform in ["linux", "windows", "macos"] {
        let job = workflow_job(&ci, platform);
        job_step_running(job, "cargo clippy");
        job_step_running(job, "cargo test");
        job_step_running(job, "cargo build");
        job_step_running(
            job,
            "required_release_artifact_paths_are_complete_and_versioned",
        );
    }
    let nix = workflow_job(&ci, "nix");
    let nix_systems = matrix_entries(nix)
        .iter()
        .map(|entry| {
            yaml_scalar(required_mapping(entry, "Nix matrix entry"), "system")
                .expect("Nix matrix entry must define a system")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(nix_systems, strings(["aarch64-linux", "x86_64-linux"]));
    assert_eq!(
        yaml_scalar(job_step_running(nix, "nix flake check"), "if").as_deref(),
        Some("${{ matrix.system == 'x86_64-linux' }}")
    );

    let supply_chain = workflow_job(&ci, "supply-chain");
    job_step_running(supply_chain, "makepkg --printsrcinfo");
    let deny = job_step_running(supply_chain, "cargo deny");
    assert!(step_script(deny).contains("--manifest-path fuzz/Cargo.toml"));
}

#[test]
fn scheduled_parser_campaigns_are_pinned_and_bounded() {
    let fuzz = parsed_workflow(FUZZ_WORKFLOW);
    let triggers = mapping_value(workflow_root(&fuzz), "on")
        .map(|value| required_mapping(value, "fuzz triggers"))
        .expect("fuzz workflow must define triggers");
    assert!(mapping_value(triggers, "workflow_dispatch").is_some());
    assert!(mapping_value(triggers, "schedule").is_some());
    assert!(mapping_value(triggers, "push").is_none());
    assert!(mapping_value(triggers, "pull_request").is_none());

    let root_environment = yaml_mapping(workflow_root(&fuzz), "env");
    assert!(root_environment.iter().any(|(name, value)| {
        name == "RUST_NIGHTLY"
            && value.strip_prefix("nightly-").is_some_and(|date| {
                let parts = date.split('-').collect::<Vec<_>>();
                parts.len() == 3
                    && parts.iter().zip([4, 2, 2]).all(|(part, length)| {
                        part.len() == length && part.bytes().all(|byte| byte.is_ascii_digit())
                    })
            })
    }));
    assert!(root_environment.iter().any(|(name, value)| {
        name == "CARGO_FUZZ_VERSION"
            && value.split('.').count() == 3
            && value
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }));

    let campaign = workflow_job(&fuzz, "parser-campaign");
    assert_eq!(matrix_entries(campaign).len(), 3);
    let script = step_script(job_step_running(campaign, "fuzz run"));
    for bound in [
        "-max_total_time=60",
        "-max_len=\"$MAX_INPUT_BYTES\"",
        "-timeout=5",
        "-rss_limit_mb=1024",
    ] {
        assert!(script.contains(bound), "missing parser bound {bound}");
    }
    assert!(script.contains("$RUNNER_TEMP/kickoutchi-fuzz-$PARSER_TARGET"));
    assert!(script.contains("cp -a \"fuzz/corpus/$PARSER_TARGET/.\""));
    assert!(!script.contains("\"fuzz/corpus/$PARSER_TARGET\" \\"));
    assert!(step_script(job_step_running(campaign, "cargo metadata")).contains("--locked"));
}

#[test]
fn release_runs_only_for_tags_or_manual_dry_runs_and_keeps_every_target() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let root = workflow_root(&release);
    let triggers = mapping_value(root, "on")
        .map(|value| required_mapping(value, "release triggers"))
        .expect("release workflow must define triggers");
    assert!(mapping_value(triggers, "workflow_dispatch").is_some());
    assert!(mapping_value(triggers, "push").is_some());
    assert!(mapping_value(triggers, "pull_request").is_none());
    assert!(mapping_value(triggers, "schedule").is_none());

    let concurrency = mapping_value(root, "concurrency")
        .map(|value| required_mapping(value, "release concurrency"))
        .expect("release workflow must serialize publication");
    assert_eq!(
        yaml_scalar(concurrency, "cancel-in-progress").as_deref(),
        Some("false")
    );

    let workspace =
        toml::from_str::<toml::Value>(DIST_WORKSPACE).expect("dist workspace must be valid TOML");
    let dist = workspace
        .get("dist")
        .and_then(toml::Value::as_table)
        .expect("dist workspace must define [dist]");
    let targets = dist
        .get("targets")
        .and_then(toml::Value::as_array)
        .expect("dist must define targets")
        .iter()
        .map(|target| target.as_str().expect("target must be a string").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        targets,
        strings([
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ])
    );
    assert!(dist.get("pr-run-mode").is_none());

    let installers = dist
        .get("installers")
        .and_then(toml::Value::as_array)
        .expect("dist must define installers")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("installer must be a string")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(installers, strings(["homebrew", "powershell", "shell"]));
    assert_eq!(
        dist.get("tap").and_then(toml::Value::as_str),
        Some("nuggocto/homebrew-tap")
    );
    assert_eq!(
        dist.get("publish-jobs")
            .and_then(toml::Value::as_array)
            .expect("Homebrew publication must remain enabled")
            .iter()
            .map(|value| value.as_str().expect("publish job must be a string"))
            .collect::<Vec<_>>(),
        ["homebrew"]
    );
    assert_eq!(
        dist.get("install-updater").and_then(toml::Value::as_bool),
        Some(true)
    );
}

#[test]
fn release_validates_packages_before_attested_publication() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    assert_eq!(
        workflow_job_names(&release)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        strings([
            "attest-release-artifacts",
            "build-global-artifacts",
            "build-local-artifacts",
            "host",
            "plan",
            "publish-homebrew-formula",
            "validate-installers",
            "validate-linux-archives",
        ])
    );

    let local = workflow_job(&release, "build-local-artifacts");
    assert_eq!(job_needs(local), ["plan"]);
    assert!(yaml_scalar(local, "if").is_some_and(|condition| {
        condition.contains("workflow_dispatch") && condition.contains("publishing")
    }));
    let steps = job_steps(local);
    let updater = steps
        .iter()
        .position(|step| step_runs(step, "cargo install --locked axoupdater-cli"))
        .expect("updater must be rebuilt before archive validation");
    let validate = steps
        .iter()
        .position(|step| step_runs(step, "validate_generated_native_archive"))
        .expect("native archive must be validated");
    let upload = steps
        .iter()
        .position(|step| step_uses(step, "actions/upload-artifact"))
        .expect("native artifacts must be uploaded");
    assert!(updater < validate && validate < upload);

    let global = workflow_job(&release, "build-global-artifacts");
    assert!(job_needs(global).contains(&"build-local-artifacts".to_owned()));

    let installers = workflow_job(&release, "validate-installers");
    assert_eq!(job_needs(installers), ["build-global-artifacts"]);
    let installer_entries = matrix_entries(installers);
    assert_eq!(installer_entries.len(), 3);
    let installer_targets = installer_entries
        .iter()
        .map(|entry| {
            yaml_scalar(required_mapping(entry, "installer entry"), "targets_json")
                .expect("installer entry must define one native target")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        installer_targets,
        strings([
            "[\"aarch64-apple-darwin\"]",
            "[\"x86_64-pc-windows-msvc\"]",
            "[\"x86_64-unknown-linux-gnu\"]",
        ])
    );
    job_step_running(installers, "validate_generated_native_installer");

    let attest = workflow_job(&release, "attest-release-artifacts");
    assert!(job_needs(attest).contains(&"validate-installers".to_owned()));
    assert!(yaml_scalar(attest, "if").is_some_and(|condition| condition.contains("publishing")));
    assert!(
        job_steps(attest)
            .iter()
            .any(|step| step_uses(step, "actions/attest"))
    );

    let host = workflow_job(&release, "host");
    assert!(job_needs(host).contains(&"attest-release-artifacts".to_owned()));
    assert!(yaml_scalar(host, "if").is_some_and(|condition| condition.contains("publishing")));
    assert!(
        step_script(job_step_running(host, "dist host"))
            .contains("test \"$TAG_COMMIT\" = \"$RELEASE_COMMIT\"")
    );
    job_step_running(host, "gh release create");

    assert_no_ref_expression_in_scripts(RELEASE_WORKFLOW);
}

#[test]
fn linux_release_archives_are_validated_natively_before_attestation_and_publication() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let native = workflow_job(&release, "validate-linux-archives");
    assert!(mapping_value(native, "container").is_none());
    assert_eq!(job_needs(native), ["build-local-artifacts"]);
    let targets = matrix_entries(native)
        .iter()
        .map(|entry| {
            yaml_scalar(required_mapping(entry, "native Linux entry"), "target")
                .expect("each native Linux runner must select a release target")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        targets,
        strings(["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"])
    );
    let validation = step_script(job_step_running(
        native,
        "validate_generated_native_archive",
    ));
    assert!(validation.contains("unshare --net"));
    assert!(!validation.contains("--pid"));
    assert!(!validation.contains("--user"));
    for job in ["attest-release-artifacts", "host"] {
        assert!(
            job_needs(workflow_job(&release, job)).contains(&"validate-linux-archives".to_owned())
        );
    }
}

#[test]
fn homebrew_publication_is_a_scoped_blocking_handoff_to_the_tap() {
    let release = parsed_workflow(RELEASE_WORKFLOW);
    let homebrew = workflow_job(&release, "publish-homebrew-formula");
    assert!(job_needs(homebrew).contains(&"host".to_owned()));

    let checkout = job_steps(homebrew)
        .into_iter()
        .find(|step| mapping_value(step, "uses").is_some())
        .expect("Homebrew job must check out the tap");
    let checkout_options = mapping_value(checkout, "with")
        .map(|value| required_mapping(value, "Homebrew checkout options"))
        .expect("Homebrew checkout must define options");
    assert_eq!(
        yaml_scalar(checkout_options, "repository").as_deref(),
        Some("nuggocto/homebrew-tap")
    );

    for step in job_steps(homebrew) {
        let token = step_env(step, "GH_TOKEN");
        if step_runs(step, "git push") {
            assert_eq!(token.as_deref(), Some("${{ secrets.HOMEBREW_TAP_TOKEN }}"));
        } else {
            assert!(token.is_none(), "tap token must exist only while pushing");
        }
    }
}

#[test]
fn cargo_dist_and_linux_release_inputs_are_exact_and_immutable() {
    let workspace =
        toml::from_str::<toml::Value>(DIST_WORKSPACE).expect("dist workspace must be valid TOML");
    let dist = workspace
        .get("dist")
        .expect("dist workspace must define [dist]");
    let configured_version = dist
        .get("cargo-dist-version")
        .and_then(toml::Value::as_str)
        .expect("cargo-dist-version must be a string");
    let version_parts = configured_version.split('.').collect::<Vec<_>>();
    assert!(
        version_parts.len() == 3
            && version_parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        "cargo-dist-version must be exact semver: {configured_version}"
    );

    let release = parsed_workflow(RELEASE_WORKFLOW);
    assert_eq!(
        yaml_mapping(workflow_root(&release), "env")
            .into_iter()
            .find_map(|(name, value)| (name == "DIST_VERSION").then_some(value)),
        Some(configured_version.to_owned())
    );
    for job_name in ["plan", "build-local-artifacts"] {
        let scripts = job_steps(workflow_job(&release, job_name))
            .into_iter()
            .filter_map(|step| mapping_value(step, "run").and_then(Value::as_str));
        assert!(
            scripts
                .clone()
                .any(|script| { script.contains("cargo install --locked cargo-dist --version") })
        );
    }

    let runners = dist
        .get("github-custom-runners")
        .and_then(toml::Value::as_table)
        .expect("Linux release builders must be configured");
    for target in ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"] {
        let image = runners
            .get(target)
            .and_then(|runner| runner.get("container"))
            .and_then(|container| container.get("image"))
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{target} must use a container image"));
        let (_, digest) = image
            .rsplit_once("@sha256:")
            .unwrap_or_else(|| panic!("{target} image must be digest pinned"));
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
