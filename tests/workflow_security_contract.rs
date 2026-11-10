include!("support/workflow.rs");

#[test]
fn workflows_pin_actions_and_keep_credentials_and_permissions_narrow() {
    for workflow in [CI_WORKFLOW, FUZZ_WORKFLOW, RELEASE_WORKFLOW] {
        assert_workflow_security(workflow);
    }

    assert_release_job_permissions(&parsed_workflow(RELEASE_WORKFLOW));
    assert_no_ref_expression_in_scripts(RELEASE_WORKFLOW);
}

#[test]
fn release_runs_only_for_tags_or_manual_dry_runs() {
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
            .get("DIST_VERSION")
            .map(String::as_str),
        Some(configured_version)
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
