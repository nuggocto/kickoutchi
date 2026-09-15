const CI_WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const FUZZ_WORKFLOW: &str = include_str!("../../.github/workflows/fuzz.yml");
const RELEASE_WORKFLOW: &str = include_str!("../../.github/workflows/release.yml");
const DIST_WORKSPACE: &str = include_str!("../../dist-workspace.toml");

use serde_yaml_ng::{Mapping, Value};

fn parsed_workflow(source: &str) -> Value {
    serde_yaml_ng::from_str(source).expect("workflow must be valid YAML")
}

fn mapping_value<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn required_mapping<'a>(value: &'a Value, context: &str) -> &'a Mapping {
    value
        .as_mapping()
        .unwrap_or_else(|| panic!("{context} must be a mapping"))
}

fn required_sequence<'a>(mapping: &'a Mapping, key: &str) -> &'a [Value] {
    mapping_value(mapping, key)
        .and_then(Value::as_sequence)
        .unwrap_or_else(|| panic!("{key} must be a sequence"))
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        _ => panic!("expected a YAML scalar, got {value:?}"),
    }
}

fn yaml_scalar(mapping: &Mapping, key: &str) -> Option<String> {
    mapping_value(mapping, key).map(scalar_text)
}

fn yaml_mapping(mapping: &Mapping, key: &str) -> Vec<(String, String)> {
    required_mapping(
        mapping_value(mapping, key).unwrap_or_else(|| panic!("missing YAML mapping {key}")),
        key,
    )
    .iter()
    .map(|(key, value)| (scalar_text(key), scalar_text(value)))
    .collect()
}

fn yaml_sequence(mapping: &Mapping, key: &str) -> Vec<String> {
    required_sequence(mapping, key)
        .iter()
        .map(scalar_text)
        .collect()
}

fn workflow_root(workflow: &Value) -> &Mapping {
    required_mapping(workflow, "workflow root")
}

fn workflow_jobs(workflow: &Value) -> &Mapping {
    required_mapping(
        mapping_value(workflow_root(workflow), "jobs").expect("workflow must define jobs"),
        "workflow jobs",
    )
}

fn workflow_job<'a>(workflow: &'a Value, name: &str) -> &'a Mapping {
    required_mapping(
        mapping_value(workflow_jobs(workflow), name)
            .unwrap_or_else(|| panic!("missing workflow job {name}")),
        name,
    )
}

fn workflow_job_names(workflow: &Value) -> Vec<String> {
    workflow_jobs(workflow).keys().map(scalar_text).collect()
}

fn job_steps(job: &Mapping) -> Vec<&Mapping> {
    required_sequence(job, "steps")
        .iter()
        .map(|step| required_mapping(step, "workflow step"))
        .collect()
}

fn workflow_steps(workflow: &Value) -> Vec<&Mapping> {
    workflow_jobs(workflow)
        .values()
        .filter_map(Value::as_mapping)
        .filter(|job| mapping_value(job, "steps").is_some())
        .flat_map(job_steps)
        .collect()
}

fn step_runs(step: &Mapping, command: &str) -> bool {
    mapping_value(step, "run")
        .and_then(Value::as_str)
        .is_some_and(|script| {
            script.lines().map(str::trim_start).any(|line| {
                !line.starts_with('#') && line.contains(command)
            })
        })
}

fn step_uses(step: &Mapping, action: &str) -> bool {
    mapping_value(step, "uses")
        .and_then(Value::as_str)
        .is_some_and(|reference| {
            reference
                .split_once('@')
                .is_some_and(|(name, _)| name == action)
        })
}

fn job_step_running<'a>(job: &'a Mapping, command: &str) -> &'a Mapping {
    job_steps(job)
        .into_iter()
        .find(|step| step_runs(step, command))
        .unwrap_or_else(|| panic!("missing workflow command {command}"))
}

fn step_script(step: &Mapping) -> &str {
    mapping_value(step, "run")
        .and_then(Value::as_str)
        .expect("workflow step must define a run script")
}

fn step_env(step: &Mapping, key: &str) -> Option<String> {
    mapping_value(step, "env")
        .map(|value| required_mapping(value, "step environment"))
        .and_then(|environment| yaml_scalar(environment, key))
}

fn job_needs(job: &Mapping) -> Vec<String> {
    match mapping_value(job, "needs") {
        None => Vec::new(),
        Some(Value::Sequence(values)) => values.iter().map(scalar_text).collect(),
        Some(value) => vec![scalar_text(value)],
    }
}

fn matrix_entries(job: &Mapping) -> &[Value] {
    let strategy = required_mapping(
        mapping_value(job, "strategy").expect("matrix job must define a strategy"),
        "job strategy",
    );
    let matrix = required_mapping(
        mapping_value(strategy, "matrix").expect("strategy must define a matrix"),
        "job matrix",
    );
    required_sequence(matrix, "include")
}

fn assert_workflow_security(source: &str) {
    let workflow = parsed_workflow(source);
    assert_eq!(
        yaml_mapping(workflow_root(&workflow), "permissions"),
        [("contents".to_owned(), "read".to_owned())]
    );
    assert_permission_maps(&workflow);

    let mut action_count = 0;
    for step in workflow_steps(&workflow) {
        let Some(reference) = mapping_value(step, "uses").and_then(Value::as_str) else {
            continue;
        };
        action_count += 1;
        let (action, revision) = reference
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("action must specify a revision: {reference}"));
        assert!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "action must use a full commit SHA: {reference}"
        );
        if action == "actions/checkout" {
            let options = required_mapping(
                mapping_value(step, "with").expect("checkout must define options"),
                "checkout options",
            );
            assert_eq!(
                mapping_value(options, "persist-credentials").and_then(Value::as_bool),
                Some(false)
            );
            assert!(mapping_value(options, "token").is_none());
        }
    }
    assert!(action_count > 0, "workflow must use at least one action");
}

fn assert_permission_maps(value: &Value) {
    match value {
        Value::Mapping(mapping) => mapping.iter().for_each(|(key, value)| {
            if key.as_str() == Some("permissions") {
                assert!(value.as_mapping().is_some(), "permissions must be explicit");
            }
            assert_permission_maps(value);
        }),
        Value::Sequence(sequence) => sequence.iter().for_each(assert_permission_maps),
        Value::Tagged(tagged) => assert_permission_maps(&tagged.value),
        _ => {}
    }
}

fn assert_release_job_permissions(workflow: &Value) {
    for name in workflow_job_names(workflow) {
        let job = workflow_job(workflow, &name);
        let permissions =
            mapping_value(job, "permissions").map(|_| yaml_mapping(job, "permissions"));
        match name.as_str() {
            "host" => assert_eq!(permissions, Some(vec![("contents".into(), "write".into())])),
            "attest-release-artifacts" => assert_eq!(
                permissions,
                Some(vec![
                    ("contents".into(), "read".into()),
                    ("id-token".into(), "write".into()),
                    ("attestations".into(), "write".into()),
                ])
            ),
            _ => assert!(
                permissions.is_none_or(|values| values.iter().all(|(_, access)| access == "read")),
                "release job {name} has unnecessary write access"
            ),
        }
    }
}

fn assert_no_ref_expression_in_scripts(workflow: &str) {
    for step in workflow_steps(&parsed_workflow(workflow)) {
        if let Some(script) = mapping_value(step, "run").and_then(Value::as_str) {
            assert!(!script.contains("${{ github.ref"));
        }
    }
}
