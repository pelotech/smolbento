//! What an environment file sets up, as a list of resources, and sbx's plan layout for it.

use serde::{Deserialize, Serialize};

/// When a resource takes effect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum When {
    /// When the sandbox is created: a change waits for the next create.
    #[default]
    Create,
    /// At once, also in a sandbox that exists (`env`).
    Live,
    /// On every `env run`, sandbox or not (`initialize`, the launch command).
    EveryRun,
    /// When the environment is removed (`preRemove`).
    Removal,
}

impl When {
    fn is_create(&self) -> bool {
        *self == When::Create
    }
}

/// One thing an environment sets up: a line of the plan with its details. The summary, the plan
/// and the approval check are all computed from the same list of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// The plan section it is listed under (`ENV`, `PORTS`, …). With `id`, its identity.
    pub section: String,
    /// What tells it from the others of its section when the name can change: a lifecycle
    /// command is `initialize[0]` whatever its text. Otherwise the name.
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// The detail lines, as label and value. A literal secret is its digest, never its value.
    pub fields: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "When::is_create")]
    pub when: When,
    /// A path on the user's machine (a workspace, a mount).
    #[serde(default, skip_serializing_if = "is_false")]
    pub host_path: bool,
    /// Runs a command on the user's machine.
    #[serde(default, skip_serializing_if = "is_false")]
    pub host_command: bool,
}

impl Resource {
    pub fn new(section: &str, name: &str, fields: Vec<(String, String)>) -> Resource {
        Resource {
            section: section.into(),
            id: name.into(),
            name: name.into(),
            fields,
            when: When::Create,
            host_path: false,
            host_command: false,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    Add,
    Change,
    Destroy,
    /// A host command that runs again.
    Run,
    /// Present already or run later, and not approved.
    Approve,
}

impl Marker {
    pub fn sign(self) -> char {
        match self {
            Marker::Add => '+',
            Marker::Change => '~',
            Marker::Destroy => '-',
            Marker::Run => '>',
            Marker::Approve => '!',
        }
    }
}

/// A resource as the plan shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub marker: Marker,
    pub resource: Resource,
    /// After the name, behind a dash.
    pub note: Option<&'static str>,
    /// The detail lines as printed: `label: value`, or `label: old -> new` for a change.
    pub fields: Vec<String>,
}

impl Line {
    /// `resource` with its fields as they are.
    pub fn new(marker: Marker, resource: &Resource) -> Line {
        Line {
            marker,
            resource: resource.clone(),
            note: None,
            fields: resource
                .fields
                .iter()
                .map(|(label, value)| format!("{label}: {value}"))
                .collect(),
        }
    }
}

/// The warning under a plan that runs commands on the host.
pub const HOST_COMMANDS: &str =
    "  ! this plan runs commands on this machine, outside the sandbox, with your own privileges\n";
/// The same, when those commands are approved and unchanged but ask all the same.
pub const UNCHANGED_HOST_COMMANDS: &str = "  ! nothing in this plan has changed, but its commands run on this machine, outside the sandbox, with your own privileges, which needs explicit approval on each run\n";

/// The sections (in the order their first line arrives), the count line, and `host_warning` when
/// a line runs a command on the host.
pub fn render(lines: &[Line], host_warning: &str) -> String {
    let mut out = String::new();
    let mut sections: Vec<&str> = Vec::new();
    for l in lines {
        if !sections.contains(&l.resource.section.as_str()) {
            sections.push(&l.resource.section);
        }
    }
    for section in sections {
        out += &format!("\n{section}\n");
        for l in lines.iter().filter(|l| l.resource.section == section) {
            out += &format!("  {} {}", l.marker.sign(), l.resource.name);
            if let Some(note) = l.note {
                out += &format!(" — {note}");
            }
            out.push('\n');
            for f in &l.fields {
                out += &format!("      {f}\n");
            }
        }
    }
    let count = |m: Marker| lines.iter().filter(|l| l.marker == m).count();
    out += &format!(
        "\n  {} to add · {} to change · {} to destroy",
        count(Marker::Add),
        count(Marker::Change),
        count(Marker::Destroy)
    );
    let run = count(Marker::Run);
    if run > 0 {
        out += &format!(" · {run} to run");
    }
    match count(Marker::Approve) {
        0 => {}
        1 => out += " · 1 needs approval",
        n => out += &format!(" · {n} need approval"),
    }
    out.push('\n');
    if lines.iter().any(|l| l.resource.host_command) {
        out += host_warning;
    }
    out
}

#[cfg(test)]
pub(crate) fn resource(section: &str, name: &str, fields: &[(&str, &str)]) -> Resource {
    let fields = fields.iter().map(|(l, v)| (l.to_string(), v.to_string()));
    Resource::new(section, name, fields.collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_groups_sections_and_counts() {
        let env = |name: &str| resource("ENV", name, &[("value", "1")]);
        let mut changed = Line::new(Marker::Change, &env("B"));
        changed.fields = vec!["value: 1 -> 2".into()];
        let mut command = resource("SECRETS", "github", &[("command", "gh auth token")]);
        command.host_command = true;
        let mut approve = Line::new(Marker::Approve, &resource("WORKSPACES", "/w", &[]));
        approve.note = Some("present, not recorded as applied, needs your approval");
        let lines = [
            Line::new(
                Marker::Add,
                &resource("SANDBOX", "web", &[("agent", "claude")]),
            ),
            approve,
            Line::new(Marker::Add, &env("A")),
            Line::new(Marker::Run, &command),
            Line::new(Marker::Approve, &resource("MOUNTS", "/m", &[])),
            changed,
            Line::new(Marker::Destroy, &env("C")),
        ];
        assert_eq!(
            render(&lines, HOST_COMMANDS),
            "\nSANDBOX\n  + web\n      agent: claude\n\
             \nWORKSPACES\n  ! /w — present, not recorded as applied, needs your approval\n\
             \nENV\n  + A\n      value: 1\n  ~ B\n      value: 1 -> 2\n  - C\n      value: 1\n\
             \nSECRETS\n  > github\n      command: gh auth token\n\
             \nMOUNTS\n  ! /m\n\
             \n  2 to add · 1 to change · 1 to destroy · 1 to run · 2 need approval\n\
             \x20 ! this plan runs commands on this machine, outside the sandbox, with your own privileges\n"
        );
    }

    #[test]
    fn render_omits_a_zero_approval_count() {
        assert_eq!(
            render(&[], HOST_COMMANDS),
            "\n  0 to add · 0 to change · 0 to destroy\n"
        );
    }
}
