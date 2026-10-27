//! sbx-compatible network policy: the mode and rules in `policy.toml`.

pub mod compile;
pub mod log;
pub mod presets;
pub mod rules;

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::Paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    AllowAll,
    Balanced,
    DenyAll,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::AllowAll => "allow-all",
            Mode::Balanced => "balanced",
            Mode::DenyAll => "deny-all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn name(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub decision: Decision,
    pub resources: Vec<String>,
    #[serde(default = "default_created_via")]
    pub created_via: String,
    /// sbx HTTP qualifiers: stored and shown, not enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl Rule {
    /// The rule's resources, parsed (they were validated when the rule was added).
    pub fn parsed(&self) -> impl Iterator<Item = rules::Resource> + '_ {
        self.resources
            .iter()
            .filter_map(|x| rules::Resource::parse(x).ok())
    }
}

fn default_created_via() -> String {
    "added".into()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Created with `--deny-network`: deny-all whatever the global mode.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deny_network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// `None` until the user chooses (the first `run`/`create` asks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sandboxes: BTreeMap<String, SandboxPolicy>,
}

/// `--method` as one canonical list: uppercase, comma-separated, sorted and deduped.
fn normalise_methods(m: &str) -> Option<String> {
    let mut v: Vec<String> = m
        .split(',')
        .map(|x| x.trim().to_ascii_uppercase())
        .filter(|x| !x.is_empty())
        .collect();
    v.sort();
    v.dedup();
    (!v.is_empty()).then(|| v.join(","))
}

/// A short, stable id from the rule's content, qualifiers included (FNV-1a).
fn rule_id(
    scope: &str,
    decision: Decision,
    resources: &[String],
    method: Option<&str>,
    path: Option<&str>,
) -> String {
    // Qualifiers are appended only when present, so ids of rules without them stay the same.
    let mut input = format!("{scope}|{}|{}", decision.name(), resources.join(","));
    if let Some(m) = method {
        input.push_str(&format!("|method={m}"));
    }
    if let Some(p) = path {
        input.push_str(&format!("|path={p}"));
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("r-{:08x}", h as u32)
}

impl Policy {
    pub fn load(paths: &Paths) -> Result<Policy> {
        crate::config::load_toml(&paths.policy_file())
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        crate::config::save_toml(&paths.policy_file(), self)
    }

    /// The mode a sandbox (or, for `None`, the global policy) runs under. Before any mode was
    /// chosen, sandboxes stay open as they were before policies existed.
    pub fn mode_for(&self, sandbox: Option<&str>) -> Mode {
        if sandbox
            .and_then(|s| self.sandboxes.get(s))
            .is_some_and(|s| s.deny_network)
        {
            return Mode::DenyAll;
        }
        self.mode.unwrap_or(Mode::AllowAll)
    }

    fn rules_mut(&mut self, sandbox: Option<&str>) -> &mut Vec<Rule> {
        match sandbox {
            None => &mut self.rules,
            Some(s) => &mut self.sandboxes.entry(s.to_string()).or_default().rules,
        }
    }

    /// Adds a rule after validating its resources; an identical rule is reused.
    pub fn add_rule(
        &mut self,
        sandbox: Option<&str>,
        decision: Decision,
        resources: &str,
        created_via: &str,
        method: Option<String>,
        path: Option<String>,
    ) -> Result<String> {
        let parsed = rules::parse_list(resources)?;
        let resources: Vec<String> = parsed.into_iter().map(|r| r.raw).collect();
        let method = method.as_deref().and_then(normalise_methods);
        let id = rule_id(
            sandbox.unwrap_or("global"),
            decision,
            &resources,
            method.as_deref(),
            path.as_deref(),
        );
        let list = self.rules_mut(sandbox);
        if list.iter().any(|r| r.id == id) {
            return Ok(id);
        }
        list.push(Rule {
            id: id.clone(),
            decision,
            resources,
            created_via: created_via.to_string(),
            method,
            path,
        });
        Ok(id)
    }

    /// Removes rules by id, or one resource from every rule listing it (dropping emptied rules).
    pub fn remove_rules(
        &mut self,
        sandbox: Option<&str>,
        id: Option<&str>,
        resource: Option<&str>,
    ) -> bool {
        let list = self.rules_mut(sandbox);
        let before: usize = list.iter().map(|r| r.resources.len()).sum();
        if let Some(id) = id {
            list.retain(|r| r.id != id);
        }
        if let Some(res) = resource {
            for r in list.iter_mut() {
                r.resources.retain(|x| !x.eq_ignore_ascii_case(res));
            }
            list.retain(|r| !r.resources.is_empty());
        }
        let after: usize = list.iter().map(|r| r.resources.len()).sum();
        if let Some(s) = sandbox {
            self.prune(s);
        }
        before != after
    }

    /// Drops a sandbox's entry once it holds nothing.
    fn prune(&mut self, sandbox: &str) {
        if self
            .sandboxes
            .get(sandbox)
            .is_some_and(|p| p.rules.is_empty() && !p.deny_network)
        {
            self.sandboxes.remove(sandbox);
        }
    }

    /// Rules that apply to a sandbox, global first, with their sandbox (`None` for global).
    /// `None` gives the global rules only.
    pub fn rules_for<'a>(
        &'a self,
        sandbox: Option<&'a str>,
    ) -> impl Iterator<Item = (&'a Rule, Option<&'a str>)> {
        let own = sandbox.and_then(|s| Some((s, self.sandboxes.get(s)?)));
        self.rules.iter().map(|r| (r, None)).chain(
            own.into_iter()
                .flat_map(|(s, p)| p.rules.iter().map(move |r| (r, Some(s)))),
        )
    }

    /// Every rule, global first, with its sandbox (`None` for global).
    pub fn all_rules(&self) -> impl Iterator<Item = (&Rule, Option<&str>)> {
        self.rules.iter().map(|r| (r, None)).chain(
            self.sandboxes
                .iter()
                .flat_map(|(s, p)| p.rules.iter().map(move |r| (r, Some(s.as_str())))),
        )
    }

    pub fn find(&self, id: &str) -> Option<(&Rule, Option<&str>)> {
        self.all_rules().find(|(r, _)| r.id == id)
    }

    pub fn set_deny_network(&mut self, sandbox: &str, on: bool) {
        self.sandboxes
            .entry(sandbox.to_string())
            .or_default()
            .deny_network = on;
        self.prune(sandbox);
    }

    /// `policy reset`: drops the mode and every rule, but a sandbox created with
    /// `--deny-network` stays deny-all.
    pub fn reset(&mut self) {
        self.mode = None;
        self.rules.clear();
        self.sandboxes.retain(|_, s| s.deny_network);
        for s in self.sandboxes.values_mut() {
            s.rules.clear();
        }
    }

    pub fn forget_sandbox(&mut self, sandbox: &str) {
        self.sandboxes.remove(sandbox);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_default_and_round_trips() {
        let (_d, paths) = crate::config::test_paths();
        let mut p = Policy::load(&paths).unwrap();
        assert_eq!(p, Policy::default());
        p.mode = Some(Mode::Balanced);
        let id = p
            .add_rule(
                None,
                Decision::Allow,
                "api.x.com, *.y.com",
                "added",
                None,
                None,
            )
            .unwrap();
        p.add_rule(
            Some("claude-repo"),
            Decision::Deny,
            "10.0.0.0/8",
            "added",
            None,
            None,
        )
        .unwrap();
        p.set_deny_network("claude-repo", true);
        p.save(&paths).unwrap();
        let back = Policy::load(&paths).unwrap();
        assert_eq!(back, p);
        assert!(id.starts_with("r-"));
        let text = std::fs::read_to_string(paths.policy_file()).unwrap();
        assert!(text.contains("mode = \"balanced\""), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_through_a_symlinked_policy_file() {
        let (d, paths) = crate::config::test_paths();
        let real = d.path().join("dotfiles-policy.toml");
        std::fs::write(&real, "").unwrap();
        std::os::unix::fs::symlink(&real, paths.policy_file()).unwrap();
        let p = Policy {
            mode: Some(Mode::DenyAll),
            ..Default::default()
        };
        p.save(&paths).unwrap();
        let link = std::fs::symlink_metadata(paths.policy_file()).unwrap();
        assert!(link.file_type().is_symlink());
        assert!(std::fs::read_to_string(&real).unwrap().contains("deny-all"));
        assert_eq!(Policy::load(&paths).unwrap(), p);
    }

    #[test]
    fn modes_per_sandbox() {
        let mut p = Policy::default();
        assert_eq!(p.mode_for(Some("a1")), Mode::AllowAll);
        p.mode = Some(Mode::Balanced);
        p.set_deny_network("a1", true);
        assert_eq!(p.mode_for(Some("a1")), Mode::DenyAll);
        assert_eq!(p.mode_for(Some("b1")), Mode::Balanced);
        assert_eq!(p.mode_for(None), Mode::Balanced);
        p.set_deny_network("a1", false);
        assert!(
            p.sandboxes.is_empty(),
            "an entry holding nothing is dropped"
        );
    }

    #[test]
    fn add_validates_dedupes_and_removes() {
        let mut p = Policy::default();
        assert!(
            p.add_rule(None, Decision::Allow, "*", "added", None, None)
                .is_err()
        );
        let a = p
            .add_rule(None, Decision::Allow, "a.com,b.com", "added", None, None)
            .unwrap();
        let again = p
            .add_rule(None, Decision::Allow, "a.com,b.com", "added", None, None)
            .unwrap();
        assert_eq!(a, again);
        assert_eq!(p.rules.len(), 1);
        assert!(p.remove_rules(None, None, Some("a.com")));
        assert_eq!(p.rules[0].resources, vec!["b.com"]);
        assert!(p.remove_rules(None, Some(&a), None));
        assert!(p.rules.is_empty());
    }

    #[test]
    fn method_and_path_make_a_distinct_rule() {
        let mut p = Policy::default();
        let plain = p
            .add_rule(None, Decision::Allow, "a.com", "added", None, None)
            .unwrap();
        // Ids of rules without qualifiers don't change.
        assert_eq!(
            plain,
            rule_id("global", Decision::Allow, &["a.com".into()], None, None)
        );
        assert_eq!(plain, "r-38093da7");
        let get = p
            .add_rule(
                None,
                Decision::Allow,
                "a.com",
                "added",
                Some("GET".into()),
                None,
            )
            .unwrap();
        let path = p
            .add_rule(
                None,
                Decision::Allow,
                "a.com",
                "added",
                None,
                Some("/v1".into()),
            )
            .unwrap();
        assert_ne!(plain, get);
        assert_ne!(plain, path);
        assert_ne!(get, path);
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[1].method.as_deref(), Some("GET"));
        let again = p
            .add_rule(
                None,
                Decision::Allow,
                "a.com",
                "added",
                Some("GET".into()),
                None,
            )
            .unwrap();
        assert_eq!(again, get);
        assert_eq!(p.rules.len(), 3);
    }

    #[test]
    fn methods_are_normalised_so_rules_dedupe() {
        let mut p = Policy::default();
        let a = p
            .add_rule(
                None,
                Decision::Allow,
                "a.com",
                "added",
                Some("get, POST".into()),
                None,
            )
            .unwrap();
        let b = p
            .add_rule(
                None,
                Decision::Allow,
                "a.com",
                "added",
                Some("POST,GET,get".into()),
                None,
            )
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].method.as_deref(), Some("GET,POST"));
    }

    #[test]
    fn reset_keeps_deny_network_and_clears_the_rest() {
        let mut p = Policy {
            mode: Some(Mode::Balanced),
            ..Default::default()
        };
        p.add_rule(None, Decision::Allow, "g.com", "added", None, None)
            .unwrap();
        p.add_rule(Some("s1"), Decision::Allow, "s.com", "added", None, None)
            .unwrap();
        p.add_rule(Some("s2"), Decision::Allow, "t.com", "added", None, None)
            .unwrap();
        p.set_deny_network("s2", true);
        p.reset();
        assert_eq!(p.mode, None);
        assert!(p.rules.is_empty());
        assert_eq!(
            p.sandboxes,
            BTreeMap::from([(
                "s2".to_string(),
                SandboxPolicy {
                    deny_network: true,
                    rules: vec![]
                }
            )])
        );
        assert_eq!(p.mode_for(Some("s2")), Mode::DenyAll);
    }

    #[test]
    fn rules_for_sandbox_and_forget() {
        let mut p = Policy::default();
        p.add_rule(None, Decision::Allow, "g.com", "added", None, None)
            .unwrap();
        p.add_rule(Some("s1"), Decision::Allow, "s.com", "added", None, None)
            .unwrap();
        let scopes: Vec<Option<&str>> = p.rules_for(Some("s1")).map(|(_, s)| s).collect();
        assert_eq!(scopes, [None, Some("s1")]);
        assert_eq!(p.rules_for(Some("other")).count(), 1);
        assert_eq!(p.rules_for(None).count(), 1);
        let id = p.sandboxes["s1"].rules[0].id.clone();
        assert_eq!(p.find(&id).unwrap().1, Some("s1"));
        p.forget_sandbox("s1");
        assert!(p.sandboxes.is_empty());
    }

    #[test]
    fn removing_from_an_unknown_sandbox_leaves_no_entry() {
        let mut p = Policy::default();
        assert!(!p.remove_rules(Some("ghost"), None, Some("a.com")));
        assert!(p.sandboxes.is_empty());
        // A sandbox kept for deny_network survives an empty removal.
        p.sandboxes.entry("s1".into()).or_default().deny_network = true;
        assert!(!p.remove_rules(Some("s1"), Some("r-nope"), None));
        assert!(p.sandboxes["s1"].deny_network);
    }
}
