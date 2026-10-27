//! sbx-compatible network policy: the mode and rules in `policy.toml`.

pub mod compile;
pub mod log;
pub mod presets;
pub mod rules;

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::Paths;
use crate::kits::model::Rules;

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

/// `created_via` of a kit's runtime rules: `kit:<kit>`.
pub const KIT_VIA: &str = "kit:";
/// `created_via` of a kit's install-phase rules: `kit-install:<kit>`. Only the steps that run the
/// install hooks compile them (`compile::network_with`), so one left behind by an interrupted
/// create never opens a later start.
pub const KIT_INSTALL_VIA: &str = "kit-install:";

impl Rule {
    /// The rule's resources, parsed (they were validated when the rule was added).
    pub fn parsed(&self) -> impl Iterator<Item = rules::Resource> + '_ {
        self.resources
            .iter()
            .filter_map(|x| rules::Resource::parse(x).ok())
    }

    /// Where the rule came from: "kit" when a kit added it (runtime or install phase), else
    /// "local".
    pub fn source(&self) -> &'static str {
        if self.created_via.starts_with(KIT_VIA) || self.is_kit_install() {
            "kit"
        } else {
            "local"
        }
    }

    /// An install-phase kit rule.
    pub fn is_kit_install(&self) -> bool {
        self.created_via.starts_with(KIT_INSTALL_VIA)
    }
}

fn default_created_via() -> String {
    "added".into()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Deny-all whatever the global mode. Kept for policy files written by v0.2.0, whose
    /// `--deny-network` set it; nothing sets it any more.
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

/// What a rule id hashes as its scope: kit rules get their kit too, so they never share an id
/// with a user rule for the same resources. A kit's install and runtime rules share the scope: an
/// install rule that is also a runtime rule is the runtime rule, and outlives the install phase.
fn id_scope(sandbox: &str, created_via: &str) -> String {
    let kit = created_via
        .strip_prefix(KIT_VIA)
        .or_else(|| created_via.strip_prefix(KIT_INSTALL_VIA));
    match kit {
        Some(kit) => format!("{sandbox}|kit={kit}"),
        None => sandbox.to_string(),
    }
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
            &id_scope(sandbox.unwrap_or("global"), created_via),
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

    /// Adds a kit's rules for `sandbox` with `created_via = "kit:<kit>"`, or for its install-phase
    /// rules (`install`) `"kit-install:<kit>"`. Returns
    /// `(all, added)`: the ids of every rule now in place, and the subset this call created.
    /// Adding the same rules again is a no-op, so a caller rolling back removes only `added`
    /// (via `remove_rules_by_ids`), never a rule that was there before.
    /// A rule carries one path, so each path of an entry gets its own rule.
    pub fn add_kit_rules(
        &mut self,
        sandbox: &str,
        kit: &str,
        rules: &Rules,
        install: bool,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let via = format!("{}{kit}", if install { KIT_INSTALL_VIA } else { KIT_VIA });
        let (mut all, mut added) = (Vec::new(), Vec::new());
        for (decision, list) in [
            (Decision::Allow, &rules.allow),
            (Decision::Deny, &rules.deny),
        ] {
            for n in list {
                let method = (!n.methods.is_empty()).then(|| n.methods.join(","));
                let paths: Vec<Option<String>> = if n.paths.is_empty() {
                    vec![None]
                } else {
                    n.paths.iter().cloned().map(Some).collect()
                };
                for path in paths {
                    let before: Vec<String> = self
                        .rules_mut(Some(sandbox))
                        .iter()
                        .map(|r| r.id.clone())
                        .collect();
                    let id = self.add_rule(
                        Some(sandbox),
                        decision,
                        &n.host,
                        &via,
                        method.clone(),
                        path,
                    )?;
                    // A runtime rule that an interrupted create left as an install rule becomes
                    // a runtime rule again.
                    if !install
                        && let Some(r) = self
                            .rules_mut(Some(sandbox))
                            .iter_mut()
                            .find(|r| r.id == id && r.is_kit_install())
                    {
                        r.created_via = via.clone();
                    }
                    if !before.contains(&id) && !added.contains(&id) {
                        added.push(id.clone());
                    }
                    if !all.contains(&id) {
                        all.push(id);
                    }
                }
            }
        }
        Ok((all, added))
    }

    /// Removes the sandbox's kit rules (runtime or install phase) with these ids; a user's rule
    /// with one of them stays.
    pub fn remove_rules_by_ids(&mut self, sandbox: &str, ids: &[String]) {
        self.rules_mut(Some(sandbox))
            .retain(|r| !(ids.contains(&r.id) && r.source() == "kit"));
        self.prune(sandbox);
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

    /// Copies `from`'s per-sandbox entry (rules and `deny_network`) to `to`, e.g. for a fork.
    /// Rule ids hash their scope, so the copies get ids derived for `to`. Replaces any existing
    /// entry for `to`; without an entry for `from` it does nothing (`to`'s entry stays).
    pub fn copy_sandbox(&mut self, from: &str, to: &str) {
        let Some(mut entry) = self.sandboxes.get(from).cloned() else {
            return;
        };
        // Install-phase rules belong to `from`'s (unfinished) create, not to the copy.
        entry.rules.retain(|r| !r.is_kit_install());
        for r in &mut entry.rules {
            r.id = rule_id(
                &id_scope(to, &r.created_via),
                r.decision,
                &r.resources,
                r.method.as_deref(),
                r.path.as_deref(),
            );
        }
        self.sandboxes.insert(to.to_string(), entry);
    }

    /// `policy reset`: drops the mode and every rule, but a sandbox with the v0.2.0
    /// `deny_network` flag stays deny-all.
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
    fn copy_sandbox_clones_rules_and_deny_network() {
        let mut p = Policy::default();
        p.add_rule(Some("a"), Decision::Deny, "evil.com", "added", None, None)
            .unwrap();
        p.set_deny_network("a", true);
        p.copy_sandbox("a", "a-fork-1");
        assert_eq!(p.sandboxes["a-fork-1"].rules.len(), 1);
        assert!(p.sandboxes["a-fork-1"].deny_network);
        assert_ne!(
            p.sandboxes["a-fork-1"].rules[0].id,
            p.sandboxes["a"].rules[0].id
        );
        p.copy_sandbox("none", "x");
        assert!(!p.sandboxes.contains_key("x"));
    }

    #[test]
    fn a_copied_rule_is_removed_by_its_own_id_only() {
        let mut p = Policy::default();
        p.add_rule(Some("a"), Decision::Deny, "evil.com", "added", None, None)
            .unwrap();
        p.copy_sandbox("a", "a-fork-1");
        let copy_id = p.sandboxes["a-fork-1"].rules[0].id.clone();
        let parent_id = p.sandboxes["a"].rules[0].id.clone();
        // The parent's id doesn't name the copy's rule.
        assert!(!p.remove_rules(Some("a-fork-1"), Some(&parent_id), None));
        assert!(p.remove_rules(Some("a-fork-1"), Some(&copy_id), None));
        assert!(!p.sandboxes.contains_key("a-fork-1"));
        assert_eq!(p.sandboxes["a"].rules.len(), 1);
        assert_eq!(p.sandboxes["a"].rules[0].id, parent_id);
    }

    #[test]
    fn copy_sandbox_copies_a_deny_network_only_entry_and_replaces_the_target() {
        let mut p = Policy::default();
        p.set_deny_network("a", true);
        p.add_rule(Some("b"), Decision::Deny, "old.com", "added", None, None)
            .unwrap();
        p.copy_sandbox("a", "a-fork-1");
        assert!(p.sandboxes["a-fork-1"].deny_network);
        assert!(p.sandboxes["a-fork-1"].rules.is_empty());
        p.copy_sandbox("a", "b");
        assert!(p.sandboxes["b"].deny_network);
        assert!(p.sandboxes["b"].rules.is_empty(), "replaced, not merged");
    }

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

    fn net(host: &str, methods: &[&str], paths: &[&str]) -> crate::kits::model::NetRule {
        crate::kits::model::NetRule {
            host: host.into(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn kit_rules_are_tagged_distinct_and_idempotent() {
        let mut p = Policy::default();
        let user = p
            .add_rule(Some("sb"), Decision::Allow, "a.com", "added", None, None)
            .unwrap();
        let rules = Rules {
            allow: vec![
                net("a.com", &[], &[]),
                net("b.com", &["get", "post"], &["/x", "/y"]),
            ],
            deny: vec![net("bad.com", &[], &[])],
        };
        let (all, added) = p.add_kit_rules("sb", "gh", &rules, false).unwrap();
        // a.com, b.com x 2 paths, bad.com
        assert_eq!((all.len(), added.len()), (4, 4));
        assert!(!all.contains(&user), "kit id differs from the user's rule");
        let sb = &p.sandboxes["sb"].rules;
        assert_eq!(sb.len(), 5);
        assert!(
            sb.iter()
                .filter(|r| r.source() == "kit")
                .all(|r| r.created_via == "kit:gh")
        );
        assert_eq!(sb[0].source(), "local");
        let b = sb.iter().find(|r| r.path.as_deref() == Some("/y")).unwrap();
        assert_eq!(b.method.as_deref(), Some("GET,POST"));

        // Again: same ids, nothing new, no duplicates.
        let (all2, added2) = p.add_kit_rules("sb", "gh", &rules, false).unwrap();
        assert_eq!((all2, added2.len()), (all.clone(), 0));
        assert_eq!(p.sandboxes["sb"].rules.len(), 5);

        p.remove_rules_by_ids("sb", &all);
        assert_eq!(p.sandboxes["sb"].rules.len(), 1);
        assert_eq!(p.sandboxes["sb"].rules[0].id, user);
        // Only kit rules go by id this way.
        p.remove_rules_by_ids("sb", std::slice::from_ref(&user));
        assert_eq!(p.sandboxes["sb"].rules[0].id, user);
    }

    #[test]
    fn install_rules_apply_only_when_named_and_are_not_forked() {
        let mut p = Policy {
            mode: Some(Mode::DenyAll),
            ..Default::default()
        };
        let rules = |h: &str| Rules {
            allow: vec![net(h, &[], &[])],
            deny: vec![],
        };
        p.add_kit_rules("sb", "gh", &rules("run.kit.com"), false)
            .unwrap();
        let (_, install) = p
            .add_kit_rules("sb", "gh", &rules("pkg.kit.com"), true)
            .unwrap();
        // The same host for install as for runtime is the runtime rule.
        let (_, dup) = p
            .add_kit_rules("sb", "gh", &rules("run.kit.com"), true)
            .unwrap();
        assert!(dup.is_empty());
        let r = p.find(&install[0]).unwrap().0;
        assert_eq!(
            (r.created_via.as_str(), r.source()),
            ("kit-install:gh", "kit")
        );
        let plain = format!("{:?}", compile::network(&p, "sb", &[]));
        assert!(
            plain.contains("run.kit.com") && !plain.contains("pkg.kit.com"),
            "{plain}"
        );
        assert!(!compile::check(&p, Some("sb"), &[], "pkg.kit.com").allowed);
        let with = format!("{:?}", compile::network_with(&p, "sb", &[], &install));
        assert!(with.contains("pkg.kit.com"), "{with}");
        p.copy_sandbox("sb", "fork");
        assert!(
            p.sandboxes["fork"]
                .rules
                .iter()
                .all(|r| !r.is_kit_install())
        );
        // A runtime rule an interrupted create left as an install rule is a runtime one again.
        let (_, again) = p
            .add_kit_rules("sb", "gh", &rules("pkg.kit.com"), false)
            .unwrap();
        assert!(again.is_empty());
        assert_eq!(p.find(&install[0]).unwrap().0.created_via, "kit:gh");
        p.forget_sandbox("sb");
        assert!(!p.sandboxes.contains_key("sb"));
    }

    #[test]
    fn kit_rules_apply_to_their_sandbox_and_a_user_deny_wins() {
        let mut p = Policy {
            mode: Some(Mode::DenyAll),
            ..Default::default()
        };
        let rules = Rules {
            allow: vec![net("api.kit.com", &[], &[])],
            deny: vec![],
        };
        p.add_kit_rules("sb", "gh", &rules, false).unwrap();
        let spec = |sb: &str| format!("{:?}", compile::network(&p, sb, &[]));
        assert!(spec("sb").contains("api.kit.com"));
        assert!(!spec("other").contains("api.kit.com"));
        assert!(compile::check(&p, Some("sb"), &[], "api.kit.com").allowed);
        assert!(!compile::check(&p, Some("other"), &[], "api.kit.com").allowed);

        p.add_rule(
            Some("sb"),
            Decision::Deny,
            "api.kit.com",
            "added",
            None,
            None,
        )
        .unwrap();
        assert!(!compile::check(&p, Some("sb"), &[], "api.kit.com").allowed);
    }
}
