use super::*;

pub(crate) const SKILLS_DIR: &str = "/home/agent/.claude/skills";

/// A published mixin giving an Alpine `shell` sandbox an `agent` account and a read-write-capable
/// `agent-skills@1` directory, plus `more` capabilities and `files` in its layer.
pub(crate) fn skills_kit(
    reg: &Registry,
    files: &[(&str, &str)],
    more: &[serde_json::Value],
) -> String {
    let mut caps = vec![serde_json::json!({
        "type": "com.docker.sandbox/agent-skills@1",
        "config": {"path": SKILLS_DIR, "mode": "readwrite"},
    })];
    caps.extend(more.iter().cloned());
    let mut image = Image::empty().with_agent_account(&Image::alpine());
    if !files.is_empty() {
        image = image.with_files(files);
    }
    reg.push(
        "skills",
        image,
        descriptor("mixin", &["e2e-skills@1.0.0"], caps.into()),
    )
}

/// `skills_kit` that also bundles `/opt/e2e/review` as the skill `review-pr`, so its directory
/// links into the shared mount instead of having it bound over it.
pub(crate) fn bundled_skills_kit(reg: &Registry) -> String {
    skills_kit(
        reg,
        &[("opt/e2e/review/SKILL.md", "---\nname: review-pr\n---\n")],
        &[serde_json::json!({
            "type": "com.docker.sandbox/agent-skill@1",
            "config": {"path": "/opt/e2e/review", "name": "review-pr"},
        })],
    )
}

/// The skills mounts in `/proc/mounts`: `(mount point, "ro"|"rw")`, once each (the guest lists
/// a mount more than once, and the VM's overlay paths too).
pub(crate) fn skills_mounts(name: &str) -> Vec<(String, String)> {
    let mut m: Vec<(String, String)> = root_out(name, "cat /proc/mounts")
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let opt = f[3].split(',').next().unwrap_or_default();
            [SHARED_SKILLS, SKILLS_DIR]
                .contains(&f[1])
                .then(|| (f[1].to_string(), opt.to_string()))
        })
        .collect();
    m.dedup();
    m
}

pub(crate) const SHARED_SKILLS: &str = "/run/sbx/skills-shared";

/// A skill named `name` in the test's own shared store.
pub(crate) fn store_skill(e: &E2e, name: &str) {
    let d = e.dir.path().join("data/agent-skills").join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("SKILL.md"), format!("---\nname: {name}\n---\n")).unwrap();
}

impl E2e {
    /// `create_with_kits` with `--skills mode`, which must succeed.
    pub(crate) fn create_skills_ok(&self, kit: &str, mode: &str) {
        let template = self.alpine_template();
        let head = ["-t", &template, "--kit", kit, "--skills", mode, "shell"];
        let out = self.try_create(&self.name, &head);
        assert!(
            out.status.success(),
            "create --skills {mode} failed:\n{}",
            err_text(&out)
        );
    }
}

/// With a bundled skill the kit's directory links: `readonly` shares the store read-only, the
/// store's entries are links the agent owns, writes through them fail, and every start relinks:
/// gone entries go, new ones come and a directory the agent made wins its name.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn shared_skills_read_only_links_and_relinks() {
    let e = E2e::new("skills-ro");
    let reg = Registry::start(&e);
    store_skill(&e, "alpha");
    store_skill(&e, "gone");
    let kit = bundled_skills_kit(&reg);
    e.create_skills_ok(&kit, "readonly");
    assert_eq!(
        skills_mounts(&e.name),
        [("/run/sbx/skills-shared".to_string(), "ro".to_string())]
    );
    assert_eq!(
        root_out(
            &e.name,
            &format!(
                "stat -c %U {SKILLS_DIR}; readlink {SKILLS_DIR}/alpha; stat -c %U {SKILLS_DIR}/alpha"
            )
        ),
        "agent\n/run/sbx/skills-shared/alpha\nagent\n"
    );
    assert_eq!(
        root_out(&e.name, &format!("cat {SKILLS_DIR}/alpha/SKILL.md")),
        "---\nname: alpha\n---\n"
    );
    let w = e.sbt(&["exec", &e.name, "touch", &format!("{SKILLS_DIR}/alpha/x")]);
    assert!(!w.status.success(), "a write through the link must fail");
    assert!(!e.dir.path().join("data/agent-skills/alpha/x").exists());
    e.ok(&["exec", &e.name, "mkdir", &format!("{SKILLS_DIR}/mine")]);
    std::fs::remove_dir_all(e.dir.path().join("data/agent-skills/gone")).unwrap();
    store_skill(&e, "gamma");
    store_skill(&e, "mine");
    e.ok(&["stop", &e.name]);
    e.ok(&["start", &e.name]);
    assert_eq!(
        root_out(&e.name, &format!("ls -A {SKILLS_DIR}")),
        "alpha\ngamma\nmine\nreview-pr\n"
    );
    assert_eq!(
        root_out(
            &e.name,
            &format!("readlink {SKILLS_DIR}/gamma; readlink {SKILLS_DIR}/review-pr")
        ),
        "/run/sbx/skills-shared/gamma\n/opt/e2e/review\n"
    );
    assert!(
        root_sh(
            &e.name,
            &format!("test -d {SKILLS_DIR}/mine && ! test -L {SKILLS_DIR}/mine")
        )
        .status
        .success(),
        "the agent's own directory keeps its name"
    );
}

/// Without a bundled skill a kit's directory has the store's one mount bound over it: read-only
/// under `readonly` (no links, writes fail), read-write under `readwrite` (writes land in the
/// store); `off` mounts and links nothing. agent-skills@1/same-store-at-every-path: a second,
/// read-only directory is the same store, so a write through the first shows there, even after it
/// was listed. The mount points' parents stay the agent's to write in.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn shared_skills_kit_dirs_are_mounted_over_and_off() {
    let e = E2e::new("skills-rw");
    let reg = Registry::start(&e);
    store_skill(&e, "alpha");
    let ro = "/home/agent/.other/skills";
    let kit = skills_kit(
        &reg,
        &[],
        &[serde_json::json!({
            "type": "com.docker.sandbox/agent-skills@1",
            "config": {"path": ro},
        })],
    );
    e.create_skills_ok(&kit, "readonly");
    assert_eq!(
        skills_mounts(&e.name),
        [
            (SHARED_SKILLS.to_string(), "ro".to_string()),
            (SKILLS_DIR.to_string(), "ro".to_string())
        ]
    );
    assert!(
        root_sh(
            &e.name,
            &format!("test -d {SKILLS_DIR}/alpha && ! test -L {SKILLS_DIR}/alpha")
        )
        .status
        .success(),
        "the store itself, not a link"
    );
    let w = e.sbt(&["exec", &e.name, "mkdir", &format!("{SKILLS_DIR}/mine")]);
    assert!(!w.status.success(), "a read-only mount refuses writes");
    e.ok(&["rm", "-f", &e.name]);

    e.create_skills_ok(&kit, "readwrite");
    assert_eq!(
        skills_mounts(&e.name),
        [
            (SHARED_SKILLS.to_string(), "rw".to_string()),
            (SKILLS_DIR.to_string(), "rw".to_string())
        ]
    );
    assert_eq!(root_out(&e.name, &format!("ls {ro}")), "alpha\n");
    let write = format!("mkdir {SKILLS_DIR}/fromrw && echo x > {SKILLS_DIR}/fromrw/SKILL.md");
    e.sh_ok(&e.name, &write);
    assert_eq!(root_out(&e.name, &format!("ls {ro}")), "alpha\nfromrw\n");
    let w = e.sbt(&["exec", &e.name, "mkdir", &format!("{ro}/mine")]);
    assert!(
        !w.status.success(),
        "the read-only directory refuses writes"
    );
    e.sh_ok(
        &e.name,
        "touch /home/agent/.claude/settings.json /home/agent/.other/x",
    );
    assert_eq!(
        std::fs::read_to_string(e.dir.path().join("data/agent-skills/fromrw/SKILL.md")).unwrap(),
        "x\n"
    );
    e.ok(&["rm", "-f", &e.name]);
    assert!(
        e.dir.path().join("data/agent-skills/fromrw").exists(),
        "the store outlives the sandbox"
    );

    e.create_skills_ok(&kit, "off");
    assert!(skills_mounts(&e.name).is_empty(), "no skills mount");
    assert!(
        !root_sh(&e.name, &format!("test -e {SKILLS_DIR}"))
            .status
            .success()
    );
}

/// A kit's bundled skill (`agent-skill@1`) is linked into its skills directory at the first
/// start. Under `readwrite` (the kit's directory asks for it) the shared mount is read-write, so
/// writes through a store link land in the store.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn bundled_skills_are_linked() {
    let e = E2e::new("skills-bundled");
    let reg = Registry::start(&e);
    store_skill(&e, "alpha");
    let kit = bundled_skills_kit(&reg);
    e.create_skills_ok(&kit, "readwrite");
    assert_eq!(
        skills_mounts(&e.name),
        [("/run/sbx/skills-shared".to_string(), "rw".to_string())]
    );
    assert_eq!(
        root_out(
            &e.name,
            &format!("readlink {SKILLS_DIR}/review-pr; stat -c %U {SKILLS_DIR}/review-pr")
        ),
        "/opt/e2e/review\nagent\n"
    );
    e.ok(&["exec", &e.name, "touch", &format!("{SKILLS_DIR}/alpha/x")]);
    assert!(e.dir.path().join("data/agent-skills/alpha/x").exists());
}
