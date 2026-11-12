use super::*;

impl Image {
    /// Appends a layer giving Alpine (`base`) an `agent` account with the host's uid and its own
    /// home, as sbx images have one before any kit hook runs: the skills steps hand directories
    /// and links to it, and the tests `sbt exec` as it.
    pub(crate) fn with_agent_account(mut self, base: &Image) -> Image {
        let uid = smolbento::util::host_uid();
        let passwd =
            base.file("etc/passwd") + &format!("agent:x:{uid}:{uid}::/home/agent:/bin/sh\n");
        let group = base.file("etc/group") + &format!("agent:x:{uid}:\n");
        let mut b = tar::Builder::new(Vec::new());
        let mut entry = |path: &str, body: Option<&str>, owner: u64| {
            let mut h = tar::Header::new_gnu();
            h.set_uid(owner);
            h.set_gid(owner);
            match body {
                Some(body) => {
                    h.set_mode(0o644);
                    h.set_size(body.len() as u64);
                    h.set_cksum();
                    b.append_data(&mut h, path, body.as_bytes()).unwrap();
                }
                None => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_mode(0o755);
                    h.set_size(0);
                    h.set_cksum();
                    b.append_data(&mut h, path, std::io::empty()).unwrap();
                }
            }
        };
        entry("etc/", None, 0);
        entry("etc/passwd", Some(&passwd), 0);
        entry("etc/group", Some(&group), 0);
        entry("home/", None, 0);
        entry("home/agent/", None, uid.into());
        let data = b.into_inner().unwrap();
        let diff_id = sha256(&data);
        self.config["rootfs"]["diff_ids"]
            .as_array_mut()
            .unwrap()
            .push(diff_id.into());
        self.layers
            .push((data, "application/vnd.oci.image.layer.v1.tar".to_string()));
        self
    }
}

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
/// links into the shared mount instead of having the store mounted over it.
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
    /// `create_with_kits` with `--skills mode`, returning the output whatever the status.
    pub(crate) fn create_skills(&self, kit: &str, mode: &str) -> Output {
        let ws = self.workspace();
        self.sbt(&[
            "create",
            "-t",
            "alpine",
            "--kit",
            kit,
            "--skills",
            mode,
            "shell",
            ws.to_str().unwrap(),
            "--name",
            &self.name,
            "--cpus",
            "1",
            "-m",
            "1g",
        ])
    }

    /// `create_skills` that must succeed.
    pub(crate) fn create_skills_ok(&self, kit: &str, mode: &str) {
        let out = self.create_skills(kit, mode);
        assert!(
            out.status.success(),
            "create --skills {mode} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
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

/// Without a bundled skill a kit's directory has the store mounted over it: read-only under
/// `readonly` (no links, writes fail), read-write under `readwrite` (writes land in the store);
/// `off` mounts and links nothing.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn shared_skills_kit_dirs_are_mounted_over_and_off() {
    let e = E2e::new("skills-rw");
    let reg = Registry::start(&e);
    store_skill(&e, "alpha");
    let kit = skills_kit(&reg, &[], &[]);
    e.create_skills_ok(&kit, "readonly");
    assert_eq!(
        skills_mounts(&e.name),
        [(SKILLS_DIR.to_string(), "ro".to_string())]
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
        [(SKILLS_DIR.to_string(), "rw".to_string())]
    );
    let write = format!("mkdir {SKILLS_DIR}/fromrw && echo x > {SKILLS_DIR}/fromrw/SKILL.md");
    e.ok(&["exec", &e.name, "sh", "-c", &write]);
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
/// writes through a store link land in the store. A store entry named like the bundled skill
/// fails the create with sbx's message.
#[test]
#[ignore = "boots real VMs and pulls alpine; run with `just e2e`"]
pub(crate) fn bundled_skills_are_linked_and_a_store_clash_fails_the_create() {
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
    e.ok(&["rm", "-f", &e.name]);

    store_skill(&e, "review-pr");
    let out = e.create_skills(&kit, "readonly");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the clash fails the create:\n{err}");
    assert!(
        err.contains(&format!(
            "failed to compose shared skills into the sandbox: bundled skills review-pr cannot \
             be exposed in {SKILLS_DIR}: another skill already uses the name"
        )),
        "{err}"
    );
}
