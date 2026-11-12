use super::*;

pub(crate) struct E2e {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) name: String,
    /// Extra environment for every `sbt` call (e.g. `SMOLBENTO_DOCKER=true` for one test).
    pub(crate) vars: Vec<(&'static str, String)>,
    /// Set by [`E2e::one_off_images`].
    pub(crate) no_seeds: std::cell::Cell<bool>,
}

impl E2e {
    pub(crate) fn new(test: &str) -> E2e {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let e = E2e {
            dir,
            name: format!("e2e-{}-{test}", std::process::id()),
            vars: Vec::new(),
            no_seeds: Default::default(),
        };
        e.ok(&["policy", "init", "allow-all"]);
        e
    }

    /// The test boots images made for it alone (kits from its registry, builder builds): smolvm
    /// doesn't keep a ready-made copy of them (`SMOLVM_IMAGE_SEEDS=0`), which nothing would reuse
    /// and which would push your agent images out of smolvm's image cache.
    pub(crate) fn one_off_images(&self) {
        self.no_seeds.set(true);
    }

    pub(crate) fn workspace(&self) -> PathBuf {
        self.dir.path().join("ws").canonicalize().unwrap()
    }

    pub(crate) fn machine(&self) -> String {
        format!("sbx-{}", self.name)
    }

    pub(crate) fn sbt(&self, args: &[&str]) -> Output {
        self.env(Command::new(env!("CARGO_BIN_EXE_smolbento")).args(args))
            .output()
            .unwrap()
    }

    pub(crate) fn env<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.current_dir(self.workspace())
            .env("SMOLBENTO_CONFIG_DIR", self.dir.path().join("config"))
            .env("SMOLBENTO_CACHE_DIR", self.dir.path().join("cache"))
            .env("SMOLBENTO_DATA_DIR", self.dir.path().join("data"))
            .env("SMOLBENTO_DOCKER", "false")
            // Never your SSH agent: only the SSH tests set a throwaway one in `vars`.
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SMOLBENTO_SSH_AGENT_SOCKET")
            .env_remove("SMOLBENTO_SSH_AGENT_FORWARDING")
            .envs(self.vars.iter().map(|(k, v)| (k, v)))
            .envs(self.no_seeds.get().then_some(("SMOLVM_IMAGE_SEEDS", "0")))
    }

    /// Host git in the workspace. The `sandbox-<name>` remote runs `smolbento _upload-pack`, so
    /// `smolbento` (a symlink to this build) goes first on `PATH`, with the same environment as
    /// [`E2e::sbt`].
    pub(crate) fn git(&self, args: &[&str]) -> Output {
        let bin = self.dir.path().join("bin");
        if !bin.exists() {
            std::fs::create_dir_all(&bin).unwrap();
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_smolbento"), bin.join("smolbento"))
                .unwrap();
        }
        let path = std::env::join_paths(
            std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        self.env(
            Command::new("git")
                .args(["-c", "user.name=e2e", "-c", "user.email=e2e@example.com"])
                .args(["-c", "commit.gpgsign=false"])
                .args(args),
        )
        .env("PATH", path)
        .output()
        .unwrap()
    }

    pub(crate) fn git_ok(&self, args: &[&str]) -> String {
        let out = self.git(args);
        assert!(
            out.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    pub(crate) fn ok(&self, args: &[&str]) -> String {
        let out = self.sbt(args);
        assert!(
            out.status.success(),
            "sbt {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Alpine has no `agent` user or bash; add them as root, straight through smolvm. The user
    /// gets the host uid, as smolbento's identity step does for sbx images.
    pub(crate) fn create_alpine(&self) {
        self.create_alpine_with("apk add -q bash");
    }

    /// `create_alpine` without bash, so it needs no network (busybox has `wget`).
    pub(crate) fn create_alpine_offline(&self) {
        self.create_alpine_with("true");
    }

    pub(crate) fn create_alpine_with(&self, then: &str) {
        self.create_alpine_named(&self.name, then);
    }

    /// An Alpine sandbox `name` with an `agent` user of the host's uid, then `then` run as root.
    fn create_alpine_named(&self, name: &str, then: &str) {
        let ws = self.workspace();
        self.ok(&[
            "create",
            "shell",
            ws.to_str().unwrap(),
            "--name",
            name,
            "-t",
            "alpine",
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
        let setup = format!(
            "adduser -D -u {} agent && {then}",
            smolbento::util::host_uid()
        );
        guest_root(name, &setup);
    }

    /// Creates this test's sandbox as a `--clone` of its workspace. A clone sandbox needs git and
    /// the `agent` user from its first start, and plain Alpine has neither (a create that fails
    /// its first start removes the sandbox), so it comes from a template saved with both.
    pub(crate) fn create_clone(&self) {
        let base = format!("{}-base", self.name);
        // Removed below; the guard covers a panic in between.
        let _base = Forks(vec![base.clone()]);
        self.create_alpine_named(&base, "apk add -q git");
        self.ok(&["stop", &base]);
        self.ok(&["template", "save", &base, "e2e-git:v1"]);
        self.ok(&["rm", "-f", &base]);
        let ws = self.workspace();
        self.ok(&[
            "create",
            "--clone",
            "shell",
            ws.to_str().unwrap(),
            "--name",
            &self.name,
            "-t",
            "e2e-git:v1",
            "--pull",
            "never",
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
    }

    pub(crate) fn state(&self) -> String {
        let ls: serde_json::Value = serde_json::from_str(&self.ok(&["ls", "--json"])).unwrap();
        ls.as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == self.name.as_str())
            .map(|s| s["status"].as_str().unwrap().to_string())
            .unwrap_or_else(|| "absent".into())
    }
}

impl Drop for E2e {
    fn drop(&mut self) {
        let _ = Command::new("smolvm")
            .args(["machine", "delete", "-n", &self.machine(), "-f"])
            .output();
    }
}

/// Whether `smolvm args` succeeds.
pub(crate) fn smolvm(args: &[&str]) {
    let out = Command::new("smolvm").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "smolvm {args:?}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A throwaway `registry:2` in its own smolvm machine on a free loopback port, for published-kit
/// fixtures. Each test starts its own: nextest runs every test in a process of its own. `start`
/// also lets `e` load kits from any registry (`kit.allowedSources=["*"]`).
pub(crate) struct Registry {
    pub(crate) machine: String,
    pub(crate) port: u16,
}

impl Registry {
    pub(crate) fn start(e: &E2e) -> Registry {
        e.one_off_images();
        e.ok(&["settings", "set", "kit.allowedSources", r#"["*"]"#]);
        let r = Registry {
            machine: format!("e2e-{}-registry", std::process::id()),
            port: smolbento::sandbox::options::free_port().unwrap(),
        };
        let publish = format!("{}:5000", r.port);
        smolvm(&[
            "machine",
            "run",
            "-d",
            "-n",
            &r.machine,
            "--image",
            "registry:2",
            "--cpus",
            "1",
            "--mem",
            "512",
            "--net",
            "-p",
            &publish,
        ]);
        assert!(wait_until(60, || r.answers()), "the local registry answers");
        r
    }

    pub(crate) fn answers(&self) -> bool {
        use std::io::{Read, Write};
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", self.port)) else {
            return false;
        };
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut body = String::new();
        s.write_all(b"GET /v2/ HTTP/1.0\r\n\r\n").is_ok()
            && s.read_to_string(&mut body).is_ok()
            && body.starts_with("HTTP/1.")
            && body.contains(" 200 ")
    }

    /// `localhost:<port>/e2e/<repo>:1`.
    pub(crate) fn reference(&self, repo: &str) -> String {
        format!("localhost:{}/e2e/{repo}:1", self.port)
    }

    /// Pushes `image` as a kit: the descriptor goes in the manifest annotation, as `sbx kit push`
    /// publishes it.
    pub(crate) fn push(&self, repo: &str, image: Image, descriptor: serde_json::Value) -> String {
        use oci_client::client::{ClientConfig, ClientProtocol, Config, ImageLayer};
        use oci_client::manifest::OciImageManifest;
        use oci_client::secrets::RegistryAuth;
        let reference = self.reference(repo);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = oci_client::Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        });
        let layers: Vec<ImageLayer> = image
            .layers
            .into_iter()
            .map(|(data, media)| ImageLayer::new(data, media, None))
            .collect();
        let config = Config::oci_v1(serde_json::to_vec(&image.config).unwrap(), None);
        let annotations = std::collections::BTreeMap::from([
            (
                "vnd.docker.sandbox.kit.descriptor".to_string(),
                descriptor.to_string(),
            ),
            (
                "vnd.docker.sandbox.kit.schema-version".to_string(),
                "3".to_string(),
            ),
        ]);
        let manifest = OciImageManifest::build(&layers, &config, Some(annotations));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(client.push(
            &reference.parse().unwrap(),
            &layers,
            config,
            &RegistryAuth::Anonymous,
            Some(manifest),
        ))
        .unwrap_or_else(|e| panic!("pushing {reference}: {e}"));
        reference
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = Command::new("smolvm")
            .args(["machine", "delete", "-f", "-n", &self.machine])
            .output();
    }
}

/// Layers (data, media type) and image config of a kit image to push.
pub(crate) struct Image {
    pub(crate) layers: Vec<(Vec<u8>, String)>,
    pub(crate) config: serde_json::Value,
}

pub(crate) fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

impl Image {
    /// No layers: a declaration-only mixin.
    pub(crate) fn empty() -> Image {
        Image {
            layers: Vec::new(),
            config: serde_json::json!({
                "architecture": arch(),
                "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": []},
                "config": {},
            }),
        }
    }

    /// Alpine's layers and config, pulled from Docker Hub with smolbento's own client.
    pub(crate) fn alpine() -> Image {
        Image::pull("alpine")
    }

    /// `reference`'s layers and config, pulled from Docker Hub with smolbento's own client.
    pub(crate) fn pull(reference: &str) -> Image {
        let cache = tempfile::tempdir().unwrap();
        let dir = smolbento::kits::registry::pull_image(
            reference,
            cache.path(),
            smolbento::kits::registry_auth::Logins::none(),
        )
        .unwrap();
        let blob = |d: &serde_json::Value| {
            let hex = d.as_str().unwrap().trim_start_matches("sha256:");
            std::fs::read(dir.join("blobs/sha256").join(hex)).unwrap()
        };
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&blob(&index["manifests"][0]["digest"])).unwrap();
        let layers = manifest["layers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                let media = match l["mediaType"].as_str().unwrap() {
                    "application/vnd.docker.image.rootfs.diff.tar.gzip" => {
                        "application/vnd.oci.image.layer.v1.tar+gzip"
                    }
                    m => m,
                };
                (blob(&l["digest"]), media.to_string())
            })
            .collect();
        Image {
            layers,
            config: serde_json::from_slice(&blob(&manifest["config"]["digest"])).unwrap(),
        }
    }

    /// Appends an uncompressed layer holding `path` (relative, e.g. `opt/x/f`) with `body`.
    pub(crate) fn with_file(self, path: &str, body: &str) -> Image {
        self.with_files(&[(path, body)])
    }

    /// Appends one uncompressed layer holding each `(path, body)`.
    pub(crate) fn with_files(mut self, files: &[(&str, &str)]) -> Image {
        let mut b = tar::Builder::new(Vec::new());
        let mut dirs = std::collections::BTreeSet::new();
        for (path, body) in files {
            let parts: Vec<&str> = path.split('/').collect();
            for i in 1..parts.len() {
                let dir = format!("{}/", parts[..i].join("/"));
                if !dirs.insert(dir.clone()) {
                    continue;
                }
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                h.set_size(0);
                h.set_cksum();
                b.append_data(&mut h, dir, std::io::empty()).unwrap();
            }
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o644);
            h.set_size(body.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
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

impl Image {
    /// The image's `path` (e.g. `etc/passwd`) from its topmost layer that has it, read with the
    /// host's `tar` (which detects gzip itself).
    pub(crate) fn file(&self, path: &str) -> String {
        let dir = tempfile::tempdir().unwrap();
        let layer = dir.path().join("layer");
        for (data, _) in self.layers.iter().rev() {
            std::fs::write(&layer, data).unwrap();
            for member in [path.to_string(), format!("./{path}")] {
                let out = Command::new("tar")
                    .arg("-xOf")
                    .arg(&layer)
                    .arg(&member)
                    .output()
                    .unwrap();
                if out.status.success() && !out.stdout.is_empty() {
                    return String::from_utf8(out.stdout).unwrap();
                }
            }
        }
        panic!("no {path} in the image");
    }
}

pub(crate) fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    let hex: String = sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// A kit descriptor as published: `schemaVersion` 3 plus `kind` and capabilities.
pub(crate) fn descriptor(
    kind: &str,
    provides: &[&str],
    caps: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": "3",
        "kind": kind,
        "provides": provides,
        "capabilities": caps,
    })
}

/// Install hook (as root) giving an Alpine guest the `agent` user, as the identity step would.
pub(crate) fn add_agent_hook() -> String {
    format!(
        "id agent >/dev/null 2>&1 || adduser -D -u {} agent",
        smolbento::util::host_uid()
    )
}

impl E2e {
    /// `sbt create` of an Alpine-based shell sandbox with `kits` (`-t alpine --kit ...`).
    pub(crate) fn create_with_kits(&self, kits: &[&str]) {
        let ws = self.workspace();
        let mut args = vec!["create", "-t", "alpine"];
        for k in kits {
            args.extend(["--kit", k]);
        }
        args.extend([
            "shell",
            ws.to_str().unwrap(),
            "--name",
            &self.name,
            "--cpus",
            "1",
            "-m",
            "1g",
        ]);
        self.ok(&args);
    }
}

/// Root's view of `script` in sandbox `sb`: its stdout, whatever the exit status.
pub(crate) fn root_out(sb: &str, script: &str) -> String {
    String::from_utf8_lossy(&root_sh(sb, script).stdout).into_owned()
}
