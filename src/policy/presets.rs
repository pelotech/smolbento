//! The balanced preset: Docker Sandboxes v0.49.2's baseline rules (`sbx policy ls`, 195 entries
//! in six groups), plus the Nix caches smolbento users need.

use super::rules::Resource;

pub const GROUPS: &[(&str, &[&str])] = &[
    (
        "default-ai-services",
        &[
            "api.anthropic.com",
            "statsig.anthropic.com",
            "platform.claude.com",
            "mcp-proxy.anthropic.com",
            "downloads.claude.ai",
            "claude.com",
            "bridge.claudeusercontent.com",
            "**.openai.com",
            "chatgpt.com",
            "**.chatgpt.com",
            "**.oaistatic.com",
            "**.oaiusercontent.com",
            "cdn.openaimerge.com",
            "cursor.com",
            "**.cursor.sh",
            "gemini.google.com",
            "generativelanguage.googleapis.com",
            "play.googleapis.com",
            "api.perplexity.ai",
            "models.dev",
            "factory.ai",
            "**.factory.ai",
            "api.workos.com",
        ],
    ),
    (
        "default-package-managers",
        &[
            "registry.npmjs.org",
            "npmjs.com",
            "npmjs.org",
            "npm.duckdb.org",
            "yarnpkg.com",
            "**.yarnpkg.com",
            "nodejs.org",
            "deb.nodesource.com",
            "bun.sh",
            "**.bun.sh",
            "pypi.org",
            "pypi.python.org",
            "files.pythonhosted.org",
            "pythonhosted.org",
            "pypa.io",
            "bootstrap.pypa.io",
            "astral.sh",
            "crates.io",
            "index.crates.io",
            "static.crates.io",
            "rustup.rs",
            "sh.rustup.rs",
            "static.rust-lang.org",
            "golang.org",
            "goproxy.io",
            "proxy.golang.org",
            "sum.golang.org",
            "pkg.go.dev",
            "maven.org",
            "repo.maven.apache.org",
            "gradle.org",
            "**.gradle.org",
            "spring.io",
            "java.com",
            "java.net",
            "packagist.org",
            "**.packagist.org",
            "packagist.com",
            "rubygems.org",
            "ruby-lang.org",
            "rubyonrails.org",
            "rvm.io",
            "nuget.org",
            "dot.net",
            "dotnet.microsoft.com",
            "pub.dev",
            "hex.pm",
            "cpan.org",
            "metacpan.org",
            "haskell.org",
            "swift.org",
            "cocoapods.org",
            "ziglang.org",
            "apache.org",
            "eclipse.org",
            "tuf-repo-cdn.sigstore.dev",
        ],
    ),
    (
        "default-code-and-containers",
        &[
            "github.com",
            "**.github.com",
            "**.githubusercontent.com",
            "gitlab.com",
            "**.gitlab.com",
            "bitbucket.org",
            "sourceforge.net",
            "launchpad.net",
            "ppa.launchpad.net",
            "docker.io",
            "**.docker.io",
            "docker.com",
            "**.docker.com",
            "production.cloudflare.docker.com",
            "**.production.cloudflare.docker.com",
            "production.cloudfront.docker.com",
            "**.production.cloudfront.docker.com",
            "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
            "dhi.io",
            "dhi.io:80",
            "ghcr.io",
            "gcr.io",
            "**.gcr.io",
            "mcr.microsoft.com",
            "**.data.mcr.microsoft.com",
            "quay.io",
            "registry.k8s.io",
            "k8s.io",
            "public.ecr.aws",
            "d2glxqk2uabbnd.cloudfront.net",
            "**.githubcopilot.com",
            "code.visualstudio.com",
            "vscode.dev",
            "vscode.download.prss.microsoft.com",
        ],
    ),
    (
        "default-cloud-infrastructure",
        &[
            "**.amazonaws.com",
            "**.googleapis.com",
            "azure.com",
            "dev.azure.com",
            "login.microsoftonline.com",
            "**.blob.core.windows.net",
            "visualstudio.com",
            "**.visualstudio.com",
            "packages.microsoft.com",
            "hashicorp.com",
            "**.hashicorp.com",
            "vercel.com",
            "**.public.blob.vercel-storage.com",
            "challenges.cloudflare.com",
            "fastly.com",
            "unpkg.com",
            "jsdelivr.net",
            "**.gvt1.com",
            "dl.google.com",
            "binaries.prisma.sh",
            "playwright.azureedge.net",
            "cdn.playwright.dev",
            "mise.run",
            "mise-versions.jdx.dev",
            "json-schema.org",
            "json.schemastore.org",
            "**.gstatic.com",
            "**.googleusercontent.com",
            "apis.google.com",
            "play.google.com",
            "www.google.com",
            "csp.withgoogle.com",
            "supabase.com",
            "clerk.com",
            "figma.com",
            "app.daytona.io",
        ],
    ),
    (
        "default-os-packages",
        &[
            "archive.ubuntu.com",
            "archive.ubuntu.com:80",
            "security.ubuntu.com",
            "security.ubuntu.com:80",
            "ports.ubuntu.com",
            "ports.ubuntu.com:80",
            "ubuntu.com",
            "debian.org",
            "**.debian.org",
            "archlinux.org",
            "alpinelinux.org",
            "dl-cdn.alpinelinux.org",
            "centos.org",
            "fedoraproject.org",
            "apt.llvm.org",
            "packagecloud.io",
        ],
    ),
    (
        "default-cert-validation",
        &[
            "**.lencr.org:80",
            "**.lencr.org",
            "ocsp.digicert.com:80",
            "crl*.digicert.com:80",
            "cacerts.digicert.com:80",
            "*.one.digicert.com:80",
            "*.one.au.digicert.com:80",
            "*.one.ch.digicert.com:80",
            "*.one.nl.digicert.com:80",
            "*.one.digicert.co.jp:80",
            "ocsp.sectigo.com:80",
            "crl.sectigo.com:80",
            "crt.sectigo.com:80",
            "ocsp.comodoca.com:80",
            "crl.comodoca.com:80",
            "ocsp.usertrust.com:80",
            "crl.usertrust.com:80",
            "**.pki.goog:80",
            "**.pki.goog",
            "**.amazontrust.com:80",
            "**.amazontrust.com",
            "isrg.trustid.ocsp.identrust.com:80",
            "**.pki.microsoft.com:80",
            "**.pki.microsoft.com",
            "crl.globalsign.com:80",
            "crl.globalsign.net:80",
            "ocsp.globalsign.com:80",
            "ocsp.globalsign.com",
            "ocsp2.globalsign.com:80",
            "ocsp2.globalsign.com",
        ],
    ),
    (
        "smolbento-nix",
        &[
            "cache.nixos.org",
            "channels.nixos.org",
            "releases.nixos.org",
            "nixos.org",
        ],
    ),
];

pub fn balanced() -> Vec<Resource> {
    GROUPS
        .iter()
        .flat_map(|(_, rules)| rules.iter())
        .map(|r| Resource::parse(r).expect("preset rules parse"))
        .collect()
}

/// The preset group that allows `target`, if any.
pub fn group_for(target: &str) -> Option<&'static str> {
    GROUPS.iter().find_map(|(name, rules)| {
        rules
            .iter()
            .any(|r| Resource::parse(r).is_ok_and(|r| r.matches(target)))
            .then_some(*name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbx_groups_have_195_rules_and_all_parse() {
        let sbx: usize = GROUPS
            .iter()
            .filter(|(n, _)| n.starts_with("default-"))
            .map(|(_, r)| r.len())
            .sum();
        assert_eq!(sbx, 195);
        assert_eq!(balanced().len(), 199);
    }

    #[test]
    fn groups_for_hosts() {
        assert_eq!(group_for("api.anthropic.com"), Some("default-ai-services"));
        assert_eq!(
            group_for("crl3.digicert.com"),
            Some("default-cert-validation")
        );
        assert_eq!(group_for("cache.nixos.org"), Some("smolbento-nix"));
        assert_eq!(group_for("example.com"), None);
    }
}
