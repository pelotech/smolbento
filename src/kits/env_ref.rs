//! A kit variable that refers to itself (`PATH: /opt/kit/bin:$PATH`) gets the image's value of
//! that variable in place of the reference, as sbx gives it and as a Dockerfile's
//! `ENV PATH=/opt/kit/bin:$PATH` does.
//!
//! A workaround: smolvm lays the variables smolbento gives over the image's own without expanding
//! them, so smolbento reads the image's environment and expands them itself. Delete this module
//! and its one call in `kits::apply` once smolvm does it.

/// Whether `value` refers to `name` itself, as `$NAME` or `${NAME}`.
pub fn refers_to_itself(name: &str, value: &str) -> bool {
    expand(name, value, "\u{0}") != value
}

/// `value` with each `$NAME` and `${NAME}` replaced by `image_value`. Other references stay as
/// written.
pub fn expand(name: &str, value: &str, image_value: &str) -> String {
    let braced = format!("${{{name}}}");
    let plain = format!("${name}");
    let continues = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut rest = value;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let at = &rest[i..];
        if let Some(after) = at.strip_prefix(&braced) {
            out.push_str(image_value);
            rest = after;
        } else if let Some(after) = at
            .strip_prefix(&plain)
            .filter(|a| !a.starts_with(continues))
        {
            out.push_str(image_value);
            rest = after;
        } else {
            out.push('$');
            rest = &at[1..];
        }
    }
    out.push_str(rest);
    out
}

/// The image's value of `name` from its `KEY=VALUE` environment; empty when it has none, as in
/// a Dockerfile.
pub fn image_value<'a>(image_env: &'a [String], name: &str) -> &'a str {
    image_env
        .iter()
        .find_map(|e| e.strip_prefix(name)?.strip_prefix('='))
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_variable_itself_is_expanded() {
        let image = "/usr/bin:/bin";
        assert_eq!(
            expand("PATH", "/opt/x:$PATH", image),
            "/opt/x:/usr/bin:/bin"
        );
        assert_eq!(
            expand("PATH", "/opt/x:${PATH}", image),
            "/opt/x:/usr/bin:/bin"
        );
        assert_eq!(
            expand("PATH", "$PATH:/a:$PATH", image),
            "/usr/bin:/bin:/a:/usr/bin:/bin"
        );
        // Another name, a longer one, or a lone `$` stays as written.
        assert_eq!(
            expand("PATH", "/b:$HOME:$PATHX:$:${P}", image),
            "/b:$HOME:$PATHX:$:${P}"
        );
        assert!(refers_to_itself("PATH", "/opt/x:$PATH"));
        assert!(!refers_to_itself("PATH", "/opt/x:$HOME"));
        assert!(!refers_to_itself("BRACED", "/opt/b:${PATH}"));
    }

    #[test]
    fn the_image_value_is_looked_up_by_exact_name() {
        let env = ["PATHX=/no".to_string(), "PATH=/usr/bin".to_string()];
        assert_eq!(image_value(&env, "PATH"), "/usr/bin");
        assert_eq!(image_value(&env, "HOME"), "");
    }
}
