//! A Smolfile kit: handed to smolvm as-is, so it is a workload with no capabilities of its own.

use std::path::Path;

use anyhow::{Context, Result};

use crate::kits::model::*;
use crate::kits::v3::name_from_source;

/// Checks the file is readable and nothing more: smolvm owns the Smolfile grammar, so parsing it
/// here would only drift from the real one.
pub fn load(path: &Path) -> Result<Kit> {
    std::fs::File::open(path).with_context(|| format!("reading Smolfile {}", path.display()))?;
    let source = Source::Smolfile(path.to_path_buf());
    Ok(Kit {
        name: name_from_source(&source)?,
        source,
        digest: None,
        kind: Kind::Workload,
        provides: vec![],
        requires: vec![],
        integrates: vec![],
        conflicts: vec![],
        args: Default::default(),
        caps: vec![],
        env: vec![],
        content: Content::Smolfile(path.to_path_buf()),
        command: None,
        config: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_smolfile_is_a_workload_passed_through() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("Smolfile");
        std::fs::write(&p, "image = \"alpine\"\n").unwrap();
        let k = load(&p).unwrap();
        assert_eq!(k.kind, Kind::Workload);
        assert_eq!(k.content, Content::Smolfile(p));
        assert!(k.caps.is_empty());
    }

    #[test]
    fn a_missing_smolfile_is_an_error_naming_the_path() {
        let d = tempfile::tempdir().unwrap();
        let e = load(&d.path().join("Smolfile")).unwrap_err();
        assert!(format!("{e:#}").contains("Smolfile"), "{e:#}");
    }
}
