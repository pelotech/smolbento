//! `bento kit mounts ls|rm`: the directories kept for kits' host mounts (smolbento only; sbx has
//! no command for them).

use std::io::Write;

use anyhow::{Result, bail};

use super::Ctx;
use super::args::KitMountsCmd;
use crate::kits::host_mount;
use crate::sandbox;
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: KitMountsCmd) -> Result<i32> {
    let root = ctx.paths.kit_host_mounts();
    match cmd {
        KitMountsCmd::Ls { output } => {
            let kept = host_mount::kept(&root)?;
            let text = output.structured(&kept)?.unwrap_or_else(|| {
                let rows = kept
                    .iter()
                    .map(|k| {
                        vec![
                            k.id.clone(),
                            k.kit.clone(),
                            k.path.clone(),
                            k.host_path.display().to_string(),
                        ]
                    })
                    .collect();
                super::table(&["ID", "KIT", "PATH", "HOST PATH"], rows)
            });
            write!(&ctx.out, "{text}")?;
        }
        KitMountsCmd::Rm { ids } => {
            let kept = host_mount::kept(&root)?;
            let sandboxes = sandbox::list(&ctx.vm)?;
            for id in &ids {
                // Its contents are a live sandbox's data: refuse while any sandbox mounts it.
                if let Some(k) = kept.iter().find(|k| &k.id == id) {
                    let host = k.host_path.display().to_string();
                    if let Some(sb) = sandboxes
                        .iter()
                        .find(|sb| sb.meta.host_mounts.values().any(|h| *h == host))
                    {
                        bail!(
                            "{id}: sandbox {} mounts it; remove the sandbox first",
                            sb.name()
                        );
                    }
                }
                host_mount::remove(&root, id)?;
                writeln!(&ctx.out, "Removed {id}")?;
            }
        }
    }
    Ok(0)
}
