//! `sbt template`: saved sandbox templates (spec Phase 5d).

use anyhow::Result;

use super::args::TemplateCmd;
use super::{Ctx, Unsupported};
use crate::smolvm::Runner;

pub fn run<R: Runner>(ctx: &mut Ctx<R>, cmd: TemplateCmd) -> Result<i32> {
    let _ = ctx;
    match cmd {
        TemplateCmd::Inspect(_) => Err(Unsupported(
            "'template inspect' requires --cloud in v1; local templates are smolvm packs; \
             list them with sbt template ls"
                .into(),
        )
        .into()),
        _ => Err(Unsupported("`sbt template` is not implemented yet".into()).into()),
    }
}
