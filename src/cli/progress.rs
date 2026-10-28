//! Progress lines for create/run/start, in sbx's layout, written to `ctx.out`.
// Wired into create/run/start in the next change; drop this then.
#![allow(dead_code)]

use std::io::Write;

use super::{Ctx, Out};
use crate::smolvm::Runner;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BLUE: &str = "94";
const GREY: &str = "90";
const MAGENTA: &str = "35";
const GREEN: &str = "32";
const RED: &str = "31";
/// Moves up one line and clears it.
const UP_CLEAR: &str = "\x1b[1A\r\x1b[K";

/// Writes sections, fields and steps. On a terminal a step is one line redrawn in place; otherwise
/// each step prints when it starts and when it ends. `quiet` makes every call a no-op. Cloning is
/// cheap; clones write to the same output.
#[derive(Clone)]
pub struct Progress {
    out: Out,
    tty: bool,
    color: bool,
    quiet: bool,
}

/// One step started with [`Progress::step`]; end it with `done` or `fail`.
pub struct Step {
    p: Progress,
    subject: String,
    doing: String,
    frame: usize,
    /// Lines drawn on a terminal (the step, then its detail); 0 once ended or when not drawing.
    lines: usize,
}

impl Progress {
    pub fn new(out: Out, tty: bool, color: bool, quiet: bool) -> Self {
        Self {
            out,
            tty,
            color,
            quiet,
        }
    }

    /// A reporter on `ctx.out`: redraws on a terminal, coloured unless `NO_COLOR` is set.
    pub fn for_ctx<R: Runner>(ctx: &Ctx<R>, quiet: bool) -> Self {
        let no_color = ctx.env.get("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self::new(
            ctx.out.clone(),
            ctx.stdout_tty,
            ctx.stdout_tty && !no_color,
            quiet,
        )
    }

    /// A blank line and a header, `SANDBOX`.
    pub fn section(&self, title: &str) {
        let title = if self.tty {
            self.paint(BLUE, &format!("  {title}"))
        } else {
            title.to_string()
        };
        self.write(&format!("\n{title}\n"));
    }

    /// `  Key:       value`, values aligned at column 14.
    pub fn field(&self, key: &str, value: &str) {
        let key = format!("{key}:");
        let pad = " ".repeat(12usize.saturating_sub(key.chars().count()).max(1));
        self.write(&format!("  {}{pad}{value}\n", self.paint(GREY, &key)));
    }

    /// Starts `  ○ subject — doing…`.
    pub fn step(&self, subject: &str, doing: &str) -> Step {
        let mut step = Step {
            p: self.clone(),
            subject: subject.to_string(),
            doing: doing.to_string(),
            frame: 0,
            lines: 0,
        };
        if self.drawing() {
            step.draw(None);
        } else {
            self.write(&format!("  ○ {subject} — {doing}…\n"));
        }
        step
    }

    /// A blank line and `  ✓ line`.
    pub fn finish(&self, line: &str) {
        self.write(&format!("\n  {} {line}\n", self.paint(GREEN, "✓")));
    }

    /// `        try: cmd`.
    pub fn hint(&self, cmd: &str) {
        self.write(&format!("        {} {cmd}\n", self.paint(BLUE, "try:")));
    }

    fn drawing(&self) -> bool {
        self.tty && !self.quiet
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[m")
        } else {
            text.to_string()
        }
    }

    /// Progress is best effort: a failed write must not fail the command it describes.
    fn write(&self, s: &str) {
        if !self.quiet {
            let _ = (&self.out).write_all(s.as_bytes());
            let _ = (&self.out).flush();
        }
    }
}

impl Step {
    /// Redraws the step with `text` under it and the next spinner frame. Terminal only.
    pub fn detail(&mut self, text: &str) {
        if self.lines > 0 {
            self.frame = (self.frame + 1) % SPINNER.len();
            self.draw(Some(text));
        }
    }

    /// `  ✓ subject — word`.
    pub fn done(mut self, word: &str) {
        let mark = self.p.paint(GREEN, "✓");
        self.end(&format!("  {mark} {} — {word}\n", self.subject));
    }

    /// `  ✗ subject — failed`; the caller then reports the error as usual.
    pub fn fail(mut self) {
        let mark = self.p.paint(RED, "✗");
        self.end(&format!("  {mark} {} — failed\n", self.subject));
    }

    fn draw(&mut self, detail: Option<&str>) {
        let mut s = UP_CLEAR.repeat(self.lines);
        let frame = self.p.paint(MAGENTA, SPINNER[self.frame]);
        s += &format!("  {frame} {} — {}…\n", self.subject, self.doing);
        self.lines = 1;
        if let Some(text) = detail {
            s += &format!("        {text}\n");
            self.lines = 2;
        }
        self.p.write(&s);
    }

    fn end(&mut self, line: &str) {
        if self.lines > 0 {
            self.p
                .write(&format!("{}{line}", UP_CLEAR.repeat(self.lines)));
            self.lines = 0;
        } else {
            self.p.write(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reporter(tty: bool, color: bool, quiet: bool) -> (Progress, Out) {
        let out = Out::Buffer(Default::default());
        (Progress::new(out.clone(), tty, color, quiet), out)
    }

    fn text(out: &Out) -> String {
        match out {
            Out::Buffer(b) => String::from_utf8(b.take()).unwrap(),
            Out::Stdout => unreachable!(),
        }
    }

    /// The create sequence the spec quotes from sbx.
    fn create(p: &Progress) {
        p.section("SANDBOX");
        p.field("Name", "chk-pg1");
        p.field("Workspace", "/path/ws (rw)");
        p.section("IMAGE");
        let mut s = p.step("image", "pulling");
        s.detail("42%");
        s.detail("syncing");
        s.done("ready");
        p.step("kit", "building").fail();
        p.finish("Created sandbox chk-pg1");
        p.hint("sbt run --name chk-pg1");
    }

    #[test]
    fn non_tty_prints_plain_lines_once() {
        let (p, out) = reporter(false, false, false);
        create(&p);
        assert_eq!(
            text(&out),
            "\nSANDBOX\n  Name:       chk-pg1\n  Workspace:  /path/ws (rw)\n\nIMAGE\n\
             \x20 ○ image — pulling…\n  ✓ image — ready\n\
             \x20 ○ kit — building…\n  ✗ kit — failed\n\
             \n  ✓ Created sandbox chk-pg1\n        try: sbt run --name chk-pg1\n"
        );
    }

    #[test]
    fn tty_redraws_with_colour() {
        let (p, out) = reporter(true, true, false);
        create(&p);
        insta::assert_snapshot!(text(&out).replace('\x1b', "\\e").replace('\r', "\\r"));
    }

    #[test]
    fn no_color_keeps_redraws_without_colour_codes() {
        let (p, out) = reporter(true, false, false);
        create(&p);
        let s = text(&out);
        assert!(s.contains("\x1b[1A\r\x1b[K"), "{s:?}");
        assert!(!s.contains("\x1b[9"), "{s:?}");
        assert!(!s.contains("\x1b[3"), "{s:?}");
        assert!(s.contains("  ✓ image — ready\n"), "{s:?}");
    }

    #[test]
    fn quiet_prints_nothing() {
        for tty in [false, true] {
            let (p, out) = reporter(tty, tty, true);
            create(&p);
            assert_eq!(text(&out), "");
        }
    }

    #[test]
    fn for_ctx_colours_only_a_tty_without_no_color() {
        let mut t = super::super::testutil::test_env(&[]);
        let colour = |t: &super::super::testutil::TestEnv| Progress::for_ctx(&t.ctx, false).color;
        assert!(!colour(&t));
        t.ctx.stdout_tty = true;
        assert!(colour(&t));
        t.ctx.env.insert("NO_COLOR".into(), "1".into());
        assert!(!colour(&t));
        t.ctx.env.insert("NO_COLOR".into(), String::new());
        assert!(colour(&t));
    }
}
