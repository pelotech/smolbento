//! Progress lines for create/run/start, in sbx's layout, written to `ctx.out`.

use std::io::Write;

use super::{Ctx, Out};
use crate::sandbox::Event;
use crate::smolvm::Runner;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BLUE: &str = "94";
const GREY: &str = "90";
const MAGENTA: &str = "35";
const GREEN: &str = "32";
const RED: &str = "31";
/// Returns to the start of the line and clears it. Steps never move the cursor up, so text
/// written to stderr during a step (a warning) is never erased.
const CLEAR: &str = "\r\x1b[K";

/// Writes sections, fields and steps. On a terminal a step is one line redrawn in place (with no
/// newline until it ends); otherwise
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
    /// Drawn on a terminal and not yet ended.
    drawn: bool,
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
            drawn: false,
        };
        if self.drawing() {
            step.draw(None);
        } else {
            self.write(&format!("  ○ {subject} — {doing}…\n"));
        }
        step
    }

    /// `  ✓ subject — word`, for a step that had nothing to do.
    pub fn done(&self, subject: &str, word: &str) {
        self.write(&format!(
            "  {} {subject} — {word}\n",
            self.paint(GREEN, "✓")
        ));
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
    /// Redraws the step with `text` after it and the next spinner frame. Terminal only.
    pub fn detail(&mut self, text: &str) {
        if self.drawn {
            self.frame = (self.frame + 1) % SPINNER.len();
            self.draw(Some(text));
        }
    }

    /// `  ✓ subject — word`.
    pub fn done(mut self, word: &str) {
        let mark = self.p.paint(GREEN, "✓");
        self.end(&format!("  {mark} {} — {word}\n", self.subject));
    }

    /// `  ✓ line` in place of the step, e.g. `  ✓ Started NAME`.
    pub fn done_as(mut self, line: &str) {
        let mark = self.p.paint(GREEN, "✓");
        self.end(&format!("  {mark} {line}\n"));
    }

    /// `  ✗ subject — failed`; the caller then reports the error as usual.
    pub fn fail(mut self) {
        let mark = self.p.paint(RED, "✗");
        self.end(&format!("  {mark} {} — failed\n", self.subject));
    }

    /// `  ⠙ subject — doing… detail`, over the current line and without a newline.
    fn draw(&mut self, detail: Option<&str>) {
        let frame = self.p.paint(MAGENTA, SPINNER[self.frame]);
        let detail = detail.map(|d| format!(" {d}")).unwrap_or_default();
        self.p.write(&format!(
            "{CLEAR}  {frame} {} — {}…{detail}",
            self.subject, self.doing
        ));
        self.drawn = true;
    }

    fn end(&mut self, line: &str) {
        if self.drawn {
            self.p.write(&format!("{CLEAR}{line}"));
            self.drawn = false;
        } else {
            self.p.write(line);
        }
    }
}

/// A create's IMAGE and SETUP steps, from the sandbox's [`Event`]s: `image` around `machine
/// start` (with the pull percentage on a terminal), then `sandbox` around the guest setup and one
/// step per kit's part of the first start.
pub struct CreateSteps {
    p: Progress,
    /// The running step and the word that ends it.
    current: Option<(Step, &'static str)>,
}

impl CreateSteps {
    pub fn new(p: &Progress) -> Self {
        Self {
            p: p.clone(),
            current: None,
        }
    }

    pub fn on(&mut self, e: Event) {
        match e {
            Event::Boot => {
                self.p.section("IMAGE");
                self.begin("image", "pulling", "ready");
            }
            Event::Pull(pull) => {
                if let Some((step, _)) = &mut self.current {
                    step.detail(&pull.to_string());
                }
            }
            Event::Setup => {
                self.end(true);
                self.p.section("SETUP");
                self.begin("sandbox", "starting", "started");
            }
            Event::Install(kit) => {
                self.end(true);
                self.begin(kit, "installing", "installed");
            }
        }
    }

    /// Ends the running step: done when the create succeeded, else failed.
    pub fn end(&mut self, ok: bool) {
        if let Some((step, word)) = self.current.take() {
            if ok { step.done(word) } else { step.fail() }
        }
    }

    fn begin(&mut self, subject: &str, doing: &str, done: &'static str) {
        self.current = Some((self.p.step(subject, doing), done));
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
    fn create_steps_follow_the_sandbox_events() {
        use crate::smolvm::PullProgress;
        let (p, out) = reporter(false, false, false);
        let mut steps = CreateSteps::new(&p);
        for e in [
            Event::Boot,
            Event::Pull(PullProgress::Percent(42)),
            Event::Setup,
            Event::Install("docker"),
        ] {
            steps.on(e);
        }
        steps.end(true);
        assert_eq!(
            text(&out),
            "\nIMAGE\n  ○ image — pulling…\n  ✓ image — ready\n\nSETUP\n\
             \x20 ○ sandbox — starting…\n  ✓ sandbox — started\n\
             \x20 ○ docker — installing…\n  ✓ docker — installed\n"
        );
        steps.on(Event::Boot);
        steps.end(false);
        steps.end(false);
        assert_eq!(
            text(&out),
            "\nIMAGE\n  ○ image — pulling…\n  ✗ image — failed\n"
        );
    }

    #[test]
    fn a_step_can_end_as_its_own_line_or_need_no_start() {
        let (p, out) = reporter(false, false, false);
        p.step("box", "starting").done_as("Started box");
        p.done("./kit", "cached");
        assert_eq!(
            text(&out),
            "  ○ box — starting…\n  ✓ Started box\n  ✓ ./kit — cached\n"
        );
        let (p, out) = reporter(true, false, false);
        p.step("box", "starting").done_as("Started box");
        assert_eq!(
            text(&out),
            "\r\x1b[K  ⠋ box — starting…\r\x1b[K  ✓ Started box\n"
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
        assert!(s.contains("\r\x1b[K  ⠙ image — pulling… 42%"), "{s:?}");
        assert!(!s.contains("\x1b[9"), "{s:?}");
        assert!(!s.contains("\x1b[3"), "{s:?}");
        assert!(s.contains("  ✓ image — ready\n"), "{s:?}");
    }

    /// A warning written to stderr during a step must stay on screen: the terminal gets one
    /// stream, so interleave both into one buffer and check nothing moves the cursor up.
    #[test]
    fn tty_never_moves_up_over_a_warning() {
        let (p, out) = reporter(true, false, false);
        let warn = || {
            let _ = (&out).write_all(b"warning: kept stopped\n");
        };
        let mut s = p.step("image", "pulling");
        warn();
        s.detail("42%");
        warn();
        s.done("ready");
        let s = p.step("kit", "installing");
        warn();
        s.fail();
        let s = text(&out);
        assert!(!s.contains("\x1b[1A") && !s.contains("\x1b[A"), "{s:?}");
        assert_eq!(s.matches("warning: kept stopped\n").count(), 3, "{s:?}");
        assert!(
            s.ends_with("warning: kept stopped\n\r\x1b[K  ✗ kit — failed\n"),
            "{s:?}"
        );
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
