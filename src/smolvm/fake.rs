//! A scripted [`Runner`] for tests: records every call and answers by argument prefix.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use anyhow::Result;

use super::{Output, Proc, ProcCtl, Pty, Runner, Spawner};

struct Reply {
    prefix: Vec<String>,
    output: Output,
    once: bool,
}

/// Called with a call's args (`FakeRunner::during`).
type Hook = Box<dyn Fn(&[String])>;

#[derive(Default)]
pub struct FakeRunner {
    replies: RefCell<Vec<Reply>>,
    calls: RefCell<Vec<Vec<String>>>,
    interactive_calls: RefCell<Vec<Vec<String>>>,
    interactive_code: RefCell<i32>,
    interactive_error: RefCell<Option<String>>,
    envs: RefCell<Vec<Vec<(String, String)>>>,
    removed: RefCell<Vec<Vec<String>>>,
    spawn_errors: RefCell<Vec<(Vec<String>, String)>>,
    download: RefCell<Option<Vec<u8>>>,
    uploads: RefCell<Vec<(String, String)>>,
    progress: RefCell<Vec<(Vec<String>, Vec<String>)>>,
    during_interactive: RefCell<Option<Box<dyn Fn()>>>,
    during: RefCell<Vec<(Vec<String>, Hook)>>,
    spawner: Arc<FakeSpawner>,
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn error_output(code: &str, message: &str) -> Output {
    let stderr = serde_json::json!({ "error": { "code": code, "message": message } }).to_string();
    Output {
        code: 1,
        stdout: String::new(),
        stderr,
    }
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    fn add(&self, prefix: &[&str], output: Output, once: bool) -> &Self {
        self.replies.borrow_mut().push(Reply {
            prefix: strings(prefix),
            output,
            once,
        });
        self
    }

    /// Answer every call whose args start with `prefix`. Later registrations win.
    pub fn on(&self, prefix: &[&str], output: Output) -> &Self {
        self.add(prefix, output, false)
    }

    /// Answer only the next matching call, ahead of `on` replies registered earlier.
    pub fn once(&self, prefix: &[&str], output: Output) -> &Self {
        self.add(prefix, output, true)
    }

    pub fn ok(&self, prefix: &[&str], stdout: &str) -> &Self {
        self.on(
            prefix,
            Output {
                stdout: stdout.into(),
                ..Output::default()
            },
        )
    }

    /// `ok` that also writes `stderr`, as a successful exec whose guest command warned.
    pub fn ok_with_stderr(&self, prefix: &[&str], stdout: &str, stderr: &str) -> &Self {
        self.on(
            prefix,
            Output {
                stdout: stdout.into(),
                stderr: stderr.into(),
                ..Output::default()
            },
        )
    }

    pub fn once_ok(&self, prefix: &[&str], stdout: &str) -> &Self {
        self.once(
            prefix,
            Output {
                stdout: stdout.into(),
                ..Output::default()
            },
        )
    }

    pub fn fail(&self, prefix: &[&str], code: &str, message: &str) -> &Self {
        self.on(prefix, error_output(code, message))
    }

    pub fn once_fail(&self, prefix: &[&str], code: &str, message: &str) -> &Self {
        self.once(prefix, error_output(code, message))
    }

    /// Make calls starting with `prefix` fail to run at all, as when smolvm can't be spawned.
    pub fn spawn_fail(&self, prefix: &[&str], message: &str) -> &Self {
        self.spawn_errors
            .borrow_mut()
            .push((strings(prefix), message.into()));
        self
    }

    /// Make each `machine cp MACHINE:PATH HOST` write `bytes` to `HOST`, as a real download would.
    pub fn download(&self, bytes: &[u8]) -> &Self {
        *self.download.borrow_mut() = Some(bytes.to_vec());
        self
    }

    /// Make `run_streaming` calls starting with `prefix` emit `lines` (stderr pieces) before
    /// answering as `run` would. Later registrations win.
    pub fn progress(&self, prefix: &[&str], lines: &[&str]) -> &Self {
        self.progress
            .borrow_mut()
            .push((strings(prefix), strings(lines)));
        self
    }

    pub fn interactive_exit(&self, code: i32) -> &Self {
        *self.interactive_code.borrow_mut() = code;
        self
    }

    /// Run `f` inside each interactive call, to see what holds while the user is attached.
    pub fn during_interactive(&self, f: impl Fn() + 'static) -> &Self {
        *self.during_interactive.borrow_mut() = Some(Box::new(f));
        self
    }

    /// Call `f` with the args during each (non-interactive) call that starts with `prefix`.
    pub fn during(&self, prefix: &[&str], f: impl Fn(&[String]) + 'static) -> &Self {
        self.during
            .borrow_mut()
            .push((strings(prefix), Box::new(f)));
        self
    }

    /// Make interactive calls fail, as when smolvm can't be spawned.
    pub fn interactive_fail(&self, message: &str) -> &Self {
        *self.interactive_error.borrow_mut() = Some(message.into());
        self
    }

    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }

    /// Calls as space-joined strings, for compact assertions.
    pub fn call_lines(&self) -> Vec<String> {
        self.calls().iter().map(|c| c.join(" ")).collect()
    }

    /// The env passed to each `run_with_env` call, in order.
    pub fn envs(&self) -> Vec<Vec<(String, String)>> {
        self.envs.borrow().clone()
    }

    /// The variables removed by each `run_with_env` call, in order.
    pub fn removed(&self) -> Vec<Vec<String>> {
        self.removed.borrow().clone()
    }

    /// `(MACHINE:PATH, content)` of each `machine cp HOST MACHINE:PATH`, read when it ran.
    pub fn uploads(&self) -> Vec<(String, String)> {
        self.uploads.borrow().clone()
    }

    /// The fake process spawner (what `ssh proxy` runs sessions with).
    pub fn spawns(&self) -> &Arc<FakeSpawner> {
        &self.spawner
    }

    pub fn interactive_calls(&self) -> Vec<Vec<String>> {
        self.interactive_calls.borrow().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, args: &[String]) -> Result<Output> {
        self.calls.borrow_mut().push(args.to_vec());
        if let Some((_, message)) = self
            .spawn_errors
            .borrow()
            .iter()
            .rfind(|(p, _)| args.starts_with(p))
        {
            anyhow::bail!("{message}");
        }
        if let (Some(bytes), [m, cp, src, dst]) = (self.download.borrow().as_ref(), args)
            && m == "machine"
            && cp == "cp"
            && src.contains(':')
        {
            std::fs::write(dst, bytes)?;
        }
        if let [m, cp, src, dst] = args
            && m == "machine"
            && cp == "cp"
            && dst.contains(':')
            && let Ok(content) = std::fs::read_to_string(src)
        {
            self.uploads.borrow_mut().push((dst.clone(), content));
        }
        for (prefix, f) in self.during.borrow().iter() {
            if args.starts_with(prefix) {
                f(args);
            }
        }
        let mut replies = self.replies.borrow_mut();
        let Some(index) = replies.iter().rposition(|r| args.starts_with(&r.prefix)) else {
            return Ok(Output::default());
        };
        if replies[index].once {
            return Ok(replies.remove(index).output);
        }
        Ok(replies[index].output.clone())
    }

    fn run_with_env(
        &self,
        args: &[String],
        env: &[(String, String)],
        remove: &[String],
    ) -> Result<Output> {
        self.envs.borrow_mut().push(env.to_vec());
        self.removed.borrow_mut().push(remove.to_vec());
        self.run(args)
    }

    fn run_streaming(
        &self,
        args: &[String],
        env: &[(String, String)],
        remove: &[String],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<Output> {
        let lines = self
            .progress
            .borrow()
            .iter()
            .rfind(|(p, _)| args.starts_with(p))
            .map(|(_, lines)| lines.clone())
            .unwrap_or_default();
        for line in &lines {
            on_line(line);
        }
        self.run_with_env(args, env, remove)
    }

    fn spawner(&self) -> Option<Arc<dyn Spawner>> {
        Some(self.spawner.clone())
    }

    fn interactive(&self, args: &[String]) -> Result<i32> {
        self.interactive_calls.borrow_mut().push(args.to_vec());
        if let Some(f) = self.during_interactive.borrow().as_ref() {
            f();
        }
        if let Some(message) = self.interactive_error.borrow().as_ref() {
            anyhow::bail!("{message}");
        }
        Ok(*self.interactive_code.borrow())
    }
}

/// What a fake spawned process does.
#[derive(Clone, Default)]
pub struct Script {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: i32,
    /// Echoes its stdin to stdout and exits when stdin closes (or it is killed).
    pub echo: bool,
    /// Exits when its stdin has received these bytes.
    pub exit_on: Option<Vec<u8>>,
}

/// One process the fake spawner started, with what was done to it.
pub struct Spawned {
    pub args: Vec<String>,
    pub pty: Option<Pty>,
    pub resizes: Arc<Mutex<Vec<Pty>>>,
    pub stdin: Arc<Mutex<Vec<u8>>>,
    pub killed: Arc<AtomicBool>,
}

/// Answers spawns by a substring of the joined args (later registrations win; no match runs a
/// process that exits 0 silently).
#[derive(Default)]
pub struct FakeSpawner {
    scripts: Mutex<Vec<(String, Script)>>,
    spawned: Mutex<Vec<Arc<Spawned>>>,
}

impl FakeSpawner {
    pub fn on(&self, contains: &str, script: Script) {
        self.scripts.lock().unwrap().push((contains.into(), script));
    }

    /// The processes started so far.
    pub fn spawned(&self) -> Vec<Arc<Spawned>> {
        self.spawned.lock().unwrap().clone()
    }
}

struct Chan(Receiver<Vec<u8>>, Vec<u8>);

impl Read for Chan {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.1.is_empty() {
            match self.0.recv() {
                Ok(b) => self.1 = b,
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.1.len());
        buf[..n].copy_from_slice(&self.1[..n]);
        self.1.drain(..n);
        Ok(n)
    }
}

struct Stdin {
    seen: Arc<Mutex<Vec<u8>>>,
    echo: Option<Sender<Vec<u8>>>,
    closed: Arc<AtomicBool>,
    exit_on: Option<Vec<u8>>,
}

impl Write for Stdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut seen = self.seen.lock().unwrap();
        seen.extend_from_slice(buf);
        if let Some(m) = &self.exit_on
            && seen.windows(m.len()).any(|w| w == m.as_slice())
        {
            self.closed.store(true, Ordering::SeqCst);
        }
        let exited = self.closed.load(Ordering::SeqCst);
        drop(seen);
        if let Some(tx) = &self.echo {
            let _ = tx.send(buf.to_vec());
        }
        if exited {
            // The process is gone: its output ends.
            self.echo = None;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Stdin {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

struct Ctl(Arc<Spawned>);

impl ProcCtl for Ctl {
    fn resize(&self, size: Pty) {
        self.0.resizes.lock().unwrap().push(size);
    }

    fn kill(&self) {
        self.0.killed.store(true, Ordering::SeqCst);
    }
}

impl Spawner for FakeSpawner {
    fn spawn(&self, args: &[String], pty: Option<Pty>) -> Result<Proc> {
        let line = args.join(" ");
        let script = self
            .scripts
            .lock()
            .unwrap()
            .iter()
            .rfind(|(p, _)| line.contains(p.as_str()))
            .map(|(_, s)| s.clone())
            .unwrap_or_default();
        let rec = Arc::new(Spawned {
            args: args.to_vec(),
            pty,
            resizes: Arc::default(),
            stdin: Arc::default(),
            killed: Arc::default(),
        });
        self.spawned.lock().unwrap().push(rec.clone());
        let (out_tx, out_rx) = channel();
        let _ = out_tx.send(script.stdout.clone());
        let (err_tx, err_rx) = channel();
        let _ = err_tx.send(script.stderr.clone());
        let closed = Arc::new(AtomicBool::new(false));
        let stdin = Stdin {
            seen: rec.stdin.clone(),
            echo: script.echo.then(|| out_tx.clone()),
            closed: closed.clone(),
            exit_on: script.exit_on.clone(),
        };
        drop(out_tx);
        drop(err_tx);
        let killed = rec.killed.clone();
        let (echo, code) = (script.echo, script.code);
        Ok(Proc {
            stdin: Box::new(stdin),
            stdout: Box::new(Chan(out_rx, Vec::new())),
            stderr: pty
                .is_none()
                .then(|| Box::new(Chan(err_rx, Vec::new())) as _),
            ctl: Arc::new(Ctl(rec)),
            wait: Box::new(move || {
                while echo && !closed.load(Ordering::SeqCst) && !killed.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Ok(code)
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        strings(items)
    }

    #[test]
    fn once_replies_take_priority_then_expire() {
        let fake = FakeRunner::new();
        fake.ok(&["machine", "status"], "always")
            .once_ok(&["machine", "status"], "first");
        let call = args(&["machine", "status", "-n", "x"]);
        assert_eq!(fake.run(&call).unwrap().stdout, "first");
        assert_eq!(fake.run(&call).unwrap().stdout, "always");
        assert_eq!(
            fake.call_lines(),
            vec!["machine status -n x", "machine status -n x"]
        );
    }

    #[test]
    fn unmatched_calls_succeed_empty() {
        let fake = FakeRunner::new();
        assert_eq!(
            fake.run(&args(&["machine", "stop"])).unwrap(),
            Output::default()
        );
    }
}
