//! A scripted [`Runner`] for tests: records every call and answers by argument prefix.

use std::cell::RefCell;

use anyhow::Result;

use super::{Output, Runner};

struct Reply {
    prefix: Vec<String>,
    output: Output,
    once: bool,
}

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

    pub fn interactive_exit(&self, code: i32) -> &Self {
        *self.interactive_code.borrow_mut() = code;
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

    fn interactive(&self, args: &[String]) -> Result<i32> {
        self.interactive_calls.borrow_mut().push(args.to_vec());
        if let Some(message) = self.interactive_error.borrow().as_ref() {
            anyhow::bail!("{message}");
        }
        Ok(*self.interactive_code.borrow())
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
