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

    pub fn interactive_exit(&self, code: i32) -> &Self {
        *self.interactive_code.borrow_mut() = code;
        self
    }

    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }

    /// Calls as space-joined strings, for compact assertions.
    pub fn call_lines(&self) -> Vec<String> {
        self.calls().iter().map(|c| c.join(" ")).collect()
    }

    pub fn interactive_calls(&self) -> Vec<Vec<String>> {
        self.interactive_calls.borrow().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, args: &[String]) -> Result<Output> {
        self.calls.borrow_mut().push(args.to_vec());
        let mut replies = self.replies.borrow_mut();
        let Some(index) = replies.iter().rposition(|r| args.starts_with(&r.prefix)) else {
            return Ok(Output::default());
        };
        if replies[index].once {
            return Ok(replies.remove(index).output);
        }
        Ok(replies[index].output.clone())
    }

    fn interactive(&self, args: &[String]) -> Result<i32> {
        self.interactive_calls.borrow_mut().push(args.to_vec());
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
