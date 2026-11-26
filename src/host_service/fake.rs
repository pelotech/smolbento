use super::*;
use std::cell::RefCell;
use std::rc::Rc;

/// Records the loads and unloads; never touches a service manager.
#[derive(Clone, Default)]
pub struct FakeControl(pub Rc<RefCell<Vec<String>>>);

impl Control for FakeControl {
    fn usable(&self) -> bool {
        true
    }
    fn refresh(&self) -> Result<()> {
        self.0.borrow_mut().push("refresh".into());
        Ok(())
    }
    fn load(&self, u: &UnitPaths) -> Result<()> {
        self.0.borrow_mut().push(format!("load {}", u.id));
        Ok(())
    }
    fn loaded(&self, u: &UnitPaths) -> bool {
        let last = self
            .0
            .borrow()
            .iter()
            .rfind(|c| c.ends_with(&format!(" {}", u.id)))
            .cloned();
        last.is_some_and(|c| c.starts_with("load "))
    }
    fn unload(&self, u: &UnitPaths) {
        self.0.borrow_mut().push(format!("unload {}", u.id));
    }
    fn restart(&self, u: &UnitPaths) -> Result<()> {
        self.0.borrow_mut().push(format!("restart {}", u.id));
        Ok(())
    }
    fn settle(&self) {
        self.0.borrow_mut().push("settle".into());
    }
}

impl FakeControl {
    pub fn calls(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

/// Units under `dir`, as `flavor`, controlled by the returned fake.
pub fn services(dir: &Path, flavor: Flavor, ns: &str) -> (HostServices, FakeControl) {
    let ctl = FakeControl::default();
    let s = HostServices::new(
        flavor,
        ns.into(),
        dir.join("units"),
        dir.join("sock"),
        "/usr/local/bin/sbt".into(),
        Box::new(ctl.clone()),
    );
    (s, ctl)
}
