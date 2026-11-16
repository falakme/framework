//! Build-time compatibility check between two versions of an app's event contracts
//! (FEDERATION §13.3). A change that consumers could not read must come with a higher
//! event `version`.

use falak_contracts::ir::{Ir, IrEvent};

/// A problem with the change from `old` to `new`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breaking {
    pub event: String,
    pub message: String,
}

fn breaks(old: &IrEvent, new: &IrEvent) -> Option<String> {
    if old.entity != new.entity || old.on != new.on {
        return Some("it now fires for a different entity or change".to_owned());
    }
    for f in &old.fields {
        match new.fields.iter().find(|n| n.name == f.name) {
            None => return Some(format!("field `{}` was removed", f.name)),
            Some(n) if n.ty != f.ty => return Some(format!("field `{}` changed type", f.name)),
            Some(_) => {}
        }
    }
    None
}

/// Compare the events `new` publishes with what `old` published. Adding an event or a
/// field is compatible. Removing an event, removing or retyping a field, or changing
/// what fires it is breaking, and needs a higher `version`. Empty means compatible.
pub fn check(old: &Ir, new: &Ir) -> Vec<Breaking> {
    let mut out = Vec::new();
    for e in &old.events {
        let Some(n) = new.events.iter().find(|n| n.name == e.name) else {
            out.push(Breaking {
                event: e.name.clone(),
                message: format!(
                    "event `{}` was removed; subscribers still depend on it. Keep it until they have moved",
                    e.name
                ),
            });
            continue;
        };
        if n.version < e.version {
            out.push(Breaking {
                event: e.name.clone(),
                message: format!(
                    "event `{}` went from version {} down to {}",
                    e.name, e.version, n.version
                ),
            });
        } else if let Some(why) = breaks(e, n)
            && n.version == e.version
        {
            out.push(Breaking {
                event: e.name.clone(),
                message: format!(
                    "event `{}` changed in a way that breaks subscribers ({why}) but is still version {}. Raise `version`",
                    e.name, e.version
                ),
            });
        }
    }
    out
}
