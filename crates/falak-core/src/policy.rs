//! Authorisation decisions (stages 1 and 2: ownership, roles, authentication, attribute
//! conditions and field masks).
//!
//! Policies are compiled into the IR as a list of rules. At request time
//! [`authorize`] turns the rules, the action and the verified principal into an
//! [`Access`] decision that the SQL builders in [`crate::sql`] apply. Default deny:
//! no rule, no principal, or no matching rule all give [`Access::Denied`].

use falak_contracts::{
    identity::Principal,
    ir::{IrAction, IrAllow, IrCondition, IrEntity, IrField},
};

/// One satisfied rule: the rows it reaches and the fields it grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The rule's id, for `falak policy explain`.
    pub rule: String,
    /// `Some(subject)` for an `owner` rule: only rows the subject owns.
    pub owner: Option<String>,
    /// The verified subject, which `$subject` in a condition stands for.
    pub subject: String,
    /// Attribute conditions. Every one must hold.
    pub conds: Vec<IrCondition>,
    /// The declared fields the rule grants. `None` grants all of them.
    pub fields: Option<Vec<String>>,
}

impl Grant {
    /// The rule reaches every row.
    pub fn is_unconditional(&self) -> bool {
        self.owner.is_none() && self.conds.is_empty()
    }

    /// Whether the rule grants `field`. Built-in fields are always granted.
    pub fn allows_field(&self, field: &IrField) -> bool {
        field.builtin
            || self
                .fields
                .as_ref()
                .is_none_or(|list| list.contains(&field.name))
    }
}

/// What a principal may do with an entity for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Nothing. No query is run.
    Denied,
    /// Every row (within the tenant, which is always applied separately), every field.
    Unrestricted,
    /// Only rows whose owner field equals this subject, every field. On create, the
    /// owner is set to it.
    OwnedBy(String),
    /// Rows and fields as the satisfied rules say. A row is visible if any grant reaches
    /// it. A field of a visible row is returned only if a grant that reaches that row
    /// grants the field.
    Grants(Vec<Grant>),
}

impl Access {
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied)
    }

    /// Whether `field` is returned for every row the caller can see. Only such fields
    /// may be filtered or sorted on: anything else would let a caller learn values it
    /// may not read, by watching which rows come back.
    pub fn reads_everywhere(&self, field: &IrField) -> bool {
        match self {
            Self::Denied => false,
            Self::Unrestricted | Self::OwnedBy(_) => true,
            Self::Grants(grants) => grants.iter().all(|g| g.allows_field(field)),
        }
    }

    /// Whether the caller may set `field` on a write. The most restrictive satisfied
    /// rule decides, because a write can reach rows through any of them.
    pub fn writes(&self, field: &IrField) -> bool {
        self.reads_everywhere(field)
    }
}

/// Decide access. Rules add: every satisfied rule that lists `action` is a grant, and
/// a grant that needs no row condition and no mask beats the others.
pub fn authorize(entity: &IrEntity, action: IrAction, principal: Option<&Principal>) -> Access {
    let Some(principal) = principal else {
        return Access::Denied;
    };
    let mut grants: Vec<Grant> = Vec::new();
    for rule in entity
        .policy
        .rules
        .iter()
        .filter(|r| r.actions.contains(&action))
    {
        let owner = match &rule.allow {
            IrAllow::Authenticated => None,
            IrAllow::Role(role) if principal.roles.iter().any(|r| r == role) => None,
            IrAllow::Role(_) => continue,
            // An owner rule on an entity with no owner field cannot be satisfied. The
            // loader rejects that, but the IR may come from elsewhere, so fail closed.
            IrAllow::Owner if entity.owner.is_some() => Some(principal.subject.clone()),
            IrAllow::Owner => continue,
        };
        grants.push(Grant {
            rule: rule.id.clone(),
            owner,
            subject: principal.subject.clone(),
            conds: rule.when.clone(),
            fields: rule.fields.clone(),
        });
    }
    if grants.is_empty() {
        return Access::Denied;
    }
    // Stage 1 shapes keep their simple form.
    if grants
        .iter()
        .all(|g| g.conds.is_empty() && g.fields.is_none())
    {
        return match grants.iter().find(|g| g.owner.is_none()) {
            Some(_) => Access::Unrestricted,
            None => Access::OwnedBy(principal.subject.clone()),
        };
    }
    Access::Grants(grants)
}

#[cfg(test)]
mod tests {
    use super::*;
    use falak_contracts::ir::{
        FieldType, IrAdmin, IrCmp, IrCondValue, IrPolicy, IrRelation, IrRule,
    };

    fn field(name: &str, builtin: bool) -> IrField {
        IrField {
            name: name.into(),
            ty: FieldType::Text,
            nullable: false,
            default: None,
            unique: false,
            indexed: false,
            max_length: None,
            min: None,
            max: None,
            pii: false,
            encrypted: false,
            references: None,
            builtin,
        }
    }

    fn entity(rules: Vec<IrRule>) -> IrEntity {
        IrEntity {
            name: "doc".into(),
            table: "docs".into(),
            owner: Some("owner_id".into()),
            fields: vec![
                field("id", true),
                field("title", false),
                field("body", false),
                field("owner_id", false),
            ],
            relations: Vec::<IrRelation>::new(),
            policy: IrPolicy { rules },
            admin: IrAdmin::default(),
            soft_delete: false,
            retention_days: None,
            erasable: false,
        }
    }

    fn rule(id: &str, allow: IrAllow) -> IrRule {
        IrRule {
            id: id.into(),
            actions: vec![IrAction::Read],
            allow,
            when: vec![],
            fields: None,
        }
    }

    fn principal(roles: &[&str]) -> Principal {
        Principal {
            subject: "u1".into(),
            tenant: None,
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    #[test]
    fn stage_one_shapes_are_unchanged() {
        let e = entity(vec![rule("o", IrAllow::Owner)]);
        assert_eq!(
            authorize(&e, IrAction::Read, Some(&principal(&[]))),
            Access::OwnedBy("u1".into())
        );
        let e = entity(vec![
            rule("o", IrAllow::Owner),
            rule("a", IrAllow::Authenticated),
        ]);
        assert_eq!(
            authorize(&e, IrAction::Read, Some(&principal(&[]))),
            Access::Unrestricted
        );
        assert_eq!(authorize(&e, IrAction::Read, None), Access::Denied);
        assert_eq!(
            authorize(&e, IrAction::Update, Some(&principal(&[]))),
            Access::Denied
        );
    }

    #[test]
    fn a_condition_or_mask_makes_a_grant() {
        let mut r = rule("a", IrAllow::Authenticated);
        r.when = vec![IrCondition {
            field: "title".into(),
            cmp: IrCmp::Eq,
            values: vec![IrCondValue::Text("x".into())],
        }];
        let e = entity(vec![r]);
        let Access::Grants(g) = authorize(&e, IrAction::Read, Some(&principal(&[]))) else {
            panic!("expected grants");
        };
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].rule, "a");
    }

    #[test]
    fn a_role_rule_needs_the_role() {
        let mut r = rule("m", IrAllow::Role("editor".into()));
        r.fields = Some(vec!["title".into()]);
        let e = entity(vec![r]);
        assert_eq!(
            authorize(&e, IrAction::Read, Some(&principal(&[]))),
            Access::Denied
        );
        assert!(matches!(
            authorize(&e, IrAction::Read, Some(&principal(&["editor"]))),
            Access::Grants(_)
        ));
    }

    #[test]
    fn masks_decide_what_can_be_filtered_or_sorted() {
        let mut masked = rule("m", IrAllow::Authenticated);
        masked.fields = Some(vec!["title".into()]);
        let mut owner = rule("o", IrAllow::Owner);
        owner.fields = None;
        let e = entity(vec![masked, owner]);
        let access = authorize(&e, IrAction::Read, Some(&principal(&[])));
        let title = e.field("title").unwrap();
        let body = e.field("body").unwrap();
        let id = e.field("id").unwrap();
        assert!(access.reads_everywhere(title));
        assert!(!access.reads_everywhere(body));
        assert!(
            access.reads_everywhere(id),
            "built-in fields are always readable"
        );
    }
}
