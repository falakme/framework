//! Schema diffing between intermediate representations (IR).

use falak_contracts::ir::{Ir, IrEntity, IrField};

/// An index to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSpec {
    pub name: String,
    pub column: String,
    pub unique: bool,
}

/// Change between two schema definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SchemaDiff {
    CreateTable(IrEntity),
    DropTable(String),
    AlterTable {
        /// The entity as it was.
        old: IrEntity,
        /// The entity as it will be.
        new: IrEntity,
        table: String,
        add_fields: Vec<IrField>,
        drop_fields: Vec<String>,
        /// `(old, new)` for a field whose type, nullability or constraints changed.
        changed_fields: Vec<(IrField, IrField)>,
        add_indexes: Vec<IndexSpec>,
        drop_indexes: Vec<String>,
    },
}

fn wants_index(f: &IrField) -> bool {
    !f.builtin && (f.indexed || f.unique) && !f.encrypted
}

/// Whether two fields of the same name differ in anything the database stores.
fn field_changed(a: &IrField, b: &IrField) -> bool {
    a.ty != b.ty
        || a.nullable != b.nullable
        || a.max_length != b.max_length
        || a.min != b.min
        || a.max != b.max
        || a.references != b.references
}

/// Compute the schema differences from an old IR to a new target IR.
pub fn diff_ir(from: Option<&Ir>, to: &Ir) -> Vec<SchemaDiff> {
    let mut diffs = Vec::new();

    let empty_entities = Vec::new();
    let old_entities = from.map(|ir| &ir.entities).unwrap_or(&empty_entities);

    for target in &to.entities {
        let Some(old) = old_entities.iter().find(|e| e.name == target.name) else {
            diffs.push(SchemaDiff::CreateTable(target.clone()));
            continue;
        };
        let add_fields: Vec<IrField> = target
            .fields
            .iter()
            .filter(|f| old.field(&f.name).is_none())
            .cloned()
            .collect();
        let drop_fields: Vec<String> = old
            .fields
            .iter()
            .filter(|f| target.field(&f.name).is_none())
            .map(|f| f.name.clone())
            .collect();
        let changed_fields: Vec<(IrField, IrField)> = target
            .fields
            .iter()
            .filter_map(|f| {
                let o = old.field(&f.name)?;
                field_changed(o, f).then(|| (o.clone(), f.clone()))
            })
            .collect();

        let mut add_indexes = Vec::new();
        let mut drop_indexes = Vec::new();
        for f in &target.fields {
            let had = old.field(&f.name).is_some_and(wants_index);
            let had_unique = old
                .field(&f.name)
                .is_some_and(|o| wants_index(o) && o.unique);
            if wants_index(f) && (!had || had_unique != f.unique) {
                add_indexes.push(IndexSpec {
                    name: format!("idx_{}_{}", target.table, f.name),
                    column: f.name.clone(),
                    unique: f.unique,
                });
                if had {
                    drop_indexes.push(format!("idx_{}_{}", old.table, f.name));
                }
            }
        }
        for of in &old.fields {
            let still = target.field(&of.name).is_some_and(wants_index);
            if wants_index(of) && !still && target.field(&of.name).is_some() {
                drop_indexes.push(format!("idx_{}_{}", old.table, of.name));
            }
        }

        if !add_fields.is_empty()
            || !drop_fields.is_empty()
            || !changed_fields.is_empty()
            || !add_indexes.is_empty()
            || !drop_indexes.is_empty()
        {
            diffs.push(SchemaDiff::AlterTable {
                old: old.clone(),
                new: target.clone(),
                table: target.table.clone(),
                add_fields,
                drop_fields,
                changed_fields,
                add_indexes,
                drop_indexes,
            });
        }
    }

    for old in old_entities {
        if !to.entities.iter().any(|e| e.name == old.name) {
            diffs.push(SchemaDiff::DropTable(old.table.clone()));
        }
    }

    diffs
}
