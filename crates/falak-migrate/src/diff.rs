//! Schema diffing between intermediate representations (IR).

use falak_contracts::ir::{Ir, IrEntity, IrField};

/// Change between two schema definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaDiff {
    CreateTable(IrEntity),
    DropTable(String),
    AlterTable {
        table: String,
        add_fields: Vec<IrField>,
        drop_fields: Vec<String>,
        add_indexes: Vec<String>,
        drop_indexes: Vec<String>,
    },
}

/// Compute the schema differences from an old IR to a new target IR.
pub fn diff_ir(from: Option<&Ir>, to: &Ir) -> Vec<SchemaDiff> {
    let mut diffs = Vec::new();

    let empty_entities = Vec::new();
    let old_entities = from.map(|ir| &ir.entities).unwrap_or(&empty_entities);

    // 1. Detect new entities and altered entities
    for target_entity in &to.entities {
        match old_entities.iter().find(|e| e.name == target_entity.name) {
            None => {
                diffs.push(SchemaDiff::CreateTable(target_entity.clone()));
            }
            Some(old_entity) => {
                let mut add_fields = Vec::new();
                let mut drop_fields = Vec::new();
                let mut add_indexes = Vec::new();
                let mut drop_indexes = Vec::new();

                for f in &target_entity.fields {
                    if !old_entity.fields.iter().any(|of| of.name == f.name) {
                        add_fields.push(f.clone());
                    }
                }

                for of in &old_entity.fields {
                    if !target_entity.fields.iter().any(|f| f.name == of.name) {
                        drop_fields.push(of.name.clone());
                    }
                }

                // Check index changes
                for f in &target_entity.fields {
                    if (f.indexed || f.unique)
                        && !old_entity
                            .fields
                            .iter()
                            .any(|of| of.name == f.name && (of.indexed || of.unique))
                    {
                        add_indexes.push(format!("idx_{}_{}", target_entity.table, f.name));
                    }
                }

                for of in &old_entity.fields {
                    if (of.indexed || of.unique)
                        && !target_entity
                            .fields
                            .iter()
                            .any(|f| f.name == of.name && (f.indexed || f.unique))
                    {
                        drop_indexes.push(format!("idx_{}_{}", old_entity.table, of.name));
                    }
                }

                if !add_fields.is_empty()
                    || !drop_fields.is_empty()
                    || !add_indexes.is_empty()
                    || !drop_indexes.is_empty()
                {
                    diffs.push(SchemaDiff::AlterTable {
                        table: target_entity.table.clone(),
                        add_fields,
                        drop_fields,
                        add_indexes,
                        drop_indexes,
                    });
                }
            }
        }
    }

    // 2. Detect dropped entities
    for old_entity in old_entities {
        if !to.entities.iter().any(|e| e.name == old_entity.name) {
            diffs.push(SchemaDiff::DropTable(old_entity.table.clone()));
        }
    }

    diffs
}
