# How to use SeaORM

## TLDR

- Create empty `entity` crate.
- Create migration to create tables.
- Create entity for migration?
- Migrate.

## Steps

### Entities prelude

Create entity crate and directory `entities` for entities.

```sh
cargo new --lib entity
mkdir entity/src/entities
```

Export entities in `entity/src/lib.rs`

```rust
mod entities;
pub use entities::*;
```

Add dependencies to `entity/Cargo.toml`

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
sea-orm = { version = "^0" }
```

Add `entity` to Cargo.toml.

```toml
[dependencies]
entity = { path = "entity" }
# migration = { path = "migration" } # if migration is used via binary
```

### Migration initialization

```sh
sea-orm-cli migrate init
```

Add dependencies to `migration/Cargo.toml`

> If you need some SeaORM entities when writing migrations, you can import the `entity` crate.

```toml
[dependencies]
tokio = { version = "1", features = ["full"] } # for migration main function
async-trait = "0.1.56"

sea-orm-migration = { version = "^0" }
entity = { path = "../entity" } # depends on your needs
```

Add migration that creates new table(s) to the `migration` crate.

### Example migration definition

```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Posts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Posts::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Posts::Title).string().not_null())
                    .col(ColumnDef::new(Posts::Text).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Posts::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum Posts {
    Table,
    Id,
    Title,
    Text,
}
```

Apply the migration with

```sh
sea-orm-cli migrate up
```

Create a new entity with

```sh
sea-orm-cli generate entity -o entity/src/entities
```

### Example entity definition

```rust
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "posts")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: i32,
    pub title: String,
    #[sea_orm(column_type = "Text")]
    pub text: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// ActiveModel is defined by `DeriveEntityModel` derive macro.
impl ActiveModelBehavior for ActiveModel {}
```
