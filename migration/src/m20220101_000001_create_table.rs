use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create table for users.
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).uuid().primary_key())
                    .col(
                        ColumnDef::new(Users::Username)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Users::PasswordSaltedHashed)
                            .string()
                            .not_null(),
                    )
                    .take(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Things::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Things::UuidVerHash)
                            .binary_len(256 / 8)
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Things::Uuid).uuid().not_null())
                    .col(ColumnDef::new(Things::Version).big_unsigned().not_null())
                    .col(ColumnDef::new(Things::Data).blob(BlobSize::Long).not_null())
                    .take(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Users::Table).take())
            .await?;

        manager
            .drop_table(Table::drop().table(Things::Table).take())
            .await?;

        Ok(())
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum Users {
    Table,

    Id,
    Username,
    PasswordSaltedHashed,
}

#[derive(Iden)]
enum Things {
    /// The table identifier.
    Table,

    /// Primary key of the entity. Formed from concatenation of UUID and version.
    UuidVerHash,
    /// Identifer of the entity.
    Uuid,
    /// Version of the entity. Unsigned 64-bit integer.
    Version,
    /// Data associated with the entity. Raw bytes at the moment.
    Data,
}
