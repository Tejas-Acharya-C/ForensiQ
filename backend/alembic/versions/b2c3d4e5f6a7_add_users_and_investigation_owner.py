"""Add users table and owner_user_id to investigations.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-08-20 16:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='INVESTIGATOR'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('ADMIN', 'INVESTIGATOR', 'VIEWER')", name='chk_user_role'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)

    # 2. Add owner_user_id to investigations
    with op.batch_alter_table('investigations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('owner_user_id', sa.Uuid(), nullable=True))
        batch_op.create_index(batch_op.f('ix_investigations_owner_user_id'), ['owner_user_id'], unique=False)
        batch_op.create_foreign_key(
            'fk_investigations_owner_user_id_users',
            'users',
            ['owner_user_id'],
            ['id'],
            ondelete='SET NULL',
        )


def downgrade() -> None:
    # 1. Drop owner_user_id from investigations
    with op.batch_alter_table('investigations', schema=None) as batch_op:
        batch_op.drop_constraint('fk_investigations_owner_user_id_users', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_investigations_owner_user_id'))
        batch_op.drop_column('owner_user_id')

    # 2. Drop users table
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_email'))
    op.drop_table('users')
