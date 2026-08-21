"""Add relationship_fingerprint with unique index to relationships table.

Revision ID: 8e9f0a1b2c3d
Revises: 7f8a9b0c1d2e
Create Date: 2026-08-20 15:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8e9f0a1b2c3d'
down_revision: Union[str, None] = '7f8a9b0c1d2e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('relationships', schema=None) as batch_op:
        batch_op.add_column(sa.Column('relationship_fingerprint', sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f('ix_relationships_relationship_fingerprint'), ['relationship_fingerprint'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('relationships', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_relationships_relationship_fingerprint'))
        batch_op.drop_column('relationship_fingerprint')
