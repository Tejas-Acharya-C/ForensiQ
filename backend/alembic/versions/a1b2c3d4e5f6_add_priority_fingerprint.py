"""Add priority_fingerprint with unique index to priority_results table.

Revision ID: a1b2c3d4e5f6
Revises: 9f0a1b2c3d4e
Create Date: 2026-08-20 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '9f0a1b2c3d4e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('priority_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('priority_fingerprint', sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f('ix_priority_results_priority_fingerprint'), ['priority_fingerprint'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('priority_results', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_priority_results_priority_fingerprint'))
        batch_op.drop_column('priority_fingerprint')
