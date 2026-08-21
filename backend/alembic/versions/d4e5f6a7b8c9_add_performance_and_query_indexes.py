"""Add performance and query indexes for Phase 9C.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-08-20 17:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('priority_results', schema=None) as batch_op:
        batch_op.create_index('idx_priority_inv_method', ['investigation_id', 'method_type'], unique=False)
        batch_op.create_index('idx_priority_inv_tier', ['investigation_id', 'priority_tier'], unique=False)

    with op.batch_alter_table('relationships', schema=None) as batch_op:
        batch_op.create_index('idx_relationships_inv_weight', ['investigation_id', 'weight'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('relationships', schema=None) as batch_op:
        batch_op.drop_index('idx_relationships_inv_weight')

    with op.batch_alter_table('priority_results', schema=None) as batch_op:
        batch_op.drop_index('idx_priority_inv_tier')
        batch_op.drop_index('idx_priority_inv_method')
