"""Add storage_path to evidence_sources.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-08-20 17:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('evidence_sources', schema=None) as batch_op:
        batch_op.add_column(sa.Column('storage_path', sa.String(length=512), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('evidence_sources', schema=None) as batch_op:
        batch_op.drop_column('storage_path')
