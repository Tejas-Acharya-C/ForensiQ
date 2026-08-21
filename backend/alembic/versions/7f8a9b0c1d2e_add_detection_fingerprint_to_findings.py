"""Add detection_fingerprint with unique index to findings table.

Revision ID: 7f8a9b0c1d2e
Revises: 4976fb0112ee
Create Date: 2026-08-20 14:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f8a9b0c1d2e'
down_revision: Union[str, None] = '4976fb0112ee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('detection_fingerprint', sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f('ix_findings_detection_fingerprint'), ['detection_fingerprint'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_detection_fingerprint'))
        batch_op.drop_column('detection_fingerprint')
