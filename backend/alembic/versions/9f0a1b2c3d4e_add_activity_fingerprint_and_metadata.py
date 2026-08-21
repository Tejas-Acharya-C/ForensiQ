"""Add description, context_attributes, and activity_fingerprint to activities table.

Revision ID: 9f0a1b2c3d4e
Revises: 8e9f0a1b2c3d
Create Date: 2026-08-20 15:47:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '9f0a1b2c3d4e'
down_revision: Union[str, None] = '8e9f0a1b2c3d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('activities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('description', sa.String(length=1024), nullable=True))
        batch_op.add_column(sa.Column('context_attributes', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False, server_default='{}'))
        batch_op.add_column(sa.Column('activity_fingerprint', sa.String(length=64), nullable=True))
        batch_op.create_index(batch_op.f('ix_activities_activity_fingerprint'), ['activity_fingerprint'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('activities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_activities_activity_fingerprint'))
        batch_op.drop_column('activity_fingerprint')
        batch_op.drop_column('context_attributes')
        batch_op.drop_column('description')
