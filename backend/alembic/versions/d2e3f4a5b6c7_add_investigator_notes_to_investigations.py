"""Add investigator_notes to investigations table.

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-11-08 20:15:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd2e3f4a5b6c7'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('investigations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('investigator_notes', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('investigations', schema=None) as batch_op:
        batch_op.drop_column('investigator_notes')

