"""Alembic script template."""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eeb0e242923f'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop reports table and its index
    with op.batch_alter_table('reports', schema=None) as batch_op:
        batch_op.drop_index('ix_reports_investigation_id')
    op.drop_table('reports')


def downgrade() -> None:
    op.create_table(
        'reports',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('report_format', sa.String(length=16), nullable=False),
        sa.Column('content', sa.JSON(), nullable=False),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("report_format IN ('JSON', 'MARKDOWN')", name='chk_report_format'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('reports', schema=None) as batch_op:
        batch_op.create_index('ix_reports_investigation_id', ['investigation_id'], unique=False)
