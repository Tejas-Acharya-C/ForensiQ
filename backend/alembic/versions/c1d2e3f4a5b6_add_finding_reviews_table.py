"""Add finding_reviews table for investigator triage workflow.

Revision ID: c1d2e3f4a5b6
Revises: b355dc794398
Create Date: 2026-11-08 19:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c1d2e3f4a5b6'
down_revision = 'b355dc794398'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'finding_reviews',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('finding_id', sa.Uuid(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='NEW'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('NEW', 'REVIEWED', 'FALSE_POSITIVE', 'ESCALATED')",
            name='chk_finding_review_status',
        ),
        sa.ForeignKeyConstraint(
            ['investigation_id'],
            ['investigations.id'],
            ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['finding_id'],
            ['findings.id'],
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id', 'finding_id', name='uq_finding_review_inv_finding'),
    )
    with op.batch_alter_table('finding_reviews', schema=None) as batch_op:
        batch_op.create_index('idx_finding_reviews_investigation', ['investigation_id'], unique=False)
        batch_op.create_index('idx_finding_reviews_status', ['investigation_id', 'status'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('finding_reviews', schema=None) as batch_op:
        batch_op.drop_index('idx_finding_reviews_status')
        batch_op.drop_index('idx_finding_reviews_investigation')
    op.drop_table('finding_reviews')

