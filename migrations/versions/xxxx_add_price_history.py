"""Add price history table

Revision ID: xxxx
Revises: previous_revision_id
Create Date: 2023-10-xx xx:xx:xx

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'xxxx'
down_revision = 'previous_revision_id'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'price_history',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('product_id', sa.Integer, sa.ForeignKey('product.id'), nullable=False),
        sa.Column('old_price', sa.Float, nullable=False),
        sa.Column('new_price', sa.Float, nullable=False),
        sa.Column('date_changed', sa.DateTime, nullable=False, default=sa.func.current_timestamp())
    )

def downgrade():
    op.drop_table('price_history')
