"""Add technical_attributes to value_driver

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
    op.add_column('value_driver', sa.Column('technical_attributes', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('value_driver', 'technical_attributes')
