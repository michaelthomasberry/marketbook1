
"""Add category, target_customer, and country to project

Revision ID: xxxx
Revises: 
Create Date: 2023-10-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'xxxx'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add new columns to the project table
    op.add_column('project', sa.Column('category', sa.String(length=100), nullable=False))
    op.add_column('project', sa.Column('target_customer', sa.String(length=100), nullable=False))
    op.add_column('project', sa.Column('country', sa.String(length=100), nullable=False))

def downgrade():
    # Remove the columns if the migration is rolled back
    op.drop_column('project', 'category')
    op.drop_column('project', 'target_customer')
    op.drop_column('project', 'country')