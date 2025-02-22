"""Increase password_hash length to 300"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '<new_revision_id>'
down_revision = '<previous_revision_id>'
branch_labels = None
depends_on = None

def upgrade():
    op.alter_column('user', 'password_hash',
               existing_type=sa.String(length=128),
               type_=sa.String(length=300),
               existing_nullable=False)

def downgrade():
    op.alter_column('user', 'password_hash',
               existing_type=sa.String(length=300),
               type_=sa.String(length=128),
               existing_nullable=False)
