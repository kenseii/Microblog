"""added language to posts

Revision ID: 5d59ac89f403
Revises: caad48738749
Create Date: 2018-12-09 14:04:43.144219

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '5d59ac89f403'
down_revision = 'caad48738749'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('post', sa.Column('language', sa.String(length=5), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('post', 'language')
    # ### end Alembic commands ###
