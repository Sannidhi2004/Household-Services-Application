"""Added Flag model

Revision ID: 5c629aae903d
Revises: 67bc4977d4ec
Create Date: 2025-03-18 16:58:15.356067

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5c629aae903d'
down_revision = '67bc4977d4ec'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('flag',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('item_id', sa.Integer(), nullable=False),
    sa.Column('item_type', sa.String(length=50), nullable=False),
    sa.Column('reason', sa.String(length=255), nullable=True),
    sa.Column('flagged_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('flag')
    # ### end Alembic commands ###
