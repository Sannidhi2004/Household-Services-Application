"""Added remarks and completion_status to ServiceRequest table

Revision ID: 0801d4cb0d3a
Revises: 5c629aae903d
Create Date: 2025-03-20 23:23:51.263821

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0801d4cb0d3a'
down_revision = '5c629aae903d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('service_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('remarks', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('completion_status', sa.String(length=50), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('service_requests', schema=None) as batch_op:
        batch_op.drop_column('completion_status')
        batch_op.drop_column('remarks')

    # ### end Alembic commands ###
