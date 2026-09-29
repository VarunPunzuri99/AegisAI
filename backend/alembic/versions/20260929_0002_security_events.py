"""Alembic migration: security_events table for Phase 13 audit persistence.

Revision ID: 20260929_0002
Revises: 20260324_0001
Create Date: 2026-09-29

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260929_0002"
down_revision: Union[str, None] = "20260324_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("scan_id", sa.Uuid(), nullable=True),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("content_length", sa.Integer(), nullable=False),
        sa.Column("detection_label", sa.String(length=32), nullable=True),
        sa.Column(
            "attack_types",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("policy_decision", sa.String(length=32), nullable=True),
        sa.Column("policy_id", sa.String(length=128), nullable=True),
        sa.Column("policy_version", sa.String(length=32), nullable=True),
        sa.Column("conflict", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "uncertainty",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("agent_state", sa.String(length=64), nullable=True),
        sa.Column("action_id", sa.Uuid(), nullable=True),
        sa.Column("action_type", sa.String(length=64), nullable=True),
        sa.Column("tool_name", sa.String(length=128), nullable=True),
        sa.Column("tool_decision", sa.String(length=32), nullable=True),
        sa.Column("approval_state", sa.String(length=32), nullable=True),
        sa.Column("intent", sa.String(length=64), nullable=True),
        sa.Column("target", sa.String(length=64), nullable=True),
        sa.Column("impact", sa.String(length=64), nullable=True),
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "detector_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "pipeline_stages",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "risk_factors",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("note", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_events_created_at", "security_events", ["created_at"])
    op.create_index(
        "ix_security_events_policy_decision", "security_events", ["policy_decision"]
    )
    op.create_index("ix_security_events_severity", "security_events", ["severity"])
    op.create_index(
        "ix_security_events_detection_label", "security_events", ["detection_label"]
    )
    op.create_index("ix_security_events_tool_name", "security_events", ["tool_name"])
    op.create_index(
        "ix_security_events_tool_decision", "security_events", ["tool_decision"]
    )
    op.create_index("ix_security_events_scan_id", "security_events", ["scan_id"])
    op.create_index("ix_security_events_content_hash", "security_events", ["content_hash"])


def downgrade() -> None:
    op.drop_index("ix_security_events_content_hash", table_name="security_events")
    op.drop_index("ix_security_events_scan_id", table_name="security_events")
    op.drop_index("ix_security_events_tool_decision", table_name="security_events")
    op.drop_index("ix_security_events_tool_name", table_name="security_events")
    op.drop_index("ix_security_events_detection_label", table_name="security_events")
    op.drop_index("ix_security_events_severity", table_name="security_events")
    op.drop_index("ix_security_events_policy_decision", table_name="security_events")
    op.drop_index("ix_security_events_created_at", table_name="security_events")
    op.drop_table("security_events")
