"""SQLAlchemy database models."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Scan(Base):
    """Scan database model."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="running"
    )  # running, success, error, timeout
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modules: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    timeout: Mapped[int] = mapped_column(Integer, nullable=False, default=300)

    def __repr__(self) -> str:
        """String representation."""
        return f"<Scan(scan_id={self.scan_id}, target={self.target}, status={self.status})>"


class ScanResult(Base):
    """Scan result database model."""

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    module: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(20), nullable=False)  # quick, deep, security
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # success, error, timeout
    data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        """String representation."""
        return f"<ScanResult(scan_id={self.scan_id}, module={self.module}, status={self.status})>"


class Finding(Base):
    """Finding database model."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_result_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    scan_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # critical, high, medium, low, info
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    reference: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    def __repr__(self) -> str:
        """String representation."""
        return f"<Finding(severity={self.severity}, title={self.title})>"
