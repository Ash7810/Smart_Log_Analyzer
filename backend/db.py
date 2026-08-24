import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./smart_logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    raw_id = Column(Integer, nullable=True)  # original row id if present
    timestamp = Column(DateTime, nullable=True, index=True)
    raw_timestamp = Column(String, nullable=True)
    source = Column(String, nullable=True, index=True)
    event_type = Column(String, nullable=True, index=True)
    severity = Column(String, nullable=True, index=True)
    status = Column(Integer, nullable=True)
    raw_message = Column(Text, nullable=True)
    is_valid = Column(Boolean, default=True)
    validation_error = Column(String, nullable=True)

    # Relationships
    flagged_entry = relationship("FlaggedEntry", back_populates="log_entry", uselist=False, cascade="all, delete-orphan")


class FlaggedEntry(Base):
    __tablename__ = "flagged_entries"

    id = Column(Integer, primary_key=True, index=True)
    log_entry_id = Column(Integer, ForeignKey("log_entries.id", ondelete="CASCADE"), nullable=False, unique=True)
    score = Column(String, nullable=True)  # score or severity weight
    reason = Column(Text, nullable=False)
    detector_rule = Column(String, nullable=False, index=True)
    ai_explanation = Column(Text, nullable=True)
    ai_root_cause = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    # Relationships
    log_entry = relationship("LogEntry", back_populates="flagged_entry")


class IngestionSummary(Base):
    __tablename__ = "ingestion_summaries"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, default="logs.csv")
    total_rows = Column(Integer, default=0)
    valid_rows = Column(Integer, default=0)
    rejected_rows = Column(Integer, default=0)
    flagged_rows = Column(Integer, default=0)
    rejection_details = Column(Text, nullable=True)  # JSON or newline-separated
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))


def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
