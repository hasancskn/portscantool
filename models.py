from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from config import Config
from flask_login import UserMixin

Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default='monitor')  # 'admin', 'operation', 'monitor'
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=True)  # Hangi admin oluşturdu

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_host = Column(String(255), nullable=False)
    start_port = Column(Integer, nullable=False)
    end_port = Column(Integer, nullable=False)
    scan_type = Column(String(50), nullable=False)  # 'manual', 'scheduled'
    status = Column(String(50), nullable=False)  # 'running', 'completed', 'failed'
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    total_ports = Column(Integer, default=0)
    open_ports_count = Column(Integer, default=0)
    scan_duration = Column(Float, default=0.0)
    nmap_output = Column(Text)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="scan")
    audit_logs = relationship("AuditLog", back_populates="scan")

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    port = Column(Integer, nullable=False)
    service = Column(String(100))
    version = Column(String(255))
    state = Column(String(50), nullable=False)  # 'open', 'closed', 'filtered'
    protocol = Column(String(10), default='tcp')
    banner = Column(Text)
    
    # Relationships
    scan = relationship("Scan", back_populates="scan_results")

class HostInfo(Base):
    __tablename__ = 'host_info'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255))
    os_family = Column(String(100))
    os_version = Column(String(100))
    os_accuracy = Column(Integer)
    mac_address = Column(String(17))
    vendor = Column(String(255))
    last_seen = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    alert_type = Column(String(50), nullable=False)  # 'new_port', 'closed_port', 'service_change'
    severity = Column(String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    message = Column(Text, nullable=False)
    details = Column(Text)
    is_sent = Column(Boolean, default=False)
    sent_time = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class ScheduledScan(Base):
    __tablename__ = 'scheduled_scans'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)  # 'port' veya 'network'
    target_hosts = Column(Text, nullable=True)  # JSON array of hosts (port tarama için)
    port_range = Column(String(50))  # e.g., "1-1024" (port tarama için)
    network_range = Column(String(50))  # Ağ tarama için
    schedule_interval = Column(Integer, nullable=False)  # seconds
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class NetworkScan(Base):
    __tablename__ = 'network_scans'
    id = Column(Integer, primary_key=True)
    network_range = Column(String(50), nullable=False)
    active_ip_count = Column(Integer, default=0)
    scan_type = Column(String(50), nullable=False)  # 'manual' veya 'scheduled'
    created_at = Column(DateTime, default=datetime.utcnow)

class NetworkScanResult(Base):
    __tablename__ = 'network_scan_results'
    id = Column(Integer, primary_key=True)
    network_scan_id = Column(Integer, ForeignKey('network_scans.id'), nullable=False)
    ip = Column(String(45), nullable=False)
    hostname = Column(String(255))
    status = Column(String(50))
    response_time = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

class AlertRule(Base):
    __tablename__ = 'alert_rules'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    rule_type = Column(String(50), nullable=False)  # 'port', 'network', 'anomaly', etc.
    condition = Column(Text, nullable=False) # JSON string: {"field": ..., "operator": ..., "value": ...}
    severity = Column(String(20), default='medium') # 'low', 'medium', 'high'
    action = Column(String(50), default='email') # 'email', 'webhook', 'dashboard', etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    def get_condition_dict(self):
        import json
        try:
            return json.loads(self.condition)
        except Exception:
            return {}

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    action = Column(String(100), nullable=False)
    user = Column(String(100))
    details = Column(Text)
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="audit_logs")

# Database setup
engine = create_engine(Config.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 