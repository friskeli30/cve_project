from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./cve_database.db"
#Database URL specify use of SQLITE and point to the file it will create
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
#Create SQLITE Engine and connect it to the DB URL
SessionLocal = sessionmaker(bind=engine)
#Create session
Base = declarative_base()
#Defining Base model
class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String, unique=True, index=True)
    description = Column(String)
    cvss_score = Column(Float)
#Table to store CVEs
Base.metadata.create_all(engine)