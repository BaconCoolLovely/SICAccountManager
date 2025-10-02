from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from .user import Base

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    public_key = Column(String, nullable=True)
    authorized = Column(Boolean, default=False)
