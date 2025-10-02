from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    secret_key = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    birthday = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
    blocked = Column(Boolean, default=False)
    blocked_code = Column(String, nullable=True)
    permanently_banned = Column(Boolean, default=False)  # Prevents appeals

    appeals = relationship("Appeal", back_populates="user")
