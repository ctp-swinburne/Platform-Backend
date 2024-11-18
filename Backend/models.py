from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid

from .database import Base  


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    username = Column(String, nullable=False, unique=True, index=True)  
    email = Column(String, nullable=False, unique=True, index=True)  
    password = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())  
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())  

    tokens = relationship("OAuthToken", back_populates="user", cascade="all, delete-orphan")
    authorizations = relationship("OAuthAuthorization", back_populates="user", cascade="all, delete-orphan")


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    client_id = Column(String, nullable=False, unique=True, index=True)
    client_secret = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)
    grant_type = Column(String, nullable=False)

    
    tokens = relationship("OAuthToken", back_populates="client", cascade="all, delete-orphan")
    authorizations = relationship("OAuthAuthorization", back_populates="client", cascade="all, delete-orphan")


class OAuthToken(Base):
    __tablename__ = "oauth_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(UUID(as_uuid=True), ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False)
    access_token = Column(String, nullable=False, unique=True)
    refresh_token = Column(String, nullable=False, unique=True)
    expires_in = Column(DateTime, nullable=False)
    scope = Column(String, nullable=True)

    # Relationships
    user = relationship("User", back_populates="tokens")
    client = relationship("OAuthClient", back_populates="tokens")


class OAuthAuthorization(Base):
    __tablename__ = "oauth_authorizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    client_id = Column(UUID(as_uuid=True), ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    authorization_code = Column(String, nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)

    # Relationships
    client = relationship("OAuthClient", back_populates="authorizations")
    user = relationship("User", back_populates="authorizations")
