from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from .database import get_db, async_engine
from .models import Base, User, OAuthClient, OAuthAuthorization, OAuthToken
from .schemas import UserModel, ClientRegister, TokenRequest
from .auth import hash_password, verify_password, create_access_token
from datetime import datetime, timedelta
from uuid import uuid4

app = FastAPI()

# create metadata
@app.on_event("startup")
async def startup():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.post("/register-user")
async def create_user(user: UserModel, db: AsyncSession = Depends(get_db)):
    query = select(User).where(User.email == user.email)
    result = await db.execute(query)
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)
    db_user = User(username=user.username, email=user.email, password=hashed_password)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return {
        "user_id": str(db_user.id),
        "username": db_user.username,
        "email": db_user.email,
        "create_at": db_user.created_at,
        "update_at": db_user.updated_at
    }

@app.post("/register-client")
async def create_client(client: ClientRegister, db: AsyncSession = Depends(get_db)):
    db_client = OAuthClient(
        client_id=client.client_id,
        client_secret=client.client_secret,
        redirect_uri=client.redirect_uri,
        grant_type=client.grant_type
    )
    db.add(db_client)
    await db.commit()
    await db.refresh(db_client)
    return {"client_id": db_client.client_id}

@app.post("/authorize")
async def create_authorization_code(username: str, client_id: str, db: AsyncSession = Depends(get_db)):
    user_query = select(User).where(User.username == username)
    user_result = await db.execute(user_query)
    db_user = user_result.scalars().first()

    client_query = select(OAuthClient).where(OAuthClient.client_id == client_id)
    client_result = await db.execute(client_query)
    db_client = client_result.scalars().first()

    if not db_user or not db_client:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user or client")

    authorization_code = str(uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    db_authorization = OAuthAuthorization(
        client_id=db_client.id,
        user_id=db_user.id,
        authorization_code=authorization_code,
        expires_at=expires_at
    )
    db.add(db_authorization)
    await db.commit()
    await db.refresh(db_authorization)

    return {"authorization_code": authorization_code, "expires_at": expires_at.isoformat()}

@app.post("/token")
async def generate_token(client: TokenRequest, db: AsyncSession = Depends(get_db)):
    auth_query = select(OAuthAuthorization).where(OAuthAuthorization.authorization_code == client.authorization_code)
    auth_result = await db.execute(auth_query)
    db_authorization = auth_result.scalars().first()

    user_query = select(User).where(User.username == client.username)
    user_result = await db.execute(user_query)
    db_user = user_result.scalars().first()

    if not db_user or not verify_password(client.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    if not db_authorization or db_authorization.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired authorization code"
        )

    client_query = select(OAuthClient).where(
        OAuthClient.id == db_authorization.client_id,
        OAuthClient.client_secret == client.client_secret
    )
    client_result = await db.execute(client_query)
    db_client = client_result.scalars().first()

    if not db_client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid client credentials"
        )

    access_token = create_access_token(data={"sub": db_user.username})
    refresh_token = str(uuid4())
    expires_in = datetime.utcnow() + timedelta(minutes=30)

    db_token = OAuthToken(
        user_id=db_authorization.user_id,
        client_id=db_client.id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scope="read write"
    )
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)

    await db.delete(db_authorization)
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in.isoformat(),
        "token_type": "bearer"
    }
