from fastapi import FastAPI, Depends, HTTPException , status
from sqlalchemy.orm import Session

from .database import get_db, engine
from .models import Base, User , OAuthClient ,OAuthAuthorization , OAuthToken
from .schemas import  UserModel , ClientRegister , TokenRequest
from .auth import hash_password , verify_password ,create_access_token
from datetime import datetime , timedelta
from uuid import uuid4

app = FastAPI()


Base.metadata.create_all(bind=engine)

@app.post("/register-user")
async def create_user(user: UserModel, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)

    db_user = User(username=user.username, email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {
        "user_id": str(db_user.id),
        "username": db_user.username,
        "email": db_user.email,
        "create_at": db_user.created_at,
        "update_at": db_user.updated_at
    }


@app.post("/register-client")
async def create_client(client:ClientRegister,db:Session = Depends(get_db)):
    db_client = OAuthClient(
        client_id = client.client_id,
        client_secret = client.client_secret, 
        redirect_uri=client.redirect_uri,
        grant_type=client.grant_type
    )
    db.add(db_client)
    db.commit()
    db.refresh(db_client)
    return {
        "client_id": db_client.client_id
    }

@app.post("/authorize")
async def create_authorization_code(username :str , client_id :str, db:Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == username).first()
    db_client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first() 
    
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
    db.commit()
    db.refresh(db_authorization)

    return {"authorization_code": authorization_code, "expires_at": expires_at.isoformat()}


@app.post("/token")
async def gernerate_token(client: TokenRequest, db:Session = Depends(get_db)):
    db_authorization = db.query(OAuthAuthorization).filter(OAuthAuthorization.authorization_code == client.authorization_code).first() 
    db_user = db.query(User).filter(User.username == client.username).first()
    if not db_user: 
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
            )
        
    if not verify_password(client.password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
            )
    
    if not db_authorization or db_authorization.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid or expired authorization code"
        )
        
    db_client = db.query(OAuthClient).filter(
        OAuthClient.id == db_authorization.client_id,
        OAuthClient.client_secret == client.client_secret 
    ).first() 
    
    if not db_client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid client credentials"
        )
        
    access_token = create_access_token(data={"sub": db_authorization.user.username})
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
    db.commit()
    db.refresh(db_token)

    db.delete(db_authorization)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in.isoformat(),
        "token_type": "bearer"
    }