from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import secrets


SECRET_KEY =  secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(password): 
    return pwd_context.hash(password)


def verify_password(user_password, hash_password):
    return pwd_context.verify(user_password, hash_password)

def create_access_token(data): 
    to_encode = data.copy()
    expire = datetime.utcnow()+ timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp":expire})
    return jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)