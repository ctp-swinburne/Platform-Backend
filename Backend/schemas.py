from pydantic import BaseModel
from datetime import datetime

class UserModel(BaseModel):
    username: str
    email: str
    password: str


class ClientRegister(BaseModel):
    client_id: str
    client_secret:str
    redirect_uri:str 
    grant_type:str
    
class TokenRequest(BaseModel):
    username: str
    password: str
    authorization_code: str
    client_id: str
    client_secret: str