from fastapi import FastAPI
from PlatformIoT.routers import oauth_routes

app = FastAPI()

app.include_router(oauth_routes.router, prefix="/v1", tags=["Oauth"])
