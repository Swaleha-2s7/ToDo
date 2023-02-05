import os

import aioredis
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from motor.motor_asyncio import AsyncIOMotorClient
from starlette.responses import RedirectResponse

from config import settings
from openapi import initialise_openapi
from routers import router

from fastapi import Depends, Response, status
from fastapi.security import HTTPBearer
import jwt
from configparser import ConfigParser

def set_up():
    """Sets up configuration for the app"""

    env = os.getenv("ENV", ".config")

    if env == ".config":
        config = ConfigParser()
        config.read(".config")
        config = config["AUTH0"]
    else:
        config = {
            "DOMAIN": os.getenv("DOMAIN", "your.domain.com"),
            "API_AUDIENCE": os.getenv("API_AUDIENCE", "your.audience.com"),
            "ISSUER": os.getenv("ISSUER", "https://your.domain.com/"),
            "ALGORITHMS": os.getenv("ALGORITHMS", "RS256"),
        }
    return config


class VerifyToken():
    """Does all the token verification using PyJWT"""

    def __init__(self, token, permissions=None, scopes=None):
        self.token = token
        self.permissions = permissions
        self.scopes = scopes
        self.config = set_up()

        # This gets the JWKS from a given URL and does processing so you can
        # use any of the keys available
        jwks_url = f'https://{self.config["DOMAIN"]}/.well-known/jwks.json'
        self.jwks_client = jwt.PyJWKClient(jwks_url)

    def verify(self):
        # This gets the 'kid' from the passed token
        try:
            self.signing_key = self.jwks_client.get_signing_key_from_jwt(
                self.token
            ).key
        except jwt.exceptions.PyJWKClientError as error:
            return {"status": "error", "msg": error.__str__()}
        except jwt.exceptions.DecodeError as error:
            return {"status": "error", "msg": error.__str__()}

        try: 
            payload = jwt.decode(
                self.token,
                self.signing_key,
                algorithms=self.config["ALGORITHMS"],
                audience=self.config["API_AUDIENCE"],
                issuer=self.config["ISSUER"],
            )
        except Exception as e:
            return {"status": "error", "message": str(e)}

        if self.scopes:
            result = self._check_claims(payload, 'scope', str, self.scopes.split(' '))
            if result.get("error"):
                return result

        if self.permissions:
            result = self._check_claims(payload, 'permissions', list, self.permissions)
            if result.get("error"):
                return result

        return payload

    def _check_claims(self, payload, claim_name, claim_type, expected_value):

        instance_check = isinstance(payload[claim_name], claim_type)
        result = {"status": "success", "status_code": 200}

        payload_claim = payload[claim_name]

        if claim_name not in payload or not instance_check:
            result["status"] = "error"
            result["status_code"] = 400

            result["code"] = f"missing_{claim_name}"
            result["msg"] = f"No claim '{claim_name}' found in token."
            return result

        if claim_name == 'scope':
            payload_claim = payload[claim_name].split(' ')

        for value in expected_value:
            if value not in payload_claim:
                result["status"] = "error"
                result["status_code"] = 403

                result["code"] = f"insufficient_{claim_name}"
                result["msg"] = (f"Insufficient {claim_name} ({value}). You "
                                  "don't have access to this resource")
                return result
        return result

# Scheme for the Authorization header
token_auth_scheme = HTTPBearer()

# app object
app = FastAPI()


origins = ['http://localhost:3000']

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

@app.get("/api/private")
def private(response: Response, token: str = Depends(token_auth_scheme)):
    """A valid access token is required to access this route"""

    result = VerifyToken(token.credentials).verify()

    if result.get("status"):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return result

    return result


@app.get("/api/private-scoped")
def private_scoped(response: Response, token: str = Depends(token_auth_scheme)):
    """A valid access token and an appropriate scope are required to access
    this route
    """

    result = VerifyToken(token.credentials, scopes="read:messages").verify()

    if result.get("status"):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return result

    return result

@app.on_event('startup')
async def startup_event():
    try:
        app.mongodb_client = AsyncIOMotorClient(settings.MONGODB_URL)
        app.mongodb = app.mongodb_client[settings.MONGODB_NAME]
    except Exception as e:
        logger.error(f"Failed to connect with MongoDB: {e}.")
    else:
        logger.info('Connect to MongoDB ✅')
        
    try:
        redis = await aioredis.from_url(settings.REDIS_DB)
        app.redis = redis
    except Exception as e:
        logger.error(f"Failed to connect with Redis: {e}.")
    else:
        logger.info('Connect to Redis ✅')
    
    
@app.on_event("shutdown")
async def shutdown_db_client():
  logger.info('OdeServer Shutdown 💤')

  try:
    app.mongodb_client.close()
  except Exception as e:
    logger.error(f"Failed to close connection w/ MongoDB: {e}.")
  else:
    logger.info('Close connection w/ MongoDB 💤')


@app.get('/', include_in_schema=False)
async def get_root():
  if (root_url := os.environ.get('ROOT_URL')) is None:
    return {
      'api_docs': {
        'openapi': f'{root_url}/docs',
        'redoc': f'{root_url}/redoc'
      }
    }
    
  response = RedirectResponse(url=f"{root_url}/docs")
  return response

app.include_router(router, tags=["Todo"], prefix="/api/v1/task")


initialise_openapi(app)

