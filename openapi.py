import os
from loguru import logger
from fastapi.openapi.utils import get_openapi

ROOT_URL = os.environ.get('ROOT_URL')

def initialise_openapi(app):
    openapi_schema = get_openapi(
        title="Todo API",
        version=os.environ.get('RELEASE_VERSION', '1.0.0'),
        description=f"A Todo APP manager",
        routes=app.routes,
    )

    app.openapi_schema = openapi_schema