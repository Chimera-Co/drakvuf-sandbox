import os

import rq_dashboard
from flask import jsonify, send_file, send_from_directory
from flask_openapi3 import Info, OpenAPI

from drakrun.lib.config import load_config
from drakrun.version import __version__

from .api import api
from .evasion_api import evasion_api
from .pipeline_api import pipeline_api

info = Info(title="CHIMERA", version=__version__)
app = OpenAPI(__name__, info=info, static_folder="frontend/dist/assets")
config = load_config()
app.config.update(
    {
        "RQ_DASHBOARD_REDIS_URL": config.redis.make_url(),
    }
)
rq_dashboard.web.setup_rq_connection(app)
app.register_blueprint(rq_dashboard.blueprint, url_prefix="/rq")
app.register_api(api)
app.register_api(evasion_api)
app.register_api(pipeline_api)


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error="Object not found"), 404


if os.environ.get("DRAKRUN_CORS_ALL"):

    @app.after_request
    def add_header(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Range"
        return response


@app.route("/")
def index():
    return send_file("frontend/dist/index.html")


@app.route("/<path:path>")
def catchall(path):
    dist = os.path.join(app.root_path, "frontend", "dist")
    if (
        path not in (".", "..")
        and "/" not in path
        and "\\" not in path
        and os.path.isfile(os.path.join(dist, path))
    ):
        mimetype = "application/manifest+json" if path.endswith(".webmanifest") else None
        return send_from_directory(dist, path, mimetype=mimetype)
    return send_file("frontend/dist/index.html")
