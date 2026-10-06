import logging
import os

import uvicorn

if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    host, _, port = os.environ.get("LISTEN", "0.0.0.0:9000").rpartition(":")
    uvicorn.run("aism_orchestrator.main:app", host=host or "0.0.0.0", port=int(port), log_level="warning", access_log=False)
