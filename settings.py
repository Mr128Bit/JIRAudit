# PATHS
from pathlib import Path
import os
import logging

BASE_PATH = Path(os.path.dirname(os.path.realpath(__file__)))

TEMPLATES_PATH = BASE_PATH / "templates/"

PLUGINS_CONFIG_PATH = BASE_PATH / "configs/enum/plugins.json"

SUPPORTED_DBS_CONFIG_PATH = BASE_PATH / "configs/supported_platforms/databases.json"

SUPPORTED_JVM_CONFIG_PATH = BASE_PATH / "configs/supported_platforms/jvm.json"

RESULTS_PATH = BASE_PATH / "results/"

LOG_LEVEL = logging.INFO
LOG_PATH = "jiraudit.log"
