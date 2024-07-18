# PATHS
from pathlib import Path
import os
import logging

BASE_PATH = Path(os.path.dirname(os.path.realpath(__file__)))

TEMPLATES_PATH = BASE_PATH / "templates/"

JIRA_PLUGINS_CONFIG_PATH = BASE_PATH / "configs/enum/plugins.json"

CONFLUENCE_PLUGINS_CONFIG_PATH = BASE_PATH / "configs/enum/confluence/plugins.json"

EXCLUDED_ENDPOINTS_CONFIG_PATH = BASE_PATH / "configs/enum/excluded.json"

SUPPORTED_DBS_CONFIG_PATH = BASE_PATH / "configs/supported_platforms/databases.json"

SUPPORTED_JVM_CONFIG_PATH = BASE_PATH / "configs/supported_platforms/jvm.json"

RESULTS_PATH = BASE_PATH / "results/"

# If SSL/Cert problems occur, set this option to "False"
VERIFY_SSL = False

LOG_LEVEL = logging.INFO
LOG_PATH = "jiraudit.log"
