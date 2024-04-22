HOSTS = ["*"]

############### AUTHENTICATION ###############

#JIRA_USER = "admin"
#JIRA_PASSWORD = "password"

########### SCORING CONFIGURATION ############

## Personal Access Tokens
# score for pats that have an expiration date
PAT_SCORE_EXPIRE = 5
# score for pats without expiration date
PAT_SCORE_NO_EXPIRE = -5


################### PLUGINS ##################

PLUGIN_VERSION_SCORE = {"versions behind": {"0-3": 0, "4-9": -5, "10-": -10}}

############# SUPPORTED PLATFORMS ############

PLATFORM_SUPPORTED = 5  # should be the highest
PLATFORM_DEPRECATED = -1
PLATFORM_UNSUPPORTED = -10

############### VULNERABILITIES ##############

VULNERABILITIES_FOUND = {
    "LOW": -1,
    "MEDIUM": -5,
    "HIGH": -10,
    "CRITICAL": -15,
}  # should alwasy be <=0

################# COMPONENTS #################

EXPOSED_SENSITIVE_DATA = -10  # should be negative or 0

##############################################
