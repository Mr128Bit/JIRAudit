# JIRAudit :mag_right:

<p align="center">
  <a href="https://github.com/Mr128Bit/JIRAudit/blob/devel/LICENSE.md"><img src="https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg"></a>
</p>
<p align="center">

  <img src="logo.png">
</p>

JIRAudit is a powerful and sophisticated security audit tool designed for Jira Data Center and Server environments. Written in Python, it helps in identifying security vulnerabilities, enumerates plugins and users without authentication, and assesses system configurations to ensure optimal security.

ATTENTION: This is an alpha version; Use at your own risk!

## Features

- **Security Risk Assessment:** Scan and evaluate Jira Data Center and Server instances for potential security threats.
- **Unauthenticated Plugin Enumeration:** Discover all installed plugins without requiring authentication credentials, highlighting possible hidden vulnerabilities.
- **System Configuration Review:** Perform in-depth evaluations of system settings to detect potential weaknesses.
- **Platform Support Check:** Verify support and security for utilized platforms, including databases and Java versions.
- **Personal Access Tokens Enumeration:** Detect and assess the usage of personal access tokens within the system.
- **CVE Scanning:** Automatically identify known vulnerabilities using the Common Vulnerabilities and Exposures (CVE) database.
- **Proxy Support:** You can tunnel requests through a proxy using the --proxy option.
- **Debug Mode:** Enable debug mode using the --debug option for additional troubleshooting and information.
- **Full Scans:** Perform a full scan with or without authentication using the --full option.
- **Authenticated and Unauthenticated Scans:** Perform scans with or without authentication using --full-auth and --full-unauth.
- **Plugin Enumeration:** Conduct authenticated (--plugin-enum) and unauthenticated (--unauth-plugin-enum) plugin enumerations.
- **Personal Access Token Enumeration:** Perform authenticated enumeration of personal access tokens using the --enum-pats option.
- **Issue Status Enumeration:** Perform unauthenticated issue status enumeration using the --unauth-issue-status-enum option.
- **User Enumeration:** Conduct unauthenticated user enumeration using the --unauth-user-enum option.
- **Output and Save Options:** Specify the output path for the result file using --out and save the results as a JSON file using the --save option.

## :wrench: Installation

```bash

# Clone the repository
git clone https://github.com/Mr128Bit/JIRAudit.git

# Navigate to the JIRAudit directory
cd JIRAudit

# Install required Python packages
pip install -r requirements.txt
```

## :rocket: Usage Examples

Command Overview
```
JIRAudit - Jira auditing tool

usage: JIRAudit - Jira auditing tool [-h] [-p PROXY] [-u USERNAME] [-pw PASSWORD] [-f] [-fua] [-fa] [-d] [-pe] [-vc] [-epat] [-cs] [-upe] [-uise] [-uue <USERLIST>] [-ce] [-s] [-o OUT] [-sm] host

Scan your jira instance and get feedback on your configuration

positional arguments:
  host                  Hostname of your jira instance

options:
  -h, --help            show this help message and exit
  -p PROXY, --proxy PROXY
                        Tunnel requests through a proxy
  -u USERNAME, --username USERNAME
                        Your username for websudo authentication
  -pw PASSWORD, --password PASSWORD
                        Your password for websudo auth
  -f, --full            Start a full scan (authenticated)
  -fua, --full-unauth   Start a full scan without authentication (only uses unauth-modules)
  -fa, --full-auth      Start a full scan with authentication (only uses auth-modules)
  -d, --debug           Enable debug mode
  -pe, --plugin-enum    Start a plugin enumeration (authenticated)
  -vc, --version-check  Check plugin versions on enumeration (use this in combination with -pe)
  -epat, --enum-pats    Enumerate personal access tokens (authenticated)
  -cs, --check-supported-platforms
                        Check support of required platforms (authenticated)
  -upe, --unauth-plugin-enum
                        Start a plugin enumeration (unauthenticated)
  -uise, --unauth-issue-status-enum
                        Start a issue status enumeration (unauthenticated)
  -uue <USERLIST>, --unauth-user-enum <USERLIST>
                        Start an unauthenticated user enumeration
  -ce, --check-exposed-endpoints
                        Check several endpoints for exposed sensitive data and enumerate if possible
  -s, --save            Save the results as a json file
  -o OUT, --out OUT     Output path for result file
  -sm, --silent-mode    If run in silent mode, only the execution ID and error logs will be printed

```

Here are some basic usage examples for using JIRAudit

```bash
# start unauthenticated plugin enumeration
python JIRAudit.py -upe https://jira.example.com
# start unauthenticated user enumeration
python JIRAudit.py -uue user_list.txt https://jira.example.com
# start unauthenticated issue statuses enumeration 
python JIRAudit.py -uise https://jira.example.com

# start full audit (requires authentication)
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -f https://jira.example.com
# start unauthenticatd full audit 
python JIRAudit.py -fua https://jira.example.com

# start personal access token enumeration (requires authentication)
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -epat https://jira.example.com
# start a pugin enumeration without version check (requires authentication)
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -pe https://jira.example.com
# start a pugin enumeration with version check (requires authentication)
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -pe -vc https://jira.example.com


# save execution result as json
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -s -f https://jira.example.com
# save execution result in a custom path
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -s -o /path/to/save -f https://jira.example.com

# start in silent mode; this only prints logs and the execution ID
# The parameter -sm is only useful if used in combination with -s
# if -s isn't set, the -sm parameter has no effect
python3 JIRAudit.py -u adminacc -pw suPeRSeCuR3 -s -sm -f https://jira.example.com

# execute script with proxy
python JIRAudit.py -u adminacc -pw suPeRSeCuR3 -p http://proxy.example.com:3333 -f https://jira.example.com
```

Explore additional commands and options with:

```bash
python jiraudit.py --help
```

## :gear: Configuration / Templates

To create a template for a host in your tool, follow these steps:

- **Copy the Configuration File**: The example configuration file **general.py** contains general settings that apply to all hosts. Copy this file and adjust it as needed.

- **Customize the HOSTS Variable**: The HOSTS variable can be populated with any number of hosts. If a host is explicitly listed in a configuration file, that configuration will be used when the host is checked.

- **Configure Authentication Options**: You can configure various authentication options in your template, such as JIRA_USER and JIRA_PASSWORD. Uncomment and modify these as needed.

- **Adjust Scoring Configuration**: Modify the scoring parameters for personal access tokens (PATs) with or without an expiration date (PAT_SCORE_EXPIRE and PAT_SCORE_NO_EXPIRE). This influences the scoring of your audit.

- **Set Up Plugin Scoring**: Define the scoring rules for plugin versions using PLUGIN_VERSION_SCORE. Customize the score for different versions of plugins.

- **Specify Supported Platforms**: Adjust the scores for supported (PLATFORM_SUPPORTED), deprecated (PLATFORM_DEPRECATED), and unsupported (PLATFORM_UNSUPPORTED) platforms.

- **Define Vulnerability Scores**: Customize the scoring for different levels of vulnerabilities found (LOW, MEDIUM, HIGH, CRITICAL) in the VULNERABILITIES_FOUND dictionary.

- **Configure Component Exposures**: Define the score for exposed sensitive data using EXPOSED_SENSITIVE_DATA.

By following these steps and customizing the configuration options, you can create tailored templates for different hosts within your tool. Make sure to adapt the settings to your specific needs and requirements.

## Plugin Enumeration

JIRAudit can currently enumerate 596 out of the 919 Marketplace plugins without authentication. This number is expected to increase in the future as new plugins are added.

It is important to keep all plugins up to date as plugin enumeration cannot currently be prevented. Keeping plugins updated helps improve the security of your system and protects against vulnerabilities.

For a comprehensive review of all installed plugins and their versions, it is recommended to perform an authenticated plugin enumeration. This provides more detailed information about the installed plugins and their compatibility.

## User Enumeration

User enumeration in JIRAudit works by checking against a list of users. This process helps identify potential users within your system.

Currently, the user enumeration query is executed through the '**/secure/QueryComponent!Default.jspa**' endpoint in Jira. You can prevent this by securing the endpoint. For more details, refer to our Best Practices page (work in progress) at this link.

In the future, additional methods will be incorporated into the tool to enable user enumeration through other means. This will enhance the tool's capabilities and provide more ways to enumerate users.

## :warning: Security Disclaimer

JIRAudit is a research tool intended for security auditing purposes. The creators are not responsible for misuse or malicious use of this tool. Users should ensure they have proper authorization before scanning any systems.

## :balance_scale: License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## :question: Support

For questions or issues, please open an issue on the [GitHub Issue Tracker](https://github.com/Mr128Bit/JIRAudit/issues) or contact us directly.

## :busts_in_silhouette: Authors

- **Robin Dost** - *Initial work* - [Mr128Bit](https://github.com/Mr128Bit)

## :star2: Acknowledgments

Special thanks to my coffe machine for the emotional support while creating this tool.

## :bookmark_tabs: FAQ

Frequently asked questions can be found in the [FAQs](FAQ.md).
```

