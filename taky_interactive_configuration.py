import os
import pwd
import netifaces
import socket
import requests
import re
import logging
import getpass

"""
User-friendly questionnaire should result in taky.conf compliant file.
"""


def section_prompt(prompt_text):
    print("\n[+] " + prompt_text)


def get_response(prompt_text, default_value=""):
    # what about blanks as an intentially acceptable response?
    # maybe we need an optional validation regex, too.
    appendix = ""
    if default_value:
        appendix = " ("+default_value+")"
    raw = ""
    halfcooked = ""
    while not halfcooked:
        raw = input(prompt_text + " > " + appendix)
        halfcooked = raw.strip().lower()
        if (not halfcooked) and default_value:
            halfcooked = default_value
        else:
            "invalid response, please try again."
        if prompt_text.strip().lower().endswith("y/n)"):
            normalized_default_value = default_value.strip().lower()
            if normalized_default_value == "enabled" or normalized_default_value == "disabled":
                if halfcooked == "y":
                    halfcooked = "enabled"
                elif halfcooked =="n":
                    halfcooked = "disabled"
    # Debugging only #print("    '" + halfcooked+"'")
    return halfcooked


logger = logging.getLogger(__name__)
logging.basicConfig(filename='taky_interactive_setup.log', level=logging.INFO)
logger.info('Beginning taky interactive setup.')

print("Welcome to the interactive taky setup.")

# Hostname
hostname = socket.gethostname()
section_prompt("Detected hostname \"{}\"".format(hostname))
hostname = get_response("Use this hostname? (Y/n)", hostname)
if hostname == "n":
    hostname = get_response("  Input preferred hostname")
logger.info("Hostname selection:"+hostname)

# Public/externalish IP Address
section_prompt("Here are the host IP addresses which seem to be candidates for service,\nplus autodiscovery options:")
candidate_ifaces = []
for net_if in netifaces.interfaces():
    if net_if.startswith("br-"):
        logger.debug(" .. ignoring bridge interface.")
    elif net_if.startswith("veth") or net_if.startswith("docker"):
        logger.debug(" .. ignoring virtual interface.")
    elif net_if.startswith("lo"):
        logger.debug(" .. ignoring loopback interface.")
    else:
        logger.debug(" .. considering interface: " + net_if)
        candidate_ifaces.append(net_if)

inet_def_gw_ip_addr, inet_def_gw_device = netifaces.gateways()['default'][netifaces.AF_INET]
ip_address = inet_def_gw_ip_addr  # default
i = 0
for net_if in candidate_ifaces:
    logger.debug("Processing net if " + net_if)
    ipaddr = netifaces.ifaddresses(net_if)[netifaces.AF_INET][0]
    appendix = ""
    if net_if == inet_def_gw_device:
        appendix = "  (default gateway interface)"
    print(" {}. {} - {} {}".format(i+1, net_if, ipaddr['addr'], appendix))
    i += 1

print(" " + str(i+1) + ". 0.0.0.0 (all interfaces, all addresses)")
print(" " + str(i+2) + ". Detect public IP if ifconfig.co ...")
print(" " + str(i+3) + ". Detect public IP if ipecho.net  ...")
source_select = ""
# magic "3" in validation is for the two public reflection options.
while not re.search("^[1-"+str(i+3)+"]", source_select.strip()):
    source_select = get_response("Which would you like to use?")
if int(source_select) == i + 1:
    print(" [*] Default binding to all reachable IP addresses on all active interfaces...")
    ip_address = "0.0.0.0"
elif int(source_select) == i + 2:
    print(" [*] Checking with ifconfig.co...")
    http_req_headers = {'Accept': 'text/plain'}
    htresponse = requests.get('https://ifconfig.co/', headers=http_req_headers)
    print(" [*] Public IP detected: " + htresponse.text)
    ip_address = htresponse.text.strip()
    #TODO: catch non-200 http responses
    #      AND scan htresponse.txt for rate limit or other non-useful answers
    #      note that apparently 429 is rate limiting, so we could just sleep for 60 seconds in that case.
elif int(source_select) == i + 3:
    print(" [*] Checking with ipecho.net...")
    htresponse = requests.get('https://ipecho.net/plain')
    ip_address = htresponse.text.strip()
    print(" [*] Public IP detected: " + ip_address)
    #TODO: catch non-200 http responses
    #      AND scan htresponse.txt for rate limit or other non-useful answers
else:
    source_select_idx = int(source_select) - 1
    logger.debug("indicated net iface: "+candidate_ifaces[source_select_idx])
    ip_address = netifaces.ifaddresses(candidate_ifaces[source_select_idx])[netifaces.AF_INET][0]['addr']
logger.info("External IP Address selection:"+ip_address)
try:
    reverse_dns = socket.getnameinfo((ip_address, 0), 0)[0]
    print("     DNS reverse lookup (just for reference): " + reverse_dns)
except socket.herror:
    print("     No reverse DNS entry found, FYI.")

# Connection: SSL and ports
section_prompt("Connection protocol options:")
ssl_enabled = get_response("Do you want to use SSL? (Y/n)", "Enabled")

cot_server_port = "0"
while not (re.search("^[0-9]+$", cot_server_port.strip()) and int(cot_server_port) > 3):
    cot_server_port = get_response("Port for COT Server?", "8089")

# Data Package Service
section_prompt("Service Modules")
dp_server_enabled = get_response("Do you want to run the Data Package Server? (Y/n)", "Enabled")
if dp_server_enabled == "Enabled":
    dp_server_filepath = get_response(" '- Where do you want to store the files?", "/var/taky")
    if os.path.isdir(dp_server_filepath):
        logger.info("Confirmed that " + dp_server_filepath + " alredy exists.")
    else:
        warning_message = "Warning: that path does NOT yet exist. "
        print(" * "+warning_message)
        logger.info(warning_message)
        #TODO: or do we want to make create directory right now optional?
        try:
            os.mkdir(dp_server_filepath)
        except:
            warning_message = (
                "Warning: failed to create the dp_server_filepath for you, so that path STILL does NOT yet exist.\n"
                "            You will need to create that directory path prior to starting the service."
            )
            print(" * "+warning_message)
            logger.info(warning_message)
else:
    #just to avoid variable access errors later, and make rundown display more explicit
    dp_server_filepath = " -n/a- "

# Service Process User
# This section is not very cross-platform. Probably would just need to do some os self-reflection and have multiple sub scripts to call conditionally
section_prompt("Select TAKy server process user identity / security principal.")
default_service_user = getpass.getuser()
service_user = get_response("Which user do you want taky to run as?", default_service_user)
try:
    pwd.getpwnam(service_user)
except KeyError:
    warning_message = (
        "Warning: that username does NOT yet exist. "
        "You will need to create it prior to starting the service."
    )
    print(" * "+warning_message)
    logger.info(warning_message)
logger.info("Service user selection:"+service_user)

# Service defintion and management
section_prompt("Service registration/daemonization")
systemd_registration = get_response("Do you want to install the systemd scripts? (Y/n)", "disabled")

# Initial client connection package provisioning
#  - type in now, csv, all entries member of tak_user group in local /etc/groups, etc.
#  - could include some optional unzip|sed|rezip for nat or ddns considerations.
#  - could include a destination to scp them to.

# Summary:
# TODO: review all of these, perhaps should track closer to conf file property name strings
taky_configuration = {
        'hostname':             hostname,
        'ip_address':           ip_address,
        'ssl_enabled':          ssl_enabled,
        'cot_server_port':      cot_server_port,
        'dp_server_enabled':    dp_server_enabled,
        'dp_server_filepath':   dp_server_filepath,
        'service_user':         service_user,
        'systemd_registration': systemd_registration
}
logger.info("_Summary:_")
logger.info(taky_configuration)
print("""

Here's the configuration so far:
 - Hostname: {hostname}
 - Bind IP:  {ip_address}
 - SSL:      {ssl_enabled}
 - COT Server Port:     {cot_server_port}
 - Service User:        {service_user}
 - Data Package Server: {dp_server_enabled}
   - Storage Path:      {dp_server_filepath}
   - DPS Server Port:   8443 (Not configurable at this time)
 - Install Systemd Startup Scripts: {systemd_registration}

""".format(**taky_configuration))

# TODO: actually DO configuration (i.e., conf file, systemd config, ssl cert placement/check, create/validate dp_server_filepath).
# but first detect and backup any existing configuration
# TODO: verify ssl cert unlocking/spit out a summary anyhow

#TODO: below probably needs to be broken up a bit and sections for which DISable was specified are commented out
taky_conf = """
[taky]
# System hostname
hostname={hostname}
# The TAK Server nodeId
#node_id=TAKY
# The IP to bind to. Defaults to 0.0.0.0. To use IPv6, set to "::"
bind_ip={ip_address}
# The server's public IP address
#public_ip=

[cot_server]
# If left blank, taky will listen on 8087 without SSL, or 8089 with SSL
port={cot_server_port}
# Where to store a log of .cot messages from the client for debug purposes
#log_cot=
# The monitor IP address. Recommend 127.0.0.1
#mon_ip=127.0.0.1
# Pick any port to enable the monitor server (ssl must be enabled)
#mon_port=12345

[dp_server]
# Where user datapackage uploads are stored.
# For quick testing, set to /tmp/taky
upload_path={dp_server_filepath}

[ssl]
# SSL is disabled by default. Set enabled to "true" to enable
enabled={ssl_enabled}

# Should taky require clients to have a certificate?
#client_cert_required=false

# The server certificate or certificate+keyfile
#cert=/etc/taky/ssl/server.crt

# Specify the SSL key path
#key=/etc/taky/ssl/server.key

# Specify the SSL key password (if required)
#key_pw=

# Specify an explicit CA certificate
# If left blank, will use system CA certificates
#ca=/etc/taky/ssl/ca.crt

# If you want to use takyctl's build_client, you'll need to specify the
# following items. (`takyctl setup` will build these for you!)
#ca_key=/etc/taky/ssl/ca.key
#server_p12=/etc/taky/ssl/server.p12
#server_p12_key=atakatak
""".format(**taky_configuration)

with open("taky.conf.NEW", 'w') as new_conf_file:
    new_conf_file.write(taky_conf)

# Coda
logger.info('Ending taky interactive setup.')
section_prompt("Done!")
print("Please remember to make sure ports " + taky_configuration['cot_server_port']
      + " and 8443 are open on your system.")
