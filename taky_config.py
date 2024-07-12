import os
import pwd
import netifaces
import socket
import requests
import re
import logging
import getpass


def section_prompt(prompt_text):
    print("\n[+] " + prompt_text)

def get_response(prompt_text, default_value=""):
    #what about blanks as an intentially acceptable response?
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
            if halfcooked == 'y':
                halfcooked = default_value
    return halfcooked


logger = logging.getLogger(__name__)
logging.basicConfig(filename='taky_interactive_setup.log', level=logging.INFO)
logger.info('Beginning taky interactive setup.')

print("Welcome to the interactive taky setup.")

#Hostname
hostname = socket.gethostname()
section_prompt( "Detected hostname \"{}\"".format(hostname) )
hostname = get_response("Use this hostname? (Y/n)",hostname)
if hostname == "n":
    hostname = get_response("  Input preferred hostname")
logger.info("Hostname selection:"+hostname)

#Public/externalish IP Address
section_prompt("Here are the IP addresses seem to be candidates for service:")
candidate_ifaces = []
for net_if in netifaces.interfaces():
    if net_if.startswith("br-"):
        logger.debug(" .. ignoring bridge interface.")
    elif net_if.startswith("veth") or net_if.startswith("docker") :
        logger.debug(" .. ignoring virtual interface.")
    elif net_if.startswith("lo") :
        logger.debug(" .. ignoring loopback interface.")
    else:
        logger.debug(" .. considering interface: " + net_if)
        candidate_ifaces.append(net_if)

inet_def_gw_ip_addr,inet_def_gw_device = netifaces.gateways()['default'][netifaces.AF_INET]
ip_address = inet_def_gw_ip_addr #default
i=1
for net_if in candidate_ifaces:
    logger.debug("Processing net if "+ net_if)
    ipaddr=netifaces.ifaddresses(net_if)[netifaces.AF_INET][0]
    appendix = ""
    if net_if == inet_def_gw_device:
        appendix = "  (default gateway interface)"
    print(" {}. {} - {} {}".format(i,net_if,ipaddr['addr'],appendix)) 
    i+=1
print(" "+str(i)   +". Detect public IP if ifconfig.co ...")
print(" "+str(i+1) +". Detect public IP if ipecho.net  ...")
source_select = ""
while not re.search("^[1-"+str(i)+"]", source_select.strip()):
    source_select = get_response("Which would you like to use?")
if int(source_select) >= i:
    print(" [*] Checking with ipecho.net...")
    htresponse = requests.get('https://ipecho.net/plain')
    print(" [*] Public IP detected: " + htresponse.text)  # This will print your public IP address
    ip_address = htresponse.text
else:
    source_select_idx=int(source_select) - 1
    logger.debug("indicated net iface: "+candidate_ifaces[source_select_idx])
    ip_address = netifaces.ifaddresses( candidate_ifaces[source_select_idx] )[netifaces.AF_INET][0]['addr']
logger.info("External IP Address selection:"+ip_address)

#Connection: SSL and ports
section_prompt("Connection protocol options:")
ssl_enabled = get_response("Do you want to use SSL? (Y/n)","Enabled")

cot_server_port = "0"
while not (re.search("^[0-9]+$", cot_server_port.strip()) and int(cot_server_port) > 3):
    cot_server_port = get_response("Port for COT Server?","8089")

#Data Package Service
section_prompt("Service Modules")
dp_server_enabled = get_response("Do you want to run the Data Package Server? (Y/n)","Enabled")
if dp_server_enabled == "Enabled":
    dp_server_filepath = get_response(" '- Where do you want to store the files?","/var/taky")
    if os.path.isdir(dp_server_filepath):
        logger.info("Confirmed that " + dp_server_filepath + " alredy exists.")
    else:
        warning_message="Warning: that path does NOT yet exist. You will need to create that directory path prior to starting the service."
        print(" * "+warning_message)
        logger.info(warning_message)

#Service Process User
#This section is not very cross-platform. Probably would just need to do some os self-reflection and have multiple sub scripts to call conditionally
section_prompt("Select TAKy server process user identity / security principal.")
default_service_user = getpass.getuser()
service_user = get_response("Which user do you want taky to run as?",default_service_user)
try:
        pwd.getpwnam(service_user)
except KeyError:
        warning_message="Warning: that username does NOT yet exist. You will need to create it prior to starting the service."
        print(" * "+warning_message)
        logger.info(warning_message)
logger.info("Service user selection:"+service_user)

# Service defintion and management
#TODO: little bug here. with the "clever" default behavior with y/n, this always ends up n. so probably need to refactor get_response or add additional clever.
section_prompt("Service registration/daemonization")
systemd_registration = get_response("Do you want to install the systemd scripts? (Y/n)","disabled")

#Initial client connection package provisioning
#type in now, csv, all entries member of tak_user group in local /etc/groups, etc.
#could include some optional unzip|sed|rezip for nat or ddns considerations.
#could include a destination to scp them to.

#Summary:
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

Here's the configuration I have so far.
 - Hostname: {hostname}
 - Bind IP:  {ip_address}
 - SSL:      {ssl_enabled}
 - COT Server Port:     {cot_server_port}
 - Service User:        {service_user}
 - Data Package Server: {dp_server_enabled}
 - Storage Path:        {dp_server_filepath}
   - DPS Server Port: 8443 (Not configurable at this time)
   - Install Systemd Startup Scripts: {systemd_registration}

""".format(**taky_configuration))

##TODO: actually DO configuration.

logger.info('Ending taky interactive setup.')
section_prompt("Done!")
print("Please remember to make sure ports "+taky_configuration['cot_server_port']+" and 8443 are open on your system.")

