import requests
import json
import os.path
from scapy.all import *


TPLINK_TOKEN = "a1b2c3d-460002228..."
TPLINK_DEVICEID = "12345678900987654321..."
TPLINK_URL = "https://eu-wap.tplinkcloud.com/?token=" + TPLINK_TOKEN
DASH_HWID = "D:A:S:H:I:D"
SETTINGS_FILE_NAME = "settings.json"
settings = {}

def load_settings():
	global settings
	""" Load settings """
	if not os.path.isfile(SETTINGS_FILE_NAME):
		print "Unable to find settings.json. Please use settings.example.json as an example"
    	else:
		with open(SETTINGS_FILE_NAME, 'r') as settings_file:
			settings = json.loads(settings_file.read())
	if settings.get("TPLINK_TOKEN") == None:
		settings["TPLINK_TOKEN"] = TPLINK_TOKEN
	if settings.get("TPLINK_DEVICEID") == None:
		settings["TPLINK_DEVICEID"] = TPLINK_DEVICEID
	if settings.get("TPLINK_URL") == None:
		settings["TPLINK_URL"] = TPLINK_URL
	settings["TPLINK_URL"] = settings["TPLINK_URL"].format(settings["TPLINK_TOKEN"])
	if settings.get("DASH_HWID") == None:
		settings["DASH_HWID"] = DASH_HWID

def SwitchState():
	if settings["TPLINK_TOKEN"] == "a1b2c3d-460002228...":
		print "TPLINK account token is not defined. Please edit settings.json"
		return

	session = requests.Session()

	""" Get current relay_state """
	get_sysinfo = {"method":"passthrough","params": {"deviceId": settings["TPLINK_DEVICEID"], \
		"requestData": "{\"system\":{\"get_sysinfo\":{}}}" }}
	resp_sysinfo = session.post(settings["TPLINK_URL"], json=get_sysinfo)

	dict_sysinfo = json.loads(resp_sysinfo.text)
	if dict_sysinfo.get("result") == None:
		print "Error, no result in sysinfo response"
		print dict_sysinfo
		return
	if dict_sysinfo["result"].get("responseData") == None:
		print "Error, no responseData in sysinfo response"
		print dict_sysinfo
		return

	dict_respData = json.loads(dict_sysinfo["result"]["responseData"])
	if dict_respData.get("system") == None:
		print "Error, no system in sysinfo response"
		print dict_respData
		return
	if dict_respData["system"].get("get_sysinfo") == None:
		print "Error, no get_sysinfo in sysinfo response"
		print dict_respData
		return
        if dict_respData["system"]["get_sysinfo"].get("relay_state") == None:
		print "Error, no relay_state in sysinfo response"
		print dict_respData
		return

	relay_state = dict_respData["system"]["get_sysinfo"]["relay_state"]
	alias = dict_respData["system"]["get_sysinfo"]["alias"]
	# print "current_state" + relay_state

	if relay_state:
		relay_state = "0"
		print "Switching Off " + alias
	else:
		relay_state = "1"
		print "Switching On " + alias

	""" Force refresh """
	get_deviceList = {"method":"passthrough", "params": {"deviceId": settings["TPLINK_DEVICEID"], \
		"requestData":"{\"schedule\":{\"get_next_action\":null}}"}}
	resp_deviceList = session.post(settings["TPLINK_URL"], json=get_deviceList)
	#print resp_deviceList.text

	""" Set new relay_state """
	post_relaystate = {"method":"passthrough", "params": {"deviceId": settings["TPLINK_DEVICEID"], \
		"requestData":"{\"system\":{\"set_relay_state\":{\"state\":"+relay_state+"} } }" } }
	#print post_relaystate
	resp_poststate = session.post(settings["TPLINK_URL"], json=post_relaystate)
	dict_poststate = json.loads(resp_poststate.text)
	if dict_poststate["error_code"] != 0:
		print dict_poststate


def arp_handler(pkt):
    """ Handles sniffed ARP requests """
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 1: #who-has request
		if settings["DASH_HWID"] == "D:A:S:H:I:D":
			print "Receive signal from a device : " + pkt[ARP].hwsrc
		if pkt[ARP].hwsrc == settings["DASH_HWID"]:
			print "Dash button pressed " + pkt[ARP].hwsrc
			SwitchState()
def main():
	print "Starting Amazon Dash to TPLink Smartplug service"
	load_settings()
	if settings["DASH_HWID"] == "D:A:S:H:I:D":
        	print "Scanning network: looking for a new Amazon Dash button... You can now press it"
	else:
		print "Scanning network: You can press your Amazon Dash button"
	sniff(prn=arp_handler, filter="arp", store=0)

if __name__ == "__main__":
	main()
