import requests
import json
import os.path
import uuid
import sys
import datetime
from scapy.all import *


TPLINK_TOKEN = "a1b2c3d-460002228..."
TPLINK_EMAIL = "email@domain.com"
TPLINK_PASSWORD = "YourKasaPassword"
TPLINK_ALIAS = "MY Living Room Light"
TPLINK_URL = "https://eu-wap.tplinkcloud.com/"
TPLINK_URL_LOGIN = "..."
TPLINK_URL_TOKEN ="..."
DASH_HWID = "D:A:S:H:I:D"
SETTINGS_FILE_NAME = "settings.json"
settings = {}

def load_settings():
	global settings, TPLINK_URL_LOGIN, TPLINK_URL_TOKEN
	""" Load settings """
	if not os.path.isfile(SETTINGS_FILE_NAME):
		print "Unable to find settings.json. Please use settings.example.json as an example"
		sys.exit()
	else:
		with open(SETTINGS_FILE_NAME, 'r') as settings_file:
			settings = json.loads(settings_file.read())

	""" Verify settings values """
	if settings.get("TPLINK_EMAIL") == None or settings.get("TPLINK_EMAIL") == TPLINK_EMAIL:
		print "TPLINK account (email) is not defined. Please edit settings.json"
		sys.exit()
	if settings.get("TPLINK_PASSWORD") == None or settings.get("TPLINK_PASSWORD") == TPLINK_PASSWORD:
		print "TPLINK account password is not defined. Please edit settings.json"
		sys.exit()
	if settings.get("TPLINK_ALIAS") == None or settings.get("TPLINK_ALIAS") == TPLINK_ALIAS:
		print "TPLINK Device alias is not defined. Please edit settings.json"
		sys.exit()
	if settings.get("DASH_HWID") == None or settings.get("DASH_HWID") == DASH_HWID:
		print "Dash button ID is not defined. Please edit settings.json"
		return

	if settings.get("TPLINK_URL") == None:
		settings["TPLINK_URL"] = TPLINK_URL

	if settings.get("TPLINK_TOKEN") == None:
		settings["TPLINK_TOKEN"] = TPLINK_TOKEN 
	TPLINK_URL_TOKEN = \
		(settings["TPLINK_URL"] + "?{}={}").format("token", settings["TPLINK_TOKEN"])
	TPLINK_URL_LOGIN = \
		(settings["TPLINK_URL"] + "?{}={}").format("appName" , "Kasa_Android")

def login_and_renew_token():
	global settings
	print "Renew TPLINK Token..."
	login = {"method":"login", \
			"params":{ \
				"appType":"Kasa_Android", \
				"cloudPassword":settings["TPLINK_PASSWORD"], \
				"cloudUserName":settings["TPLINK_EMAIL"], \
				"terminalUUID":str(uuid.uuid4()) \
			} \
		}

	resp_login = requests.post(TPLINK_URL_LOGIN, json=login)
	dict_login = json.loads(resp_login.text)

	if dict_login.get("error_code") == 0:
		settings["TPLINK_TOKEN"] = dict_login["result"]["token"]
		""" Save new token """
		with open(SETTINGS_FILE_NAME, 'w') as settings_file:
			json.dump(settings, settings_file)
		load_settings()
	else:
		print "TPLINK credentials are invalid."
		print dict_login["msg"]
		sys.exit()
		return

def switch_state():
	global settings

	print "New event on " + \
		datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	session = requests.Session()

	""" Get device id from Alias """
	get_deviceList = {"method":"getDeviceList","params": {}}
	resp_deviceList = session.post(TPLINK_URL_TOKEN, json = get_deviceList)

	dict_deviceList = json.loads(resp_deviceList.text)

	""" Must renew token if expired """
	if dict_deviceList.get("error_code") == -20651:
		login_and_renew_token()
		switch_state()
		return

	if dict_deviceList.get("result") == None:
		print "Error, no result in deviceList response"
		print dict_deviceList
		return

	""" Look for the deviceID """
	settings["TPLINK_DEVICEID"] = None
	print "Account has", len(dict_deviceList["result"]["deviceList"]), "device(s)"

	for d in dict_deviceList["result"]["deviceList"]:
		print "  " + d["deviceName"] + " : " + d["alias"]
		if d["alias"] == settings["TPLINK_ALIAS"]:
			print "    DeviceId : " + d["deviceId"]
			settings["TPLINK_DEVICEID"] = d["deviceId"]
			break

	if settings.get("TPLINK_DEVICEID") == None:
		print "No online TPLINK Device found with alias '" + settings["TPLINK_ALIAS"] + ". Check Name and Remote Access activation for this device within Kasa app.'"
		sys.exit()

	""" Get device current relay_state """
	get_sysinfo = {"method":"passthrough","params": {"deviceId": settings["TPLINK_DEVICEID"], \
		"requestData": "{\"system\":{\"get_sysinfo\":{}}}" }}
	resp_sysinfo = session.post(TPLINK_URL_TOKEN, json = get_sysinfo)

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

	if relay_state:
		relay_state = "0"
		print "Switching Off " + settings["TPLINK_ALIAS"]
	else:
		relay_state = "1"
		print "Switching On " + settings["TPLINK_ALIAS"]

	""" Force refresh """
	get_deviceList = {"method":"passthrough", "params": {"deviceId": settings["TPLINK_DEVICEID"], \
		"requestData":"{\"schedule\":{\"get_next_action\":null}}"}}
	resp_deviceList = session.post(TPLINK_URL_TOKEN, json = get_deviceList)

	""" Set new relay_state """
	post_relaystate = {"method":"passthrough", "params": {"deviceId": settings["TPLINK_DEVICEID"], \
		"requestData":"{\"system\":{\"set_relay_state\":{\"state\":"+relay_state+"} } }" } }

	resp_poststate = session.post(TPLINK_URL_TOKEN, json=post_relaystate)
	dict_poststate = json.loads(resp_poststate.text)
	if dict_poststate["error_code"] != 0:
		print dict_poststate


def arp_handler(pkt):
	""" Handles sniffed ARP requests """
	if pkt.haslayer(ARP):
		if pkt[ARP].op == 1: #who-has request
			if settings["DASH_HWID"] == DASH_HWID:
				print "Receive signal from a unknown device : " + pkt[ARP].hwsrc
			if pkt[ARP].hwsrc == settings["DASH_HWID"]:
				print "Dash button pressed " + settings["DASH_HWID"]
				switch_state()
def main():
	print "Starting Amazon Dash to TPLink Smartplug service"
	load_settings()
	if settings["DASH_HWID"] == DASH_HWID:
		print "Scanning network: looking for a new Amazon Dash button... You can now press it"
		print " Press it multiple times with a 5 sec pause to be sure it is your Dash we are detecting"
	else:
		print "Intercepting Dash " + settings["DASH_HWID"] + " enabled. You can use your Amazon Dash button"
	sniff(prn=arp_handler, filter="arp", store=0)

if __name__ == "__main__":
	main()
