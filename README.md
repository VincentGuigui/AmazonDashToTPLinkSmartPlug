# Install Python prerequisites : requests and Scapy
``` 
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
rm get-pip.py
pip install requests
pip install scapy
```

# Configure your Amazon Dash Button
* Start configuring your Amazon Dash using Amazon app 
  * Configure the WiFi
  * And stop before assigning a product
* Run 
```
python DashToTPLinkPlug.py
```
* Wait few seconds for python and the script to warm up
* Press your Amazon Dash once and see if a MAC Address appears
* Do it again to be sure it isn't another device
* When you are sure you know the MAC Address, copy/write it down
* CTRL-C to quit the script and return to the command line
* Edit `settings.json` and set DASH_HWID

# Configure your TPLInk SmartPlug HS100
* Edit `settings.json` 
  * set TPLINK_EMAIL with the email you use in KASA / TPLINK app
  * set TPLINK_PASSWORD with your actual KASA / TPLINK password
  * set TPLINK_ALIAS with the name you give to your TPLINK device (it's case sensitive)

# Starting the service for a long time
You can run the script in background with a command like this:
```
nohup python DashToTPLinkPlug.py &
```
or 
``` StartInBackground.sh ```
(the script need to be runned from the actual directory and will produce 
a log file name DashToTPLinkPlug.log


# Troubleshooting
* if you encounter an "Token expired" error, verify that you are using a correct TPLINK_TOKEN
