# Install Python prerequisites : requests and Scapy
``` 
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py
rm get-pip.py
python pip install requests
python pip install scapy
```

# Configure your Amazon Dash Button
* Start configuring your Amazon Dash using Amazon app 
** Configure the WiFi
** And stop before assigning a product
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
* Go through [Find TPLink Token and Smartplug Device ID article](http://arcturusenterprises.weebly.com/find-token--deviceid.html)
* Edit `settings.json` and set TPLINK_TOKEN and TPLINK_DEVICEID

# Starting the service for a long time
You can know run the script in background with a command like this:
```
nohup python DashToTPLinkPlug.py &
```


# Troubleshooting
* if you encounter an "Token expired" error, verify that you are using a correct TPLINK_TOKEN
