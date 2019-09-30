# wifi-presence-detector
A Python script that sniffs ARP packets in the local network to detect presence of WiFi users, then updates the presence status in Ubidots.

You may run this script from a Linux box in the same network as your WiFi, such as a Raspberry Pi or an existing Linux server inside your office. These instructions are for a Raspberry Pi using Wheezy:

1. Setup your Pi
================

Make sure to start with a fresh and working Raspberry Pi with Internet access. You can find a setup guide here: http://ubidots.com/docs/devices/raspberrypi.html#setup-your-raspberry-pi

We strongly recommend using Wicd to manage the wifi connection.

2. Install the required libraries
=================================

sudo apt-get install python-setuptools

sudo easy_install pip

sudo pip install scapy

sudo pip install ubidots

3. Code the program!
====================

pi@raspberrypi ~ $ mkdir presence_detector

pi@raspberrypi ~ $ cd presence_detector/

pi@raspberrypi ~/access_control $ nano presence_detector.py

Paste the code into the file.

4. Create a dictionary with your user names
===========================================

This script reads the entries in the file "dictionary.csv" which should be placed in the same directory as the .py script. This file relates people's names to MAC addresses of their devices. Refer to the above sample file to get familiar with its structure, which is:

User Name, <MAC Address>

5. Create an account in Ubidots
================================

Go to http://app.ubidots.com/accounts/signup/ and create an account. Then go to your profile inside Ubidots and copy your API Key.

Put this API Key into the code (line ~73).

6. Done!
========

The script will automatically create a Datasource with the value of the variable "office" in the Python script. Then it will create a variable for each new device that is detected in the network AND that is also listed in "dictionary.csv".

Once you see this data, go to your Ubidots dashboard and create "<b>Indicator</b>" widgets to see if a person is inside or outside the office!
