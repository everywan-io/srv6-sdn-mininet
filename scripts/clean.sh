#!/bin/bash

# This script is invoked on Mininet termination

# Kill the turn server
killall turnserver
# Stop the etherws virtual switch
killall etherws
# Remove documents from MongoDB
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.devices.remove({})"
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.overlays.remove({})"