#!/bin/bash

# This script is invoked on Mininet termination

# Kill the turn server
killall turnserver
# Stop the etherws virtual switch
killall etherws
# Remove documents from MongoDB
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.devices.remove({})"
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.overlays.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.dev_to_ip.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.last_allocated_ip.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.last_allocated_vni.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.overlay_to_vni.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.reusable_ip.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.reusable_vni.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.slices_in_overlay.remove({})"
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.tenants.remove({})"
#mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.tenants.insert({\"tenantid\": \"1\", \"conf\": {\"port\": NumberInt(4789)}})"  # TODO to be removed
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.tenants.insert({\"tenantid\": \"1\"})"  # TODO to be removed
mongo "mongodb://root:12345678@localhost:27017/EveryWan?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false" --eval "db.configuration.remove({})"