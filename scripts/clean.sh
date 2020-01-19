#!/bin/bash

# This script is invoked on Mininet termination

# Kill the turn server
killall turnserver
# Stop the etherws virtual switch
killall etherws