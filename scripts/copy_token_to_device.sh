#!/bin/bash

# This script copy a token to an edge device

# Source filename
source="/tmp/token-$1"
# Destination filename
dst=./token
# Wait for tokens beeing generated
sleep 10
# Copy the file from the source to the destination
cp $source $dst