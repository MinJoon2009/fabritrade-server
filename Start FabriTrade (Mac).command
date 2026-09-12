#!/bin/bash
# Double-click this file to start FabriTrade on a Mac.
cd "$(dirname "$0")"
echo "Starting FabriTrade..."
# open the website in your browser after a moment
( sleep 2 ; open "http://localhost:3000" ) &
node server.js
