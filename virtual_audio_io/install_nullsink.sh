#!/bin/bash

echo "Creating virtual speaker."
pactl load-module module-null-sink sink_name=virtspk format=s16le rate=44100 channels=1

echo "Set the virtual speaker as the default device."
pactl set-default-sink virtspk

echo "default-sink = virtspk" > $HOME/.config/pulse/client.conf