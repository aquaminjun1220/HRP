#!/bin/bash

# Uninstall the virtual speaker.

pactl unload-module module-null-sink
rm $HOME/.config/pulse/client.conf 