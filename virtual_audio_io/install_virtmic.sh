#!/bin/bash

echo "Creating virtual microphone."
pactl load-module module-pipe-source source_name=virtmic file=$HOME/virtmic format=s16le rate=44100 channels=1

echo "Set the virtual microphone as the default device."
pactl set-default-source virtmic

echo "default-source = virtmic" > $HOME/.config/pulse/client.conf

echo "Writing audio file to virtual microphone."
ffmpeg -re -i /media/aquaminjun1220/HardDrive0/Data/archive/kss/concathalf_51020_fb.wav -f s16le -ar 44100 -ac 1 - > $HOME/virtmic