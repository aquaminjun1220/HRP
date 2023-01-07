#!/bin/bash

echo "Creating virtual speaker."
pactl load-module module-null-sink sink_name=virtspk format=s16le rate=44100 channels=1

echo "Set the virtual speaker as the default device."
pactl set-default-sink virtspk

echo "default-sink = virtspk" > $HOME/.config/pulse/client.conf

echo "Press Return to record audio"
read line

# Write the audio file to the named pipe virtmic. This will block until the named pipe is read.
echo "Recording from sink monitor to file"
parecord -r -v --device=virtspk.monitor --rate=44100 --format=s16le --channels=1 ./audio/virtspk_out.wav
# Write the audio file to the named pipe virtmic. This will block until the named pipe is read.
echo "Recording from sink monitor to file"
parecord -r -v --device=virtspk.monitor --rate=44100 --format=s16le --channels=1 ./audio/virtspk_out.wav