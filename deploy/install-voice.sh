#!/usr/bin/env bash
# Free JARVIS voice on the VPS: ffmpeg (audio format), espeak-ng (fallback voice), Piper (natural British voice).
set -e
apt-get update -qq
apt-get install -y -qq ffmpeg espeak-ng python3-pip
pip install --break-system-packages -q piper-tts
mkdir -p /opt/piper
python3 -m piper.download_voices --download-dir /opt/piper en_GB-alan-medium
ls -la /opt/piper
echo "Hello Adham, this is JARVIS. Voice test complete." | python3 -m piper -m /opt/piper/en_GB-alan-medium.onnx -f /tmp/jarvis-test.wav && echo "VOICE OK"
