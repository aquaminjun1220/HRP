from scipy.io import wavfile
import numpy as np
from pypesq import pesq

def comp_SNR(x, y):
    """
       Compute SNR (signal to noise ratio)
       Arguments:
           x: vector, enhanced signal
           y: vector, reference signal(ground truth)
    """
    ref = np.power(y, 2)
    if len(x) == len(y):
        diff = np.power(x-y, 2)
    else:
        stop = min(len(x), len(y))
        diff = np.power(x[:stop] - y[:stop], 2)

    ratio = np.sum(ref) / np.sum(diff)
    value = 10*np.log10(ratio)
    
    return value

rate, ref = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/concat3rd_5_fb_16000.wav")
rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/PCMU_5_16000.wav")

print("PCMU_5")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/G722_5_16000.wav")

print("G722_5")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/OPUS_5_16000.wav")

print("OPUS_5")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, ref = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/concat3rd_10_fb_16000.wav")
rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/PCMU_10_16000.wav")

print("PCMU_10")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/G722_10_16000.wav")

print("G722_10")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/OPUS_10_16000.wav")

print("OPUS_10")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, ref = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/concat3rd_20_fb_16000.wav")
rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/PCMU_20_16000.wav")

print("PCMU_20")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/G722_20_16000.wav")

print("G722_20")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))

rate, deg = wavfile.read("/media/aquaminjun1220/HardDrive0/GoogleDrive/KSA/2022/HRP/Code/audio/cropped/OPUS_20_16000.wav")

print("OPUS_20")
print("SNR: ", comp_SNR(deg, ref))
print("PESQ: ", pesq(ref, deg, rate))
