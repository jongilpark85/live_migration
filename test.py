import subprocess
import signal
import time


def Run():
    # Run the receiver on a separate terminal
    Receiver = subprocess.Popen(['gnome-terminal', '-x', './receiver'])

    # Run the original/target with libsender.so loaded
    targetProcess = subprocess.Popen(['./target'], env={'LD_PRELOAD': './libsender.so'})
    time.sleep(5)

    # invoke live migration
    targetProcess.send_signal(signal.SIGUSR2)

    time.sleep(5)



if __name__ == "__main__":
    Run()