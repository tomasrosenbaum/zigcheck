import time
from pathlib import Path
from subprocess import Popen, PIPE
import getpass

from scapy.sendrecv import AsyncSniffer

from zigcheck.devices.device import Device


class CC2531(Device):
    """
    Represents the CC2531 sniffer. Utilizes whsniff to sniff communication.
    """
    ERROR_MSG = 'libusb couldn\'t open USB device '

    def __init__(self, handler, config):
        """
        Initiates CC2531.

        Args:
            handler (function): function to handle packets
            config (ConfigReader): complete configuration
        """
        channel = config.get('channel')
        if channel is None or not isinstance(channel, int) or not 11 <= channel <= 26:
            raise ValueError('Invalid channel number.')

        directory = Path(__file__)
        for folder in directory.parents:
            if folder.name == 'venv':
                directory = folder.parent
                break

        directory = Path(directory, 'whsniff', 'whsniff')
        self.whsniff = Popen([directory, '-c', str(channel)], stdout=PIPE, stderr=PIPE)
        time.sleep(1)
        self.whsniff.poll()
        # check if whsniff started successfully
        if self.whsniff.returncode is not None:
            err = self.whsniff.communicate()[1].decode()
            # get the name of CC2531 usb
            device = err[err.find(self.ERROR_MSG) + len(self.ERROR_MSG):].split(',')[0]
            raise IOError(f'Unable to launch whsniff.\nTry: sudo chown {getpass.getuser()} {device}')

        self.sniffer = AsyncSniffer(offline=self.whsniff.stdout, prn=handler, store=False)

    def start(self):
        """
        Start sniffing traffic in a new thread.
        """
        self.sniffer.start()

    def stop(self):
        """
        Stops whsniff and the created thread.
        """
        self.whsniff.terminate()
        self.sniffer.stop()
