from threading import Event, Thread

from scapy.utils import rdpcap

from zigcheck.devices.device import Device


class Offline(Device):
    """
    Pseudo-device that reads packets from a PCAP file.
    """
    def __init__(self, handler, config):
        """
        Initiates the offline pseudo-device.

        Args:
            handler (function): function to handle packets
            config (ConfigReader): complete configuration
        """
        filename = config.get(['devices', 'Offline', 'file'])
        if filename is None or not isinstance(filename, str):
            raise ValueError('Invalid filename.')

        self.handler = handler
        self.file = rdpcap(filename)
        self.event = None
        self.thread = None

    def start(self):
        """
        Create a new thread that reads all the packets from a file.
        """
        if self.thread is not None:
            return

        self.event = Event()
        self.thread = Thread(target=self.__thread_read, args=(self.event,))
        self.thread.start()

    def stop(self):
        """
        Stops the created thread.
        """
        if self.thread is None:
            return

        self.event.set()
        self.thread.join()

    def __thread_read(self, event):
        """
        Load each packet from the file and set it to the handler function.

        Args:
            event (Event): event indicating the thread to stop
        """
        for pkt in self.file:
            if event.is_set():
                return

            self.handler(pkt)
