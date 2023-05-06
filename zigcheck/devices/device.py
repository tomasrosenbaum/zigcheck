from abc import ABC, abstractmethod


class Device(ABC):
    """
    Abstract class representing a sniffing device.
    """
    @abstractmethod
    def __init__(self, handler, config):
        """
        Initiates Device.

        Args:
            handler (function): function to handle packets
            config (ConfigReader): complete configuration
        """
        pass

    @abstractmethod
    def start(self):
        """
        Start sniffing in new thread.
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Stop the sniffing thread.
        """
        pass
