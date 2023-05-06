import click
from scapy.all import *
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4Cmd

from zigcheck.testers.printer import Printer


class TestSuite:
    """
    Represents testing environment.
    """
    AVAILABLE_TESTERS = {'MAC_SECURITY': 'MacSecurity', 'NONCE_REUSE': 'NonceReuse', 'TEST_KEY': 'KeyTester',
                         'TRANSPORT_KEY': 'TransportKey', 'SWITCH_KEY': 'SwitchKey', }
    AVAILABLE_DEVICES = {'CC2531', 'Offline'}

    def __init__(self, tests, printer, device, pan_id, config):
        """
        Initiates testing class.

        Args:
            tests (list): array of names of tests to perform
            printer (bool): whether to print captured packets or not
            device (string): name of device to use for sniffing
            pan_id (int|None): PAN ID to filter packets by
            config (ConfigReader): complete configuration
        """
        self.testers = []
        for test in self.AVAILABLE_TESTERS:
            if test not in tests:
                continue

            class_name = self.AVAILABLE_TESTERS[test]
            # import and create new tester class
            self.testers.append(
                getattr(importlib.import_module('.' + class_name.lower(), 'zigcheck.testers'), class_name)(config))

        if printer:
            self.testers.append(Printer(config))

        if device not in self.AVAILABLE_DEVICES:
            raise IOError('Invalid device was provided.')

        # import and create new device class
        self.device = getattr(importlib.import_module('.' + device.lower(), 'zigcheck.devices'), device)(
            self.handle_packet, config)
        self.pan_id = pan_id

    def start(self):
        """
        Starts the testing process.
        """
        self.device.start()

    def stop(self):
        """
        Stops the testing process and prints report of all used testers.
        """
        self.device.stop()
        click.echo()
        for tester in self.testers:
            click.echo(f'{tester}:')
            tester.print_report()
            click.echo('\n' + ('-' * 100) + '\n')

    def handle_packet(self, pkt):
        """
            Checks if packet is sent within the specified PAN and forwards it to all testers.

            Args:
                pkt (Packet): packet captured by the device
        """
        if self.pan_id is not None:
            if pkt.haslayer(Dot15d4Data):
                subpkt = pkt.getlayer(Dot15d4Data)
            elif pkt.haslayer(Dot15d4Cmd):
                subpkt = pkt.getlayer(Dot15d4Cmd)
            else:
                subpkt = None

            # check if pkt is sent within the specified PAN
            if subpkt is not None and subpkt.dest_panid != self.pan_id and subpkt.src_panid != self.pan_id:
                return

        for tester in self.testers:
            tester.recv(pkt)
