import datetime

import click
from scapy.all import *
from scapy.layers.zigbee import ZigbeeNWK

from zigcheck.testers.tester import Tester


class Printer(Tester):
    """
    Pseudo-test that allows printing of the captured communication.
    """
    def __init__(self, config):
        """
        Initiates Printer.

        Args:
            config (ConfigReader): complete configuration
        """
        # determine whether IEEE802.15.4-only packets should be printed
        self.print_ieee = False
        print_ieee = config.get(['testers', 'PRINTER', 'print_ieee'])
        if print_ieee is not None and isinstance(print_ieee, bool) and print_ieee:
            self.print_ieee = True

        self.packets = []

    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        return 'PRINT'

    def recv(self, pkt):
        """
        Process incoming packet.
        Determines whether the packet is IEEE802.15.4-only and saves it for later printing.

        Args:
            pkt (Packet): packet to process
        """
        if not self.print_ieee and not pkt.haslayer(ZigbeeNWK):
            return

        self.packets.append(f'###[ {datetime.now().strftime("%H:%M:%S")} ]###\n{pkt.show(dump=True)}')
        # print raw payload in hex format for better readability
        if pkt.haslayer(Raw):
            self.packets[-1] += f'###[ Raw (hex) ]###\n\t{bytes(pkt.getlayer(Raw)).hex(":")}'

    def print_report(self):
        """
        Prints all the captured messages.
        """
        for pkt in self.packets:
            click.echo(f'\n{pkt}\n')
