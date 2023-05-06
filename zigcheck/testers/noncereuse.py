import click
from scapy.layers.dot15d4 import Dot15d4AuxSecurityHeader

from zigcheck.testers.tester import Tester


class NonceReuse(Tester):
    """
    Tests if the communication uses encryption in TSCH mode.
    """
    def __init__(self, config):
        """
        Initiates NonceReuse.

        Args:
            config (ConfigReader): complete configuration
        """
        self.asn = None

    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        return 'NONCE REUSE'

    def recv(self, pkt):
        """
        Process incoming packet.
        Determines whether the packet is encrypted on MAC layer and checks the 'ASN in nonce' flag

        Args:
            pkt (Packet): packet to process
        """
        if not pkt.haslayer(Dot15d4AuxSecurityHeader) or \
                bytes(pkt.getlayer(Dot15d4AuxSecurityHeader)) == bytes.fromhex('0000000000'):
            return

        click.echo(bytes(pkt.getlayer(Dot15d4AuxSecurityHeader)).hex())

        if self.asn is None:
            self.asn = False

        # check the 'ASN in nonce' flag
        if pkt.getlayer(Dot15d4AuxSecurityHeader).sec_sc_reserved & 0b010:
            self.asn = True

    def print_report(self):
        """
        Calls the __print_report_format function with appropriate status and message.
        """
        if self.asn is None:
            status = self.STATUS['NEUTRAL']
            msg = 'No encrypted data was sent to determine whether TSCH mode was used.'
        elif self.asn:
            status = self.STATUS['BAD']
            msg = 'Communication in TSCH mode - nonce reuse possible.'
        else:
            status = self.STATUS['GOOD']
            msg = 'Communication not in TSCH mode - nonce reuse not possible.'

        self.print_report_format(status, msg)
