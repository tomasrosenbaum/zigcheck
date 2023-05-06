from scapy.layers.zigbee import *

from zigcheck.testers.tester import Tester
from zigcheck.tools.decrypter import Decrypter


class KeyTester(Tester):
    """
    Tests usage of well-known keys.
    """
    NWK_KEYS = {
        bytes.fromhex('01030507090B0D0F00020406080A0C0D'),
        bytes.fromhex('07030507090B0D0F00020406080B0C0D')
    }
    LINK_KEYS = {
        bytes.fromhex('5A6967426565416C6C69616E63653039')
    }

    def __init__(self, config):
        """
        Initiates KeyTester.

        Args:
            config (ConfigReader): complete configuration
        """
        self.decrypter = Decrypter()
        self.used_keys = set()
        self.encrypted_msg_recv = False

    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        return 'KEY TESTER'

    def recv(self, pkt):
        """
        Process incoming packet.
        Determines whether security is used and tries to decrypt the package using the well-known keys.

        Args:
            pkt (Packet): packet to process
        """
        if not (pkt.haslayer(ZigbeeNWK) or pkt.haslayer(ZigbeeAppDataPayload)) or \
                not pkt.haslayer(ZigbeeSecurityHeader):
            return

        self.encrypted_msg_recv = True
        if not pkt.haslayer(ZigbeeAppDataPayload):
            for key in self.NWK_KEYS:
                if not self.decrypter.decrypt(pkt, key):
                    continue

                self.used_keys.add(key)
                break

        if not pkt.haslayer(ZigbeeAppDataPayload):
            return

        source = pkt.getlayer(ZigbeeSecurityHeader).source
        aps = pkt.getlayer(ZigbeeAppDataPayload)
        if not aps.haslayer(ZigbeeSecurityHeader):
            return

        for key in self.LINK_KEYS.union(self.NWK_KEYS):
            if self.decrypter.decrypt(aps, key, source):
                self.used_keys.add(key)
                return

    def print_report(self):
        """
        Calls the __print_report_format function with appropriate status and message.
        """
        if not self.encrypted_msg_recv:
            status = self.STATUS['NEUTRAL']
            msg = 'No encrypted messages were sent to determine whether a known key was used.'
        elif not self.used_keys:
            status = self.STATUS['GOOD']
            msg = 'No well-known keys were used.'
        else:
            status = self.STATUS['BAD']
            msg = f'The following well-known keys were used:'
            for key in self.used_keys:
                msg += f'\n\t{key.hex(":")}'

        self.print_report_format(status, msg)
