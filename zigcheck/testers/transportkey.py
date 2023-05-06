from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeAppCommandPayload

from zigcheck.testers.tester import Tester
from zigcheck.tools.decrypter import Decrypter


class TransportKey(Tester):
    """
    Tests how the transport key command is used.
    """
    WELL_KNOWN_LINK_KEY = bytes.fromhex('5A6967426565416C6C69616E63653039')

    def __init__(self, config):
        """
        Initiates TransportKey.

        Args:
            config (ConfigReader): complete configuration
        """
        self.decrypter = Decrypter()
        self.status = self.STATUS['NEUTRAL']
        self.msg = ''

    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        return 'TRANSPORT KEY'

    def recv(self, pkt):
        """
        Process incoming packet.
        Tests whether and how encrypted the packet is. Checks if the message is sent as unicast.

        Args:
            pkt (Packet): packet to process
        """
        if not pkt.haslayer(ZigbeeAppDataPayload):
            return

        # work on a copy to not alter the original packet
        app_data = pkt.getlayer(ZigbeeAppDataPayload).copy()
        is_unicast = app_data.delivery_mode == 0
        is_encrypted = False
        if app_data.haslayer(ZigbeeSecurityHeader):
            # restore header if it was malformed by previous tests
            app_data.getlayer(ZigbeeSecurityHeader).remove_payload()
            app_data.frame_control |= 0x02
            is_encrypted = True
            if not self.decrypter.decrypt(app_data, self.WELL_KNOWN_LINK_KEY,
                                          pkt.getlayer(ZigbeeSecurityHeader).source):
                if app_data.getlayer(ZigbeeSecurityHeader).key_type not in [2, 3]:
                    return

                if not is_unicast:
                    self.status = self.STATUS['BAD']
                    self.msg += 'Transport key not sent as unicast.\n\t'
                elif self.status != self.STATUS['BAD']:
                    self.status = self.STATUS['GOOD']

                return

        if pkt.haslayer(ZigbeeAppCommandPayload) and pkt.getlayer(ZigbeeAppCommandPayload).cmd_identifier == 5:
            self.status = self.STATUS['BAD']
            if is_encrypted:
                self.msg += 'Transport key mechanism used with a well-known link key.\n\t'
            else:
                self.msg += 'Transport key mechanism used with no encryption.\n\t'

            if not is_unicast:
                self.msg += 'Transport key not sent as unicast.\n\t'

    def print_report(self):
        """
        Calls the __print_report_format function with appropriate status and message.
        """
        if self.status == self.STATUS['GOOD']:
            self.msg = 'Transport key mechanism used and properly secured.'
        elif self.status == self.STATUS['NEUTRAL']:
            self.msg = 'No transport key command was sent to determine its correct use.'

        self.print_report_format(self.status, self.msg.strip())
