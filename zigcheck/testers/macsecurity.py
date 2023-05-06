from scapy.layers.dot15d4 import Dot15d4AuxSecurityHeader, Dot15d4
from scapy.packet import Raw

from zigcheck.testers.tester import Tester


class MacSecurity(Tester):
    """
    Tests whether communication uses MAC encryption.
    """
    STATUS_THRESHOLD = 0.5

    def __init__(self, config):
        """
        Initiates MacSecurity.

        Args:
            config (ConfigReader): complete configuration
        """
        # read threshold used for evaluation from config, use default value if none is configured
        threshold = config.get(['testers', 'MAC_SECURITY', 'status_threshold'])
        if threshold is not None and (isinstance(threshold, float) or isinstance(threshold, int)) and \
                0 <= threshold <= 1:
            self.STATUS_THRESHOLD = threshold

        self.unsecured_count = 0
        self.integrity_only_count = 0
        self.encrypted_count = 0

    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        return 'MAC SECURITY'

    def recv(self, pkt):
        """
        Process incoming packet.
        Determines whether security is used or not. Adds a security header if Scapy doesn't automatically create one.
        Counts number of secured/integrity-only/unsecured packets.

        Args:
            pkt (Packet): packet to process
        """
        if pkt.getlayer(Dot15d4).fcf_security and not self.__has_security_header(pkt) and pkt.haslayer(Raw):
            pkt.add_payload(Dot15d4AuxSecurityHeader(bytes(pkt.getlayer(Raw))))
        elif not self.__has_security_header(pkt):
            self.unsecured_count += 1
            return

        seclevel = pkt.getlayer(Dot15d4AuxSecurityHeader).sec_sc_seclevel
        if seclevel in range(1, 4):
            self.integrity_only_count += 1
        elif seclevel in range(5, 8):
            self.encrypted_count += 1
        else:
            self.unsecured_count += 1

    def print_report(self):
        """
        Calls the __print_report_format function with appropriate status and message.
        The status is determined by comparing the share of secured and unsecured packet to the threshold.
        """
        total = self.unsecured_count + self.integrity_only_count + self.encrypted_count
        if total == 0:
            status = self.STATUS['NEUTRAL']
        elif self.encrypted_count / total >= self.STATUS_THRESHOLD:
            status = self.STATUS['GOOD']
        elif (self.encrypted_count + self.integrity_only_count) / total > self.STATUS_THRESHOLD:
            status = self.STATUS['NEUTRAL']
        else:
            status = self.STATUS['BAD']

        self.print_report_format(status,
                                 f'Encrypted: {self.encrypted_count}\tIntegrity only: {self.integrity_only_count}\tUnsecured: {self.unsecured_count}')

    @staticmethod
    def __has_security_header(pkt):
        """
        Temporary fix - Scapy in the newest version adds non-existing security header consisting of zeroes.

        Returns:
            True if packet has valid security header, False otherwise.
        """
        return pkt.haslayer(Dot15d4AuxSecurityHeader) and bytes(
            pkt.getlayer(Dot15d4AuxSecurityHeader)) != bytes.fromhex('0000000000')
