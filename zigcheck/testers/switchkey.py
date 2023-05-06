from datetime import datetime, timedelta

from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppCommandPayload, ZigbeeNWK

from zigcheck.testers.tester import Tester


class SwitchKey(Tester):
    """
    Tests the correct use of the switch key command as per ZigBee specification.
    """
    DAYS_IN_YEAR = 365
    DAYS_IN_MONTH = 30

    def __init__(self, config):
        """
        Initiates SwitchKey.

        Args:
            config (ConfigReader): complete configuration
        """
        self.status = None
        self.msg = ''
        self.start_time = datetime.now()
        self.switch_key_count = 0
        self.switch_key_last = None

    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        return 'SWITCH KEY'

    def recv(self, pkt):
        """
        Process incoming packet.
        Determines whether the packet is as switch key command and checks its correct usage.

        Args:
            pkt (Packet): packet to process
        """
        if pkt.haslayer(ZigbeeSecurityHeader):
            frame_count = pkt.getlayer(ZigbeeSecurityHeader).fc
            # key should be switched once the frame counter exceeds 2^(31)
            if frame_count > 2 ** 31:
                self.status = self.STATUS['BAD']
                self.msg += f'A message was sent with a frame counter larger than 2^(31) and key was not switched. (frame count: {frame_count}) '

            if pkt.haslayer(ZigbeeNWK):
                source = pkt.getlayer(ZigbeeNWK).source
                # key should be switched once the coordinator's outgoing frame count exceeds 2^(30)
                if source == 0 and frame_count > 2 ** 30:
                    if self.status != self.STATUS['BAD']:
                        self.status = self.STATUS['NEUTRAL']

                    self.msg += f'A message outgoing from the coordinator was sent with a frame counter larger than 2^(30) and key was not switched. This is only a problem if coordinator does not have RTC. (frame count: {frame_count}) '

        # check if packet is not a switch key
        if not pkt.haslayer(ZigbeeAppCommandPayload) or pkt.getlayer(ZigbeeAppCommandPayload).cmd_identifier != 9:
            start_time = self.start_time if self.switch_key_last is None else self.switch_key_last
            # key should be switched at least once a year
            if datetime.now() - start_time > timedelta(days=self.DAYS_IN_YEAR):
                self.status = self.STATUS['BAD']
                self.msg += 'A key was not updated in over a year. '

            return

        # key should be switched once a month tops
        # compared to 2 to allow for key switch using two consecutive switch key commands
        if self.switch_key_count >= 2:
            if datetime.now() - self.switch_key_last <= timedelta(days=self.DAYS_IN_MONTH):
                self.status = self.STATUS['BAD']
                self.msg += f'A key was changed more than once in the last {self.DAYS_IN_MONTH} days. '
            else:
                self.switch_key_count = 0

        self.switch_key_count += 1
        self.switch_key_last = datetime.now()

    def print_report(self):
        """
        Calls the __print_report_format function with appropriate status and message.
        """
        if self.status is None:
            if self.switch_key_count > 0:
                self.status = self.STATUS['GOOD']
                self.msg = 'No problem was found while using switch key command.'
            else:
                self.status = self.STATUS['NEUTRAL']
                self.msg = 'No switch key command was sent to determine its correct use.'

        self.print_report_format(self.status, self.msg)
