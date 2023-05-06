from abc import ABC, abstractmethod
from enum import Enum

import click


class Tester(ABC):
    """
    Abstract class representing a tester.
    """
    STATUS = Enum('status', ['GOOD', 'BAD', 'NEUTRAL'])

    @abstractmethod
    def __init__(self, config):
        """
        Initiates Tester.

        Args:
            config (ConfigReader): complete configuration
        """
        pass

    @abstractmethod
    def __str__(self):
        """
        Returns:
            Name of the tester used for printing final report.
        """
        pass

    @abstractmethod
    def recv(self, pkt):
        """
        Process incoming packet.

        Args:
            pkt (Packet): packet to process
        """
        pass

    @abstractmethod
    def print_report(self):
        """
        Print report of the test outcome.
        """
        pass

    def print_report_format(self, status, msg):
        """
        Print message with status with color formatting.

        Args:
            status (Enum): status of the test
            msg (string): message to print
        """
        click.echo('[', nl=False)
        if status == self.STATUS['GOOD']:
            click.secho('+', nl=False, fg='green', bold=True)
        elif status == self.STATUS['NEUTRAL']:
            click.secho('-', nl=False, fg='yellow', bold=True)
        else:
            click.secho('X', nl=False, fg='red', bold=True)

        click.echo(f'] {msg}')
