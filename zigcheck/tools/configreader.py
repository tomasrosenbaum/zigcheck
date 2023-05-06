import click
import yaml


class ConfigReader:
    """
    Represent an app configuration read from a file.
    """
    def __init__(self, file):
        """
        Initiates ConfigReader.

        Args:
            file (File): file to read the configuration from
        """
        self.file = file
        self.config = None

    def read(self):
        """
        Loads the configuration from the given file with PyYAML.
        """
        self.config = yaml.safe_load(self.file)
        return True

    def get(self, item):
        """
        Retrieves value of item.

        Args:
            item (list|string): array of keys-path to the desired value

        Returns:
            None if the item doesn't exist, otherwise return its value
        """
        if self.config is None:
            click.echo('Configuration file was not read.')
            return None

        if not isinstance(item, list):
            item = [item]

        config = self.config
        for subitem in item:
            if config is not None and subitem in config:
                config = config[subitem]
            else:
                click.echo(f'Missing value {item} in configuration file.')
                return None

        return config

    def set(self, item, value):
        """
        Set value of existing or new item.

        Args:
            item (list|string): array of keys-path to the desired value
            value: the value to set the item to

        Returns:
            None if the value can't be set, otherwise return its value
        """
        if self.config is None:
            click.echo('Configuration file was not read.')
            return None

        if not isinstance(item, list):
            item = [item]

        config = self.config
        for subitem in item[:-1]:
            if not isinstance(config, dict):
                click.echo(f'Invalid item {item}.')
                return None

            config = config.setdefault(subitem, dict())

        if not isinstance(config, dict):
            click.echo(f'Invalid item {item}.')
            return None

        config[item[-1]] = value
        return value
