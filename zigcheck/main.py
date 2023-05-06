import time
from pathlib import Path
from signal import signal, SIGINT

import click
import yaml
from scapy.config import conf

import zigcheck.testsuite
from zigcheck.tools.configreader import ConfigReader

conf.dot15d4_protocol = "zigbee"

APP_NAME = 'ZigCheck'
APP_VERSION = '0.1'
ASCII_ART = '''
  _______        _____ _               _    
 |___  (_)      / ____| |             | |   
    / / _  __ _| |    | |__   ___  ___| | __
   / / | |/ _` | |    | '_ \ / _ \/ __| |/ /
  / /__| | (_| | |____| | | |  __/ (__|   < 
 /_____|_|\__, |\_____|_| |_|\___|\___|_|\_\\
           __/ |                            
          |___/                             '''


@click.group()
def cli(ctx):
    pass


def ascii_art():
    """
    Prints name of application in ascii art.
    """
    click.echo('\n' + '/' * 50)
    click.echo(ASCII_ART)
    click.echo('\n' + '/' * 50 + '\n')


def version(ctx, param, value):
    """
    Prints application version.
    """
    if not value or ctx.resilient_parsing:
        return

    ascii_art()
    click.echo(f'{APP_NAME} v{APP_VERSION}\n')
    ctx.exit()


def get_config_file():
    """
    Returns:
        Path of the configuration file
    """
    directory = Path(__file__)
    for folder in directory.parents:
        if folder.name == 'venv':
            directory = folder.parent
            break

    directory = Path(directory, 'config.yml')
    return directory


@cli.command()
@click.option('-v', '--version', is_flag=True, callback=version, expose_value=False, is_eager=True,
              help='Print version and exit.')
@click.option('-c', '--configfile', type=click.File('r'), default=click.open_file(str(get_config_file())),
              help='Configuration file.')
@click.option('-t', '--tests', type=click.STRING, default=None, help='Comma-separated names of tests to run.')
@click.option('--print/--no-print', 'print_packets', type=click.BOOL, default=None,
              help='Enable/disable printing of captured packets.')
@click.option('-d', '--device', type=click.Choice(['CC2531', 'Offline']), default=None,
              help='Device used for capturing traffic.')
@click.option('--no-pan-id', is_flag=True, type=click.BOOL, help='Don\'t filter packets by PAN ID.')
@click.option('--pan-id', type=click.INT, default=None, help='PAN ID to filter packets.')
@click.option('--stop-after', type=click.INT, default=None,
              help='How long the scan should take in seconds. Non-positive value means infinite.')
@click.option('--channel', type=click.IntRange(11, 26), default=None,
              help='On which channel the scan should be performed.')
@click.option('--set', 'settings', nargs=2, multiple=True,
              help='Set any value of the configuration. Multiple set options allowed. Usage: --set <colon-separated key> <value> (e.g. --set devices:Offline:file capture.pcap)')
def scan(configfile, tests, print_packets, device, no_pan_id, pan_id, stop_after, channel, settings):
    """
    \f
    Entry point of the application.
    """
    ascii_art()
    config = ConfigReader(configfile)
    if not config.read():
        return

    # parse and set settings passed by the --set option
    for item, value in settings:
        config.set([subitem.strip() for subitem in item.split(':')], yaml.safe_load(f'x: {value}')['x'])

    # read values from config file if no were provided on command line, otherwise set configuration
    channel = config.get('channel') if channel is None else config.set('channel', channel)
    tests = config.get('tests') if tests is None else config.set('tests', [test.strip() for test in tests.split(',')])
    print_packets = config.get('print') if print_packets is None else config.set('print', print_packets)
    device = config.get('device') if device is None else config.set('device', device)
    stop_after = config.get('stop_after') if stop_after is None else config.set('stop_after', stop_after)
    if no_pan_id:
        pan_id = None
    else:
        pan_id = config.get('pan_id') if pan_id is None else config.set('pan_id', pan_id)

    # check if all config values are valid
    if None in [channel, tests, print_packets, device, stop_after] or not isinstance(channel, int) or \
            not isinstance(tests, list) or not isinstance(print_packets, bool) or not isinstance(device, str) or \
            (pan_id is not None and not isinstance(pan_id, int)) or not isinstance(stop_after, int):
        click.echo('Unexpected value in configuration file.')
        return

    try:
        test_suite = zigcheck.testsuite.TestSuite(tests, print_packets, device, pan_id, config)
    except ValueError as e:
        click.echo(f'Invalid configuration. {str(e)}')
        return
    except IOError as e:
        click.echo(f'Unable to use device. {str(e)}')
        return

    test_suite.start()

    def stop(*args):
        click.echo('\nStopping...')
        test_suite.stop()
        exit()

    # call the stop function when Ctrl-C is pressed
    signal(SIGINT, stop)
    if stop_after > 0:
        progressbar_step = 10
        with click.progressbar(range(stop_after * progressbar_step),
                               label='Testing in progress. Use Ctrl-C to stop.') as bar:
            for i in bar:
                time.sleep(1 / progressbar_step)
    else:
        click.pause(info='Testing in progress. Press any key to stop.')

    stop()


if __name__ == '__main__':
    cli()
