# ZigCheck
Python application for security analysis of ZigBee networks. This appliaction utilizes CC2531 and whsniff to perform sniffing.

## Installation
```console
$ git clone https://github.com/tomasrosenbaum/zigcheck.git
$ cd zigcheck
$ chmod +x install.sh
$ ./install.sh
```

## Usage
Activate Python virtual environment.
```console
$ source venv/bin/activate
```

Now you can start ZigCheck.
```console
$ zigcheck
```

Use ``zigcheck --help`` for more information.

After you're done, you can deactivate the virtual environment.
```console
$ deactivate
```

### Configuration
You can update the app's configuration by updating the ``config.yml`` file or by specifying command line options.
