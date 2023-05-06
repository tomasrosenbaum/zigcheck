#! /bin/bash

echo '### Installing dependencies... ###'
if sudo apt install -y python3.10-venv libusb-1.0-0-dev; then
    echo -e '### Dependencies installed successfully. ###\n'
else
    echo '### Unable to install dependencies. ###'
    exit 1
fi

echo '### Installing ZigCheck... ###'
if python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt .; then
    echo -e '### ZigCheck installed successfully. ###\n'
else
    echo '### Unable to install ZigCheck. ###'
    exit 1
fi

echo '### Installing whsniff... ###'
if cd whsniff && make && cd ..; then
    echo -e '### whsniff installed succesfully. ###\n'
else
    echo '### Unable to install whsniff. ###'
    exit 1
fi

echo -e '### ZigCheck was installed successfully. ###\n'
zigcheck -v
zigcheck --help
deactivate
