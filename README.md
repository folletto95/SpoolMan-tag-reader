# SpoolMan-tag-reader

A simple Python utility to read the NFC tag attached to BambuLab filament spools and publish the decoded information to a [SpoolMan](https://github.com/Donkie/Spoolman) instance. The reader interface and API URL are configurable so the script works across different Linux distributions.


## Requirements

* [nfcpy](https://nfcpy.readthedocs.io/) for accessing the PN532 reader
* [requests](https://docs.python-requests.org/) for sending data to SpoolMan

Install the dependencies with:

```bash
pip install nfcpy requests
```

## Usage

Connect a PN532 reader via USB (or another interface supported by [nfcpy](https://nfcpy.readthedocs.io/)) to your Linux system and run:

```bash
python spoolman_tag_reader.py --device usb --url http://localhost:8000/api/spools
```

The script will wait for a tag, decode the contents and POST the spool information to SpoolMan. Use `--device` to select the nfcpy interface string (e.g. `usb` or `tty:USB0`) and `--url` to specify the SpoolMan API endpoint. The default URL can also be set via the `SPOOLMAN_URL` environment variable.