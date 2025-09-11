# SpoolMan-tag-reader

A simple Python utility to read the NFC tag attached to BambuLab filament spools and publish the decoded information to a [SpoolMan](https://github.com/Donkie/Spoolman) instance. The reader interface and API URL are configurable so the script works across different Linux distributions.

## Requirements

Python 3 with the `venv` module. The helper script will create a local virtual environment in `.venv` and install:

* [nfcpy](https://nfcpy.readthedocs.io/) for accessing the PN532 reader
* [requests](https://docs.python-requests.org/) for sending data to SpoolMan

## Usage

Copy `.env.example` to `.env` and adjust the settings for your environment:

```bash
cp .env.example .env
```

`SPOOLMAN_URL` sets the SpoolMan API endpoint and `PN532_DEVICE` can fix the reader interface (e.g. `usb` or `tty:USB0`). Set `PN532_DEVICE=auto` or leave it empty to let the script search for a reader automatically.

Connect a PN532 reader and run:

```bash
./run_spoolman_tag_reader.sh
```

On first run the script creates a `.venv` directory, installs dependencies, and loads configuration from `.env`. Command-line options `--device` and `--url` override the `.env` settings when supplied.

The script waits for a tag, decodes the contents, and POSTs the spool information to SpoolMan.