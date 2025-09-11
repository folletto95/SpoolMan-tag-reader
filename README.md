# SpoolMan-tag-reader

A simple Python utility to read the NFC tag attached to BambuLab filament spools and publish the decoded information to a [SpoolMan](https://github.com/Donkie/Spoolman) instance.

## Requirements

* [nfcpy](https://nfcpy.readthedocs.io/) for accessing the PN532 reader
* [requests](https://docs.python-requests.org/) for sending data to SpoolMan

Install the dependencies with:

```bash
pip install nfcpy requests
```

## Usage

Connect a PN532 reader via USB to your Raspberry Pi and run:

```bash
python spoolman_tag_reader.py
```

The script will wait for a tag, decode the contents and POST the spool information to SpoolMan at `http://localhost:8000/api/spools`.

Update `SPOOLMAN_URL` in `spoolman_tag_reader.py` if your instance runs elsewhere.
