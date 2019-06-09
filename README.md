# cloud_metadata_extractor

Cloud metadata extraction tools and scripts.

## Research

This repo is the result of research for the BSides San Antonio 2019 talk.  Click the link for the slides (included in this repo):

[There's no place like 169.254.169.254 - Ab(using) cloud metadata URLs](./abusing_cloud_metadata_urls-bsides_satx_2019.pdf)


## Installation

Scripts are written for Python 3.6+. Clone the git repository and install the requirements.

```bash
git clone https://github.com/opsdisk/cloud_metadata_extractor.git
cd cloud_metadata_extractor
virtualenv -p python3 .venv  # If using a virtual environment.
source .venv/bin/activate  # If using a virtual environment.
pip3 install -r requirements.txt
```

## Collect Target IPs

### Amazon AWS

```bash
python cloud_metadata_extractor.py -p aws -r
```

### Microsoft Azure

```bash
python cloud_metadata_extractor.py -p azure -r
```

### Digital Ocean

- Copy/pasted from <https://ipinfo.io/AS14061>
- Command line fu to extract
