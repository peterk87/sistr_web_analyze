# SISTR Web Analysis Python Script

Analyze a genome FASTA through the SISTR HTTP REST API using Python `requests` and save results to JSON (or Python pickle) output.


## Requirements

 - Python 2.7+ (not 3.x)

### Python 2.7+ package dependencies

Install the following packages using `pip`:

```
httplib2==0.9.2
requests==2.9.1
urllib3==1.14
```

or you can use the `requirements.txt` file:

```
pip install -r requirements.txt
```


## Usage

Run with `python sistr_web_analyze.py -i INPUT_FASTA [other args see below]`


Full usage info shown below with `python sistr_web_analyze.py -h` command:

```
usage: sistr_web_analyze [-h] -i INPUT_FASTA [-n GENOME_NAME]
                         [-f OUTPUT_FORMAT] [-o OUTPUT_DEST] [-u SISTR_USER]
                         [-p SISTR_PASSWORD] [--sistr-api-url SISTR_API_URL]
                         [-v]

Python script for web analysis of genome by SISTR
=================================================
Analyze a genome with SISTR using the public REST API.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FASTA, --input-fasta INPUT_FASTA
                        Input genome FASTA file
  -n GENOME_NAME, --genome-name GENOME_NAME
  -f OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        Output format (json, pickle)
  -o OUTPUT_DEST, --output-dest OUTPUT_DEST
                        Output destination
  -u SISTR_USER, --sistr-user SISTR_USER
                        SISTR username (anonymous temporary user is created if
                        no user specified; if registered user, password is
                        also required)
  -p SISTR_PASSWORD, --sistr-password SISTR_PASSWORD
                        SISTR user password (required for registered users)
  --sistr-api-url SISTR_API_URL
                        SISTR base HTTP API URL (default=lfz.corefacility.ca
                        /sistr-wtf/api/)
  -v, --verbose         Logging verbosity level (-v == show warnings; -vvv ==
                        show debug info)
```
