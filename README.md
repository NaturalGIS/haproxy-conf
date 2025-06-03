## haproxyconf.py

Haproxy configuration generator from data in tabular form

## Usage

```
$ ./haproxyconf.py --help
usage: haproxyconf.py [-h] [-i INPUT] [-r ROGUE] [-c CIDRMAPS] [-o OUTPUT]

Generate HAProxy config stanzas.

options:
  -h, --help            Show this help message and exit
  -i, --input INPUT     Excel file with service map
  -r, --rogue ROGUE     File listing rogue country codes
  -c, --cidrmaps CIDRMAPS
                        Directory with country CIDR files
  -o, --output OUTPUT   Output HAProxy config file
```



