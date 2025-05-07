## haproxyconf.py

Haproxy configuration generator from data in tabular form

## Usage

```
$ ./haproxyconf.py --help
usage: haproxyconf.py [-h] [-i INPUT] [-r ROGUE] [-c CIDRMAPS] [-o OUTPUT]

Generate HAProxy config stanzas.

options:
  -h, --help            show this help message and exit
  -i, --input INPUT     Excel file with service map
  -r, --rogue ROGUE     File listing rogue country codes
  -c, --cidrmaps CIDRMAPS
                        Directory with country CIDR files
  -o, --output OUTPUT   Output HAProxy config file
```

## 

 * -h,--help: prints the usual usage information
 * -i,--input: .xlsx,.csv input file (default: mappa-servizi.xlsx)
 * -c,--cidrmaps: cidr maps directory
 * -o.--ouput: configuration file output 




