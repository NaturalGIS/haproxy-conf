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

## Let's encrypt certificate installation

### One time installation of acme scripts

create `acme` user
```
$ sudo adduser \
   --system \
   --disabled-password \
   --disabled-login \
   --home /var/lib/acme \
   --quiet \
   --force-badname \
   --group \
   acme

$ sudo adduser acme haproxy
```

Create directory for acme.sh code. Replace example.com with
the correct domain/host name
```
$ sudo mkdir /usr/local/share/acme.sh/
$ git clone https://github.com/acmesh-official/acme.sh.git
$ cd acme.sh/
$ sudo ./acme.sh \
   --install \
   --no-cron \
   --no-profile \
   --home /usr/local/share/acme.sh
$ sudo ln -s /usr/local/share/acme.sh/acme.sh /usr/local/bin/
$ sudo chmod 755 /usr/local/share/acme.sh/
```
Register ACME account

```
$ acme.sh   --register-account \
            --server letsencrypt \
            -m youremail@example.com
```

Prepare directory for certificates

```
$ sudo /bin/bash -
$ mkdir /etc/haproxy/certs
$ chown haproxy:haproxy /etc/haproxy/certs
$ chmod 770 /etc/haproxy/certs
$ systemctl restart haproxy
$ exit
```

Generate a certificate

```
$ sudo -u acme -s
$ acme.sh --issue -d example.com --stateless --server letsencrypt


