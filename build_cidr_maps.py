#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
Script Name:     build_cidr_maps.py
Author:          Massimo Manghi
Date:            2025-04-15
Description:     
     Reads the Geoip country blocks and writes cidr maps files
     for each country

Usage:
     ./build_cidr_maps.it   --geolite-country-codes     <Geolite2 CSV country codes>
                            --geolite-country-locations <Geolite2 CSV country blocks>
                            --output                    <cidr maps output dir>

Dependencies:
    It depends on the csv python library
    
Notes:
    -

==============================================================================
"""
"""
Script to generate HAProxy frontend/backend stanzas from an Excel service map,
with ACLs for Accept/Reject lists and rogue countries.
"""
import csv
import sys
import os
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format = "%(asctime)s - %(levelname)s - %(message)s",
)

### main 

def main():
    # --- Configuration ---
    # Set the paths to your CSV files.
    parser = argparse.ArgumentParser(description='Generate country CIDR maps.')
    parser.add_argument('-c','--geolite-country-codes', default="/tmp/GeoLite2-Country-Blocks-IPv4.csv", help='')
    parser.add_argument('-l','--geolite-country-locations', default="/tmp/GeoLite2-Country-Locations-en.csv", help='')
    parser.add_argument('-m','--cidrmaps', default="cidr_maps/", help='Directory with country CIDR files')
    parser.add_argument('-cl','--country-list', default="ALL", help='Comma separated list of country IDs')
    args = parser.parse_args()

    try:
        os.makedirs(args.cidrmaps,exist_ok=False)
    except FileExistsError as fee:
        logging.info(f"cidr maps destination {args.cidrmaps} exists")
    except FileNotFoundError as fnfe:
        logging.error(f"A parent directory doesn't exist in path {args.cidrmaps}")
        sys.exit(1)
    
    # --- Load Locations: Map geoname_id to country ISO code ---
    try:
        locations = {}
        with open(args.geolite_country_locations, newline='', encoding="utf-8") as loc_file:
            reader = csv.DictReader(loc_file)
            for row in reader:
                geoname_id = row["geoname_id"]
                iso_code = row.get("country_iso_code", "").strip()
                if iso_code:
                    locations[geoname_id] = iso_code

    # --- Process Blocks: Map country ISO code to list of CIDR networks ---
        country_networks = {}
        with open(args.geolite_country_codes, newline='', encoding="utf-8") as blocks_file:
            reader = csv.DictReader(blocks_file)
            for row in reader:
                network = row["network"].strip()  # e.g., "1.0.0.0/24"
                # Prefer the registered country; if missing, use the represented country.
                geo_id = row.get("geoname_id", "").strip() or \
                         row.get("registered_country_geoname_id", "").strip() or \
                         row.get("represented_country_geoname_id", "").strip()
                iso_code = locations.get(geo_id)
                if not iso_code:
                    # Could not resolve country code; skip this entry.
                    continue
                country_networks.setdefault(iso_code,[]).append(network)
    except FileNotFoundError as fnfe:
        logging.error(f"File {args.filename} not found or not readable")
        logging.error(f"Python error: ´{fnfe.strerror}´")
        sys.exit(1)

    # --- Write out one file per country ---

    if args.country_list == "ALL":
        networks2generate = country_networks.items()
    else:
        countries = set([cc.upper() for cc in args.country_list.split(',')]) & \
                    set(list(country_networks.keys()))
        networks2generate = {cc: country_networks[cc] for cc in countries if cc in country_networks}
        networks2generate = networks2generate.items()

    for iso_code,networks in networks2generate:
        filename = os.path.join(args.cidrmaps,f"{iso_code}.cidr")
        with open(filename, "w", encoding="utf-8") as outfile:
            for net in networks:
                outfile.write(f"{net}\n")
        print(f"Wrote {len(networks)} networks to {filename}")
        os.chmod(filename,0o644)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)

