#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
Script Name:     haproxyconf.py
Author:          Massimo Manghi
Date:            2025-04-23
Description:     
     Reads a file with tabular data (xls,xlxs,csv) in the format
     established to generated automatically the haproxy configuration
     for reverse proxying

Usage:
    ./haproxyconf.py --input <tabular data> 
                     --rogue <filename of rogue country codes>
                     --cidrmaps <cidr maps directory>
                     --output <output filename>

Dependencies:
    It depends on the Pandas Python library
    
Notes:
    -
==============================================================================
"""
"""
Script to generate HAProxy frontend/backend stanzas from an Excel service map,
with ACLs for Accept/Reject lists and rogue countries.
"""

import sys
import re
import logging
import pandas as pd
import os
import argparse
from haconf import ACL
from haconf import Backend
from haconf import Frontend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

service_types = {'http','pgsql','ssh'}
backends    = []      # list of registered backends
frontends   = dict()  # dictionary of frontends (port as key)
rogue_codes = []

def register_frontend (svctype,name,port):
    # svctype http, pgsql, ssh
    mode = 'http' if svctype == 'http' else 'tcp'
    if (port not in frontends):
        frontends[port] = Frontend(name,port,mode)

    return frontends[port]

def register_backend (idx,be_name,mode,target_ip,target_port):
    be=Backend(idx,be_name,mode,target_ip,target_port)
    backends.append(be)
    return be


def parse_list_field(field):
    """ Split Accept/Reject cell into list of entries. """
    if pd.isna(field) or not str(field).strip():
        return []
    # split on semicolon, comma, or whitespace
    return re.split(r"[;,\s]+", str(field).strip())


def main():
    parser = argparse.ArgumentParser(description='Generate HAProxy config stanzas.')
    parser.add_argument('-i','--input', default='mappa-servizi.xlsx', help='Excel file with service map')
    parser.add_argument('-r','--rogue', default='rogue.txt', help='File listing rogue country codes')
    parser.add_argument('-c','--cidrmaps', default='cidr_maps', help='Directory with country CIDR files')
    parser.add_argument('-o','--output', default='haproxy_generated.cfg', help='Output HAProxy config file')
    args = parser.parse_args()

    print(str(args))

    ACL.cidr_dir = args.cidrmaps

    # Read service map
    df = pd.read_excel(args.input)

    # Load rogue countries
    try:
        with open(args.rogue) as f:
            for line in f:
                code = line.strip().upper()
                if code:
                    rogue_codes.append(code)
    except FileNotFoundError:
        pass

    # Start writing config
    for idx, row in df.iterrows():
        #print(f" -> {idx}: {str(row)}")
        svc_type = str(row['Service Type']).strip().lower()
        raw_sni = row.get('SNI')
        sni = str(raw_sni).strip() if not pd.isna(raw_sni) else ''
        
        # se sni = '' questo è un 'falsy' e quindi il nome del
        # servizio viene generato a partire dal tipo di servizio 
        # e dalla porta
        
        name = sni or f"{svc_type}_{int(row['Port'])}"

        port = int(row['Port'])
        target_ip = str(row['Target IP']).strip()
        target_port = row['Target Port']
        mode = 'http' if svc_type == 'http' else 'tcp'

        fe_name = f"srv_{svc_type}_{port}"
        fe = register_frontend(svc_type,fe_name,port)

        # register backend with the data so far collected
        be = register_backend(idx,f"bk_{name}_{target_ip}_{target_port}",mode,target_ip,target_port)

        print(f" -> {idx}: {svc_type} - {port}")

        accept_list = [x.upper() for x in parse_list_field(row.get('Accept',''))]
        reject_list = [x.upper() for x in parse_list_field(row.get('Reject',''))]

        if ('ALL' in reject_list) and ('ALL' in accept_list):
            logging.error(f"Inconsistent ACL definition for line {idx}")
            sys.exit(1)

        # Accept/Reject logic
        print(f"registering acl for service {fe.name} -> {be.name}")
        if 'ALL' in reject_list:
            # Default reject, allow only Accept list
            for val in accept_list:
                acl = ACL("accept",val,mode)
                fe.register_acl(be,acl)
        elif 'ALL' in accept_list:
            for val in reject_list:
                acl = ACL("reject",val,mode)
                fe.register_acl(be,acl)

    with open(args.output, 'w') as fout:
        print("Backends....")
        for be in backends:
            print("----------------")
            fout.write(str(be)+'\n')

        print("Frontends....")
        for fe in frontends:
            print("----------------")
            fout.write(str(frontends[fe])+'\n')


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)

