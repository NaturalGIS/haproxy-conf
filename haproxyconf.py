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
    ./haproxyconf.py --input    <tabular data> 
                     --rogue    <filename of rogue country codes>
                     --cidrmaps <cidr maps directory>
                     --output   <output filename>

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

### ACL

class ACL:
    cidr_dir = "cidr_maps"

    def __init__(self,acl_class,acl_val,mode):
        self.acl_class  = acl_class      # either 'accept' or 'reject'
        self.mode       = mode           # 'tcp' or 'http' or 'https'
        self.val        = acl_val
        self.definition = ''
        self.acl_name   = ''

        if re.fullmatch(r'[A-Z]{2}',self.val):
            cidr_file = os.path.join(ACL.cidr_dir, f"{self.val}.cidr")
            acl_name = f"acl_{self.acl_class}_{self.val}"
            self.definition = f"    acl {acl_name} src -f {cidr_file}"
        elif re.fullmatch(r'\d+\.\d+\.\d+\.\d+',self.val):
            safe = self.val.replace('.','_')
            acl_name = f"acl_{self.acl_class}_ip_{safe}"
            self.definition = f"    acl {acl_name} src {self.val}"
        else:
            safe = self.val.replace('.', '_').replace('-', '_')
            acl_name = f"acl_{self.acl_class}_dns_{safe}"
            if mode in ['https','http']:
                self.definition = f"    acl {acl_name} hdr(host) -i {self.val}"
            else:
                self.definition = f"    acl {acl_name} req.ssl_sni -i {self.val}"
        self.acl_name = acl_name

    def name(self):
        return self.acl_name

    def __str__(self):
        return self.definition


class SNI(ACL):
    def __init__(self,acl_class,acl_val,mode):

        super().__init__(acl_class,acl_val,mode)
        sni = acl_val
        self.definition = f"    acl {self.acl_name} hdr_beg(host) -i {self.val}"


### Backend

class Backend:
    def __init__(self,idx,mode,target_ip,target_port):
        self.idx            = idx
        self.backend_name   = f"bk_{target_ip.replace('.','_')}_{target_port}"
        self.mode           = mode
        self.target_ip      = target_ip
        self.target_port    = target_port

    def name(self):
        return self.backend_name

    def __str__(self):
        return '\n'.join([f"backend    {self.backend_name}",
                          f"    mode   {self.mode}",
                          f"    server srv{self.idx} {self.target_ip}:{self.target_port} check"])

### Frontend

class Frontend:
    def __init__(self,port,svc_type):
        self.acls   = dict()
        self.rules  = dict()
        self.port   = port
        self.type   = svc_type
        self.mode   = 'http' if svc_type == 'http' else 'tcp'
        self.fename = f"{svc_type}_{port}_{self.mode}"

    def register_acl(self,backend,acl):
        be_name=backend.name()
        # registering acl to each backend
        # handled by this frontend
        if be_name not in self.acls:
            self.acls[be_name] = list()

        self.acls[be_name].append(acl)

    def name(self):
        return self.fename

    def __str__(self):
        decl_l = [f"frontend   {self.fename}",
                  f"    mode   {self.mode}"]

        # let's encrypy challenge

        le_challenge_response = ["    http-request return status 200 content-type text/plain",
                                 "lf-string \"%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\\n\"",
                                 "if { path_beg '/.well-known/acme-challenge/' }"]


        if self.port == 443:
            decl_l.append(f"    bind *:443 ssl crt /etc/haproxy/certs/ strict-sni")
            decl_l.append(" ".join(le_challenge_response))
        else:
            decl_l.append(f"    bind *:{self.port}")


        declaration='\n'.join(decl_l)

        #           <declaration>
        #               acl1
        #               acl2
        #               .....
        #               acln
        #               backend route <backend1> if <acl names 1>
        #               acl1
        #               acl2
        #               .....
        #               acln
        #               backend route <backend2> if <acl names 2>

        be_acls_l = []
        for be in self.acls:
            acls = self.acls[be]
            acl_names = []
            acl_defs  = []
            for acl_o in acls:
                print(f"{acl_o.name()} ---> {acl_o}")
                acl_defs.append(str(acl_o))
                acl_names.append(acl_o.name())

            print(f"acl_names {acl_names}")
            acl_names_txt = ' or '.join(acl_names)
            acl_defs.append(f"    use backend {be} if {acl_names_txt}")
            be_acls_l.append('\n'.join(acl_defs))

        return '\n'.join(["#    ------ Frontend -----", declaration,
                          "#    -------- ACLs -------", *be_acls_l])

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format = "%(asctime)s - %(levelname)s - %(message)s",
)

service_types = {'http','pgsql','ssh'}
backends    = dict()  # list of registered backends
frontends   = dict()  # dictionary of frontends (port as key)
rogue_codes = []

def register_frontend (fe_o):
    service_key = fe_o.name()
    if (service_key not in frontends):
        frontends[service_key] = fe_o
    else:
        print(f"Error: multiple registraton of frontend '{service_key}'")

    return frontends[service_key]   

def register_backend (be_o):
    be_name = be_o.name()
    if (be_name not in backends):
        backends[be_name] = be_o
    else:
        print(f"Warning: backend {be_name} already registered")

    return be_o


def parse_list_field (field):
    """ Split Accept/Reject cell into list of entries. """
    if pd.isna(field) or not str(field).strip():
        return []
    # split on semicolon, comma, or whitespace
    return re.split(r"[;,\s]+", str(field).strip())


### main 

def main():
    parser = argparse.ArgumentParser(description='Generate HAProxy config stanzas.')
    parser.add_argument('-i','--input', default='mappa-servizi.xlsx', help='Excel file with service map')
    parser.add_argument('-r','--rogue', default='rogue.txt', help='File listing rogue country codes')
    parser.add_argument('-c','--cidrmaps', default='cidr_maps', help='Directory with country CIDR files')
    parser.add_argument('-o','--output', default='haproxy_generated.cfg', help='Output HAProxy config file')
    args = parser.parse_args()

    print(str(args))

    ACL.cidr_dir = args.cidrmaps

    fname,fext=os.path.splitext(args.input)
    
    # Read service map
    match fext:
        case ".xlsx":
            df = pd.read_excel(args.input)
        case ".csv":
            df = pd.read_csv(args.input,header=0,delimiter='|')
        case "_":
            logging.error(f"Unknown file type {fext}")
            sys.exit(1)

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
        # column 'Status' controls a service that is by default disabled
        # By putting 'enable' in this column enables the generation of its
        # configuration stanzas. A service may be therefore disabled and still
        # in the dataset for documentation or because temporarily disabled

        target_ip   = str(row['Target IP']).strip()
        target_port = str(row['Target Port']).strip()
        if (row['Status'] != "enable"):
            print(f"Service for port {row['Port']} and target IP {target_ip} disabled")
            continue

        svc_type    = str(row['Service Type']).strip().lower()
        raw_sni     = row['SNI']
        if not pd.isna(raw_sni):
            sni     = str(raw_sni).strip()
        else:
            sni     = ''

        port        = int(row['Port'])
        fe          = Frontend(port,svc_type)

        print(f"registering frontend {fe.name()}")

        fe          = register_frontend(fe)

        # register backend 

        mode        = 'http' if svc_type == 'http' else 'tcp'
        be          = register_backend(Backend(idx,mode,target_ip,target_port))

        print(f" -> {idx}: {svc_type} - {port}")

        accept_list = [x.upper() for x in parse_list_field(row.get('Accept',''))]
        reject_list = [x.upper() for x in parse_list_field(row.get('Reject',''))]

        if ('ALL' in reject_list) and ('ALL' in accept_list):
            logging.error(f"Inconsistent ACL definition for line {idx}")
            sys.exit(1)

        # Accept/Reject logic

        print(f"registering acl for service '{fe.name()}' -> '{be.name()}'")
        if 'ALL' in reject_list:
            # Default reject, allow only Accept list
            for val in accept_list:
                acl = ACL("accept",val,mode)
                fe.register_acl(be,acl)

            if sni:
                acl = SNI("accept",sni,mode)
                fe.register_acl(be,acl)

        elif 'ALL' in accept_list:
            # Default allow, reject only Reject list
            for val in reject_list:
                acl = ACL("reject",val,mode)
                fe.register_acl(be,acl)

            if sni:
                acl = SNI("reject",sni,mode)
                fe.register_acl(be,acl)

    with open(args.output, 'w') as fout:
        print("Writing backends configuration....")
        for be in backends:
            #print("----------------")
            #print(str(backends[be]))
            fout.write(str(backends[be])+'\n')

        print("Writing frontends configuration....")
        for fe in frontends:
            #print("----------------")
            #print(str(frontends[fe]))
            fout.write(str(frontends[fe])+'\n')

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)

