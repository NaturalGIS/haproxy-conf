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
import datetime

### ACL

class ACL:
    cidr_dir = "cidr_maps"

    def __init__(self,acl_val,mode=''):
        self.mode       = mode                      # 'tcp' or 'http' or 'https'
        self.val        = acl_val
        self.definition = ''
        self.acl_name   = ''
        self.snidef     = None
        self.acl_type   = "generic"
        self.fetch_method = ""

        if re.fullmatch(r'[A-Z]{2}',self.val):
            cidr_file = os.path.join(ACL.cidr_dir, f"{self.val}.cidr")
            acl_name = f"acl_geo_{self.val}"
            self.fetch_method = f"src -f {cidr_file}" 
            self.definition = f"    acl {acl_name} {self.fetch_method}"
            self.acl_type   = "geo"

        elif re.fullmatch(r'\d+\.\d+\.\d+\.\d+',self.val):
            safe = self.val.replace('.','_')
            acl_name = f"acl_ip_{safe}"
            self.fetch_method = f"src {self.val}"
            self.definition   = f"    acl {acl_name} {self.fetch_method}"
            self.acl_type   = "ip"
        else:
            safe = self.val.lower().replace('.', '_').replace('-', '_')
            acl_name = f"acl_dns_{safe}"
            if mode in ['https','http']:
                self.fetch_method = f"hdr(host) -i {self.val.lower()}"
            else:
                self.fetch_method = f"req.ssl_sni -i {self.val.lower()}"

            self.definition   = f"    acl {acl_name} {self.fetch_method}"
        self.acl_name = acl_name

    def get_type(self):
        return self.acl_type

    def get_method(self):
        return self.fetch_method

    def sni(self):
        return self.snidef

    def name(self):
        return self.acl_name

    def __str__(self):
        return self.definition


class SNI(ACL):
    def __init__(self,acl_val,mode):
        super().__init__(acl_val,mode)
        sniname         = acl_val.strip() 
        self.snidef     = sniname.replace('.','_').replace('.','_')
        self.acl_name   = f"acl_sni_{self.snidef}"
        self.fetch_method = f"hdr(host) -i {sniname}"
        self.definition   = f"    acl {self.acl_name} {self.fetch_method}"
        self.acl_type   = "sni"

class Redir(SNI):
    def __init__(self,acl_val,mode):
        super().__init__(acl_val,mode)
        self.acl_type   = "redir"

### Backend

class Backend:
    def __init__(self,idx,mode,target_ip,target_port):
        self.idx            = idx
        self.backend_name   = f"bk_{target_ip.replace('.','_')}_{target_port}_{idx}"
        self.mode           = mode
        self.target_ip      = target_ip
        self.target_port    = target_port

    def name(self):
        return self.backend_name

    def __str__(self):
        return '\n'.join([f"backend    {self.backend_name}",
                          f"    mode   {self.mode}",
                          f"    server srv{self.idx} {self.target_ip}:{self.target_port} check"])


class NullBackend:
    def __init__(self,idx,sni):
        self.idx            = idx
        self.backend_name   = f"null_{sni}_80_{idx}"
        self.mode           = 'http'

    def name(self):
        return self.backend_name

    def __str__(self):
        return ""

### Frontend

class Frontend:
    reject_backend = "bk_reject_all"

    def __init__(self,port,svc_type):
        self.acls   = dict()
        self.rules  = dict()
        self.port   = port
        self.type   = svc_type
        self.mode   = 'http' if svc_type == 'http' else 'tcp'
        self.fename = f"{svc_type}_{port}_{self.mode}"

    #
    # -- register_acl
    #
    # We keep a dictionary mapping a backend to a list of acls
    #

    def register_acl(self,backend,acl_class,acl):

        # registering acl to each backend handled by this frontend

        be_name = backend.name()
        if be_name not in self.rules:
            self.rules.setdefault(be_name,{}).setdefault("accept",list())
            self.rules.setdefault(be_name,{}).setdefault("reject",list())
            self.rules.setdefault(be_name,{}).setdefault("sni",None)

        if acl_class == "sni":
            self.rules[be_name]["sni"] = acl
        else:
            self.rules[be_name][acl_class].append(acl)

        acl_name = acl.name()
        if acl_name not in self.acls:
            self.acls[acl_name] = acl


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
            decl_l.append(f"    bind *:{self.port} ssl crt /etc/haproxy/certs/ strict-sni")
            decl_l.append(" ".join(le_challenge_response))
        elif self.port == 80:
            decl_l.append(f"    bind *:{self.port}")
            decl_l.append(" ".join(le_challenge_response))
        else:
            decl_l.append(f"    bind *:{self.port}")

        declaration='\n'.join(decl_l)

        #           <declaration>
        #               acl1
        #               acl2
        #               .....
        #               acln
        #               backend route <backend1> if <acl names list 1>
        #               backend route <backend2> if <acl names list 2>

        # the acls definition

        acl_definitions_l = [str(acl_o) for acl_name,acl_o in self.acls.items()]

        # the rules definition

        be_rules_l = list()
        for be in self.rules:
            acls = self.rules[be]

            # we must detect whether there is a sni acl

            sni_acl = self.rules[be]["sni"]

            if sni_acl and self.mode == "http":
                if sni_acl.get_type() == "redir":
                    be_rule_line_prefix = f"    http-request redirect scheme https if {sni_acl.name()}"
                else:
                    be_rule_line_prefix = f"    use_backend {be} if {sni_acl.name()}"
            else:
                be_rule_line_prefix = f"    use_backend {be} if "

            reject_composite_acl = ""
            if self.rules[be]["reject"]:
                if (len(self.rules[be]["reject"]) > 1):
                    reject_composite_acl = ' '.join(f"!{acl_o.name()}" for acl_o in self.rules[be]["reject"]) 
                else:
                    reject_composite_acl = self.rules[be]["reject"][0].name()

            if self.rules[be]["accept"]:
                for acl_o in self.rules[be]["accept"]:
                    if not reject_composite_acl:
                        be_rules_l.append(f"{be_rule_line_prefix} {acl_o.name()}".rstrip())
                    else:
                        be_rules_l.append(f"{be_rule_line_prefix} {acl_o.name()} {reject_composite_acl}".rstrip())
            else:
                be_rules_l.append(f"{be_rule_line_prefix} {reject_composite_acl}".rstrip())

        fe_body = '\n'.join(["#    ------ Frontend -----",  declaration,
                             "#    -------- ACLs -------", *acl_definitions_l,
                                                           *be_rules_l])

        if self.mode == "http":
            fe_body  += "\n    default_backend " + Frontend.reject_backend

        return fe_body

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
        pass
        #print(f"Error: multiple registraton of frontend '{service_key}'")

    return frontends[service_key]   

def register_backend (be_o):
    be_name = be_o.name()
    print(f"Register backend {be_name}")
    if (be_name not in backends):
        backends[be_name] = be_o
        return be_o
    else:
        logging.info(f"backend {be_name} already registered")
        return backends[be_name]


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
                line_s = line.strip().upper().split()
                if line_s:
                    rogue_codes = [ACL(code) for code in line_s]
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
            logging.warning(f"Service for port {row['Port']} and target IP {target_ip} disabled")
            continue

        svc_type = str(row['Service Type']).strip().lower()
        raw_sni  = row['SNI']
        if not pd.isna(raw_sni):
            sni  = str(raw_sni).strip()
        else:
            sni  = ''

        port = int(row['Port'])
        fe   = Frontend(port,svc_type)

        print(f"registering frontend {fe.name()}")

        fe = register_frontend(fe)

        # register backend 

        mode = 'http' if svc_type == 'http' else 'tcp'
        print(f" -> {idx}: {svc_type} - {port} - {target_ip}")

        if mode == 'http' and port == 80 and target_ip.upper() == 'REDIRECT443':
            if not sni:
                logging.error(f"Inconsistent rule: REDIR443 directive requires a SNI definition {idx}")
                sys.exit(1)
            else:
                logging.info(f"Register REDIR443 directive for sni '{sni}' {idx}")

            be  = register_backend(NullBackend(idx,sni))
            acl = Redir(sni,mode)
            fe.register_acl(be,"sni",acl)
        else:
            be  = register_backend(Backend(idx,mode,target_ip,target_port))
            accept_list = [x.upper() for x in parse_list_field(row.get('Accept',''))]
            reject_list = [x.upper() for x in parse_list_field(row.get('Reject',''))]

            # Accept/Reject logic

            print(f"registering acl for service '{fe.name()}' -> '{be.name()}'")
            
            if sni:
                acl = SNI(sni,mode)
                fe.register_acl(be,"sni",acl)

            if not accept_list and not reject_list:
                logging.warning(f"Undefined rules for service {idx}")
                continue
            elif (len(accept_list) == 1) and (accept_list[0].upper() == "ALL") and \
                 (len(reject_list) == 1) and (reject_list[0].upper() == "ALL"):
                logging.error(f"Inconsistent rules definition for service {idx}")
                sys.exit(1)
            elif (len(accept_list) == 1) and (accept_list[0].upper() == "ROGUE"):
                logging.warning(f"Invalid rules definition: accepting rogue countries in service {idx}")
                continue

            for val in accept_list:
                acl = ACL(val,mode)
                fe.register_acl(be,"accept",acl)

            for val in reject_list:
                if (val.upper() == "ROGUE"):
                    for rcacl in rogue_codes:
                        fe.register_acl(be,"reject",rcacl)
                else:
                    acl = ACL(val,mode)
                    fe.register_acl(be,"reject",acl)



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

        fout.write("\n##### Catch-all backend ########\n")
        fout.write("\n".join(["backend bk_reject_all","    mode http","    http-request deny"]))

        now = datetime.datetime.now()
        formatted_datetime = now.strftime("%Y-%m-%d %H:%M:%S")

        fout.write(f"\n\n##### Configuration file generated at {formatted_datetime} ####\n\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)

