import re
import os

class ACL:
    cidr_dir = "cidr_maps"

    def __init__(self,acl_class,acl_val,mode):
        self.acl_class = acl_class      # either 'accept' or 'reject'
        self.mode      = mode           # 'tcp' or 'http' or 'https'
        self.val       = acl_val
        self.mode      = mode
        self.definition = ''
        self.acl_name  = ''

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
            acl_name = f"acl_{self.acl_class}_sni_{safe}"
            if mode in ['https','http']:
                self.definition = f"    acl {acl_name} hdr(host) -i {self.val}"
            else:
                self.definition = f"    acl {acl_name} req.ssl_sni -i {self.val}"
        self.acl_name = acl_name

    def name(self):
        return self.acl_name

    def __str__(self):
        return self.definition
