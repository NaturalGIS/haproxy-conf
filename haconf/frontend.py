#
#
#
from haconf import Backend

class Frontend:
    def __init__(self,fename,port,mode):
        self.acl    = dict()
        self.name   = fename
        self.port   = port
        self.mode   = mode
        self.acls   = dict()

    def register_acl(self,backend,acl):
        be_name=backend.name()
        if be_name not in self.acls:
            self.acls[be_name] = list()

        self.acls[be_name].append(acl)

    def __str__(self):
        declaration='\n'.join([f"\nfrontend {self.name}",
                               f"    bind *:{self.port}",
                               f"    mode {self.mode}\n"])

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
            acl_defs = []
            for acl_o in acls:
                print(f"{acl_o.name()} ---> {acl_o}")
                acl_defs.append(str(acl_o))
                acl_names.append(acl_o.name())
            print(f"acl_names {acl_names}")
            acl_names_txt = ' or '.join(acl_names)
            acl_defs.append(f"    use backend {be} if {acl_names_txt}")
            be_acls_l.append('\n'.join(acl_defs))

        return '\n'.join([declaration, *be_acls_l])

