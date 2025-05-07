class Backend:
    def __init__(self,idx,bkname,mode,target_ip,target_port):
        self.idx          = idx
        self.backend_name = bkname
        self.mode         = mode
        self.target_ip    = target_ip
        self.target_port  = target_port

    def name(self):
        return self.backend_name

    def __str__(self):
        return '\n'.join([f"backend    {self.backend_name}",
                          f"    mode   {self.mode}",
                          f"    server srv{self.idx} {self.target_ip}:{self.target_port} check"])
