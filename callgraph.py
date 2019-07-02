class callgraph(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "callgraph"
    _syntax_  = "{:s}".format(_cmdline_)

    # @only_if_gdb_running         # not required, ensures that the debug session is started


    def getbuf(self,addr):
        return gef_disassemble(addr,100)

    def to_int(self,val):
        """
        Convert a string to int number
        """
        try:
            return int(str(val), 16)
        except:
            return None

    def addnames(self,i):
        f=None
        f1=None
        funcs=None
        plt=None
        try:
            f=open("data.json")
            plt=json.load(f)
            # print(plt,f)
        except Exception:
            pass

        try:
            f1=open(".func.json")
            funcs=json.load(f1)
        except Exception:
            pass

        if i.mnemonic == "call" and self.to_int(i.operands[0]) is not None:
            if f is not None:
                # print(plt,f)
                op=self.to_int(i.operands[0])
                if str(op) in plt:
                    i.operands=[plt[str(op)]]
            if funcs is not None:
                op=self.to_int(i.operands[0])
                if str(op) in funcs:
                    i.operands=[hex(op)+" <"+funcs[str(op)]+">"]
        return i

    def findend(self, start):
        tails=["ret","hlt","jmp"]
        pc=start
        prev=0
        flag=True

        while(flag):
            buf=self.getbuf(pc)
            for ins in buf:
                if prev==ins.address:
                    continue
                prev=pc
                pc=ins.address
                if ins.mnemonic.startswith("call"):
                    ins=self.addnames(ins)
                    if (graph.endkeys(self,ins)):
                        return ins.address
                if ins.mnemonic.strip() in tails:
                    return ins.address

    def getedge(self,func):
        targets=[]
        cfg=graph()
        gdict=cfg.do_invoke([hex(func),"func"])
        start=min(gdict.keys())
        end=max(gdict.keys())
        end=self.findend(end)
        # print(hex(end))
        no=end-start
        buf=gef_disassemble(start,no)

        for i in buf:
            if i.mnemonic=="call":
                targets.append(int(i.operands[0].strip().split()[0],16))
            if i.address==end:
                break

        return targets

    def bfs(self,root):
        self.cgraph.addvertex(root)
        queue=[root]
        visited=[root]

        for i in queue:
            edges=self.getedge(i)
            self.cgraph.addedgelist(i,edges)
            for i in edges:
                if i in visited:
                    continue
                else:
                    visited.append(i)
                    if i in self.plt:
                        continue
                    queue.append(i)

    def getplt(self):
        import subprocess
        tmp=subprocess.Popen(["readelf","-x",".plt",get_filepath()],stdout=subprocess.PIPE).communicate()[0].decode()
        tmp=tmp.split("'.plt':")[1].strip().splitlines()

        for i in tmp:
            self.plt.append(self.base_addr+int(i.strip().split(" ")[0],16))

    def getsym(self,addr):
        base=gdb.execute("x/i "+addr,to_string=True).strip()
        idx=base.find("<")
        name=''

        if idx==-1:
            name=base[:base.find(":")]
        else:
            idx=base.find("+")
            if idx==-1:
                name=base[base.find("<"):base.find(">")]
            else:
                name=base[base.find("<"):base.find("+")]

    def handle_pie(self):
        if checksec(get_filepath())["PIE"]:
            self.base_addr=get_section_base_address(get_filepath())

    def do_invoke(self, argv):
        from graphviz import Digraph
        import subprocess

        root=int(argv[0],16)
        self.cgraph=cfg({})
        self.plt=[]
        self.base_addr=0
        self.handle_pie()
        self.getplt()
        self.bfs(root)

        dot=Digraph(node_attr={'shape': 'box'})
        self.cgraph.makegraph(dot)
        dot.render('/tmp/cgraph.gv')
        subprocess.Popen(["xdot", "/tmp/cgraph.gv"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return

register_external_command(callgraph())

class cfg:
    def __init__(self,init={}):
        self.gdict=init

    def addedgelist(self,ver,edge):
        self.gdict[ver] += list(set(edge))
        for i in edge:
            if i not in self.gdict:
                self.addvertex(i)

    def addedge(self,ver,edge):
        self.gdict[ver].append(edge)

    def addvertex(self,ver):
        if ver in self.gdict:
            return
        self.gdict[ver]=[]

    def getsym(self,addr):
        base=gdb.execute("x/i "+str(addr),to_string=True).strip()
        idx=base.find("<")
        name=''

        if idx==-1:
            name=base[:base.find(":")]
        else:
            idx1=base.find("+")
            if idx1==-1:
                name=base[idx+1:base.find(">")]
            else:
                name=base[idx+1:min(base.find(">"),base.find("+"))]

        return name

    def makegraph(self,d):
        for i in self.gdict:
            # print(self.getsym(i))
            d.node(self.getsym(i))
        for i in self.gdict:
            for j in self.gdict[i]:
                if j:
                    d.edge(self.getsym(i),self.getsym(j))
