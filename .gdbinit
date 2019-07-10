##set follow-fork-mode child
#source ~/peda/peda.py
#source ~/Pwngdb/pwngdb.py
#source ~/Pwngdb/angelheap/gdbinit.py
#
#define hook-run
#python
#import angelheap
#angelheap.init_angelheap()
#end
#end

#source /home/vignesh/Documents/binary/tools/gdbida/gdb_ida_bridge_client.py

define setup
	b mm_free
	r -f short1-bal.rep
end

define v
	#x/32xw 0xf69f5000
	x/36xg
	x/4xg
	x/4xg
	x/94xg
	x/32xg
        x/94xg
        x/32xg
        x/94xg
        x/32xg

end

define debug
	while(1)
		if $req == 1331
			b mm_malloc
			break
		end
	end
end

define s
	v
	x/8xw
	x/96wx
	x/204wx
	x/260wx
end

define ns
	set follow-fork-mode parent
	set detach-on-fork on
end

#set follow-fork-mode child

source /home/vignesh/.gdbinit-gef.py
gef config context.layout "legend regs code stack args source -threads -trace extra memory"
gef config pcustom.struct_path ~/gef/structs
alias -a dt = pcustom
def cus
	gef config context.layout "regs code args"
	gef config context.ignore_registers "$cs $ds $gs $ss $es $fs $eflags"
end
source ~/gef/new.py
source ~/gef/code.py
source ~/gef/heapm.py
source ~/gef/libc.py
source ~/gef/parse.py
source ~/gef/graph.py
source ~/gef/aap.py
source ~/gef/rename.py
source ~/gef/find.py
source ~/gef/callgraph.py
#add-auto-load-safe-path /home/vignesh/Documents/ctf/34c3/33c3/feuerfuchs/down/firefox-50.1.0/js/src/build_DBG.OBJ/dist/bin/js-gdb.py
#set detach-on-fork on
#source /home/vignesh/Documents/ctf/confidence/p4fmt/files/pwndbg/gdbinit.py 

