import vtrace
import sys,time
from disassemble import *
from struct import *

class fuzzer(vtrace.Notifier):
    #logging function
    def log(self,string):
	print string[0:len(string)-1]
    
    def showRegs(self,trace):
        regs = trace.getRegisters()
        view = regs.keys()
        out=""
        for name in view:
            val = regs.get(name,None)
            if val == None:
                out += "%s:none\n" % (name)
            else: 
                out += "%s:0x%.8x\n" % (name,val)
        return out

    
    def disassemble(self,memory,eip,max=0):
        offset = 0
        databuf=""
        cont=0
	if len(memory)<1: return "error"
        while offset < len(memory):
            size = 1
            try:
                cont+=1
                if max>0:
                    if (cont>max): break
                op = Opcode(memory[offset:])
                instrbuf = op.printOpcode("INTEL")+"\n"
                size = op.getSize()
            except:
                instrbuf = "<invalid>\n"
            addrbuf = "%.8x " % (eip+offset)
            bytes = memory[offset:offset+size]
            bytes = unpack("B"*len(bytes), bytes)
            charbuf=""
            for byte in bytes:
                charbuf += "%.2x " % byte
            charbuf += "  "
            offset += size
            databuf+=addrbuf+"\t"+charbuf+"\t"+instrbuf
        return databuf
        
        
    # signal handler
    def handleEvent(self, event, trace):
    	signal = ['0','SIGHUP','SIGINT','SIGQUIT','SIGILL','5','SIGABRT','7','SIGFPE','SIGKILL','10','SIGSEGV','12','SIGPIPE','SIGALRM','SIGTERM','SIGUSR1','SIGCHLD','SIGCONT','SIGSTOP','SIGTSTP']
        if trace.isAttached():
            if (event == vtrace.NOTIFY_SIGNAL):
                sig = trace.getMeta("PendingSignal", 0)
                str ="------------------------ Signal: %d (%s)--------------------------\n" % (sig,signal[sig])
                self.log(str)
                if sig == 11: #SEGV
                    self.log("SEGV!\n")
                self.log("### Trace:\n")
		stacktrace=trace.getStackTrace()
		for i in range(len(stacktrace)):
			self.log("IP:%08X SF: %08X\n" % stacktrace[i])
                self.log("### Registers\n")
                self.log(self.showRegs(trace))
                eip=trace.getProgramCounter()
                memory = trace.readMemory(eip,50)
                self.log("### EIP Disassemble\n")
                self.log(self.disassemble(memory,eip,20))
            trace.run()

   #Main proc
    def main(self):

	timeout=5

	self.command=''
	for i in range(1,len(sys.argv)):
	        self.command += "%s " % sys.argv[i]
	print self.command
	self.vtracer = vtrace.getTrace()
	self.vtracer.setMode("NonBlocking", True)
	self.vtracer.execute(self.command)
	self.log("Executed\n")
	if self.vtracer.isAttached():
		self.vtracer.registerNotifier(vtrace.NOTIFY_SIGNAL,self)
		self.log("Running\n")
		self.vtracer.run()
		time.sleep(timeout)
	if self.vtracer.isAttached() and self.vtracer.isRunning():
		self.log("Killing\n")
		self.vtracer.kill()
		self.vtracer.detach()

f = fuzzer()
f.main()
