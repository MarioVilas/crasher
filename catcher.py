from sys import argv, exit
from pydbg import *
from pydbg.defines import *

from time import sleep

from threading import Timer

#
# Global definitions
#
METHOD_ATTACH   = 0 # default method
METHOD_LOAD     = 1

g_dbg = pydbg()

#
# Name: handler_run_timeout()
#
def handler_run_timeout():
    g_dbg.terminate_process()

#
# Name: get_process_information
#
def get_process_information(dbg, dumpContext = True, dumpInstructions = True):

    # print offending thread context
    print   'ThreadID=0x%04X\n' \
                'eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n' \
                'eip=%08x esp=%08x ebp=%08x\n' % \
                (dbg.h_thread, \
                 dbg.context.Eax, dbg.context.Ebx, dbg.context.Ecx,
dbg.context.Edx, dbg.context.Esi, dbg.context.Edi, \
                 dbg.context.Eip, dbg.context.Esp, dbg.context.Ebp)

    # dump context information + smart guess
    if dumpContext:
        print dbg.dump_context ()

    # disasembly around the offending instruction
    if dumpInstructions:
        instructions = dbg.disasm_around(dbg.context.Eip, 5)
        pos = -5
        for instruction in instructions:
            print '%2d %08X> %s' % (pos, instruction[0], instruction[1])
            pos += 1

#
# Name: handler_breakpoint()
#
def handler_breakpoint(dbg):
    if dbg.first_breakpoint:
        return DBG_CONTINUE

    print ('\nBREAKPOINT')
    get_process_information(dbg)
    return DBG_EXCEPTION_NOT_HANDLED
##    return DBG_CONTINUE


#
# Name: handler_access_violation
#
def handler_access_violation(dbg):
    print '\nACCESS VIOLATION'
    get_process_information(dbg)#, 0, True, True)
    return DBG_EXCEPTION_NOT_HANDLED
##    return DBG_CONTINUE

#
# Name: find_process_pid_by_name
#
def find_process_pid_by_name(dbg, name):
    for (pid, proc_name) in dbg.enumerate_processes():
        if proc_name.lower() == name.lower():
            return pid
    return -1

#
# Name: main()
#
def main(name, args, method, timeout):
    # register callback functions of our interest
    g_dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
    g_dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

    if method == METHOD_ATTACH: # attach to a running process
        pid = find_process_pid_by_name(g_dbg, name)
        if pid == -1:
            print '[-] Could not find process \'%s\'' % name
            return

        try:
            g_dbg.attach(pid)
        except pdx:
            print '[-] Failed to attach to process'
            return
    else: # create a new process instance
        try:
            g_dbg.load(name, args)
        except pdx:
            print '[-] Failed to create process'
            return

    # if debugee running timeout wasspecified, start the timer
    if timeout:
        timer = Timer(timeout, handler_run_timeout)
        timer.start()

    # start process debugging
    try:
        g_dbg.run()
    except Exception, e:
        print 'ERROR> Internal error'

    # Send cancellation message to the timer
    if timeout:
        timer.cancel()
        sleep(0.5)

#
# Name: Usage
#
def usage():
    print 'Usage: python catcher.py [-t <seconds>] [-l] <-pn process_name> [arg1] [argn]\n\n'\
      '-t: (optional) Specifies the time to wait until we terminate the process.\n' \
      '-l: (optional) Create a new the process instance instead of attaching.\n' \
      '-pn: Process name to attach. If -l was specified then prepend full path to the executable.'


if __name__ == '__main__':
    method  = METHOD_ATTACH
    timeout = 0
    process_name = None
    process_args = ''

    for i in range(1, len(argv)):
        param = argv[i]
        if param == '-pn':
            process_name = argv[i + 1]
            if len(argv) > i + 1:
                for arg in argv[ i + 2 : ]:
                    process_args += '\"' + arg + '\" '
        elif param == '-t':
            timeout = float(argv[i + 1])
        elif param == '-l':
            method = argv[i + 1]

    if not process_name:
        usage()
        exit(-1)

    main(process_name, process_args, method, timeout)
