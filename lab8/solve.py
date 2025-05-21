#!/usr/bin/env python3
import angr
import claripy
import sys

def main():
    # 1) load the challenge binary
    proj = angr.Project('./chal', auto_load_libs=False)

    # 2) create 8 symbolic bytes plus a trailing newline (fgets strips it)
    flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(8)]
    sym_input = claripy.Concat(*flag_chars, claripy.BVV(b'\n'))

    # 3) set up the initial state with our symbolic stdin
    state = proj.factory.entry_state(stdin=sym_input)

    # 4) explore until we hit the “Correct!” branch (and avoid wrong key)
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(
        find=lambda s: b"Correct! The flag is:" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key!"           in s.posix.dumps(1)
    )

    # 5) extract and print the concrete 8-byte key
    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(claripy.Concat(*flag_chars), cast_to=bytes)
        # write exactly the 8-byte key (no extra newline)
        sys.stdout.buffer.write(solution)
    else:
        sys.exit("[-] No solution found.")

if __name__ == '__main__':
    main()
