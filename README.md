# ctf
capture the flag type stuff

## ctf.py
little python file I wrote to handle comms to/from local or remote targets with some utility functions. 

I didn't like how much extra stuff pwntools does that cannot be disabled; so I wrote this minimalistic replacement to have more control over what is happening.

## run.sh
this script is a quick way to run a local ctf binary as a "remote" service listening on TCP:127.0.0.1:2323. That way the attack script being dev'd can simply be switched to target remote service onced finished. Also a plus to be able attach GDB
