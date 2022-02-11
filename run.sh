#!/bin/bash
# simple script to launch a local bin as a "remote" service for ctf 
# just use it as ./run.sh ./myctfbin and connect to 127.0.0.1:2323
socat TCP-LISTEN:2323,reuseaddr,fork EXEC:$1
