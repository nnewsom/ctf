#!/usr/bin/env python3

import logging
import subprocess
import select
import shlex
import fcntl
import tty
import pty
import sys
import socket
import struct
import itertools
import threading
import os

def p64( i, endian="little"):
    r = b""
    if endian == "big":
        try:
            r = struct.pack('>q', i )
        except struct.error:
            r = struct.pack('>Q', i )
    else:
        try:
            r = struct.pack('<q', i)
        except struct.error:
            r = struct.pack('<Q', i)
    return r

def p32( i, endian="little"):
    r = b""
    if endian == "big":
        try:
            r = struct.pack('>l', i )
        except struct.error:
            r = struct.pack('>l', i )
    else:
        try:
            r = struct.pack('<l', i)
        except struct.error:
            r = struct.pack('<l', i)
    return r

def p16( i, endian="little"):
    r = b""
    if endian == "big":
        try:
            r = struct.pack('>h', i )
        except struct.error:
            r = struct.pack('>H', i )
    else:
        try:
            r = struct.pack('<h', i)
        except struct.error:
            r = struct.pack('<H', i)
    return r

def u64_wrap_around( x, y ):
    return (( 0xffffffffffffffff - x ) + y ) & 0xffffffffffffffff


class PTY(object):
    pass

PTY = PTY()
PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT

class CtfException(Exception):
    pass

class ProcHandler(object):
    def __init__(self, 
                cmd,
                stdin  = PIPE,
                stdout = PTY,
                stderr = STDOUT,
                env = None,
                cwd = None,
                shell = False,
                raw = True
             ):

        handles = ( stdin, stdout, stderr )

        self.pty = handles.index(PTY) if PTY in handles else None
        self.raw_pty = raw
        self.env = env if env else os.environ
        self.pid = 5555
        self.buffer = bytes()

        if stderr is STDOUT:
            stderr = stdout

        # create PTY
        stdin, stdout, stderr, master, slave = self.__init_handles( stdin, stdout, stderr )

        self.proc = subprocess.Popen(
                    shlex.split( cmd ),
                    stdin = stdin,
                    stdout = stdout,
                    stderr = stderr,
                    env = self.env,
                    cwd = cwd,
                )
        self.pid = self.proc.pid

        if self.pty:
            if stdin is slave:
                self.proc.stdin = os.fdopen( os.dup( mater ), 'r+b', 0)
            if stdout is slave:
                self.proc.stdout = os.fdopen( os.dup( master ), 'r+b', 0)
            if stderr is slave:
                self.proc.stderr = os.fdopen( os.dup( master ), 'r+b', 0)
            os.close( master )
            os.close( slave )

        # no block
        if self.proc.stdout:
            fd = self.proc.stdout.fileno()
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def __init_handles( self, stdin, stdout, stderr ):
        master = slave = None
        if self.pty:
            master , slave  = pty.openpty()
            if self.raw_pty:
                tty.setraw( master )
                tty.setraw( slave )

            if stdin is PTY:
                stdin = slave
            if stdout is PTY:
                stdout = slave
            if stderr is PTY:
                stderr = slave

        return stdin, stdout, stderr, master , slave

    def __send(self, data , timeout= 5):
        ready = select.select( [], [ self.proc.stdin ], [], timeout )
        if ready[1]:
            self.proc.stdin.write( data )
            self.proc.stdin.flush()
        else:
            raise CtfException("failed to tx data")

    def __recv(self, n, timeout = 5 ):
        r = self.buffer
        ready = select.select( [ self.proc.stdout ], [], [], timeout )
        if ready[0]:
            if n:
                n = n - len(r)
                if n >= 0:
                    r += self.proc.stdout.read(n) 
            else:
                r += self.proc.stdout.read() 
            if len(r):
                if len(self.buffer):
                    self.buffer = bytes()
                return r
        raise CtfException("failed to rx data")

    def send( self, data, timeout =5):
        self.__send( data, timeout)

    def sendline( self, data, timeout = 5):
        if not data.endswith(b'\n'):
            data += b'\n'
        self.__send( data )

    def recv( self, n=0, timeout =5):
        r = self.__recv( n, timeout=5 )
        return r

    def recv_until( self, until, timeout=5 ):
        r = b""
        idx = -1
        count = 0
        while idx == -1 and count < timeout:
            r += self.__recv( 0 )
            idx = r.rfind( until )
            count +=1

        if count == timeout:
            raise CtfException("failed to rx data until keyword")

        offset = idx + len(until)
        self.buffer = r[ offset : ]
        r = r[:offset]

        return r

    def interact( self ):
        go = threading.Event()
        def recv_thread():
            while not go.isSet():
                try:
                    cur = self.recv()
                    if cur:
                        _stdout = getattr( sys.stdout, "buffer", sys.stdout)
                        _stdout.write( cur )
                        _stdout.flush()
                except Exception as e:
                    break

        t = threading.Thread( target = recv_thread )
        t.daemon = True
        t.start()

        try:
            while not go.isSet():
                _stdin = getattr( sys.stdin, "buffer", sys.stdin )
                data = _stdin.read(1)
                if data:
                    try:
                        self.send(data)
                    except Exception as e:
                        go.set()
                else:
                    go.set()
        except KeyboardInterrupt:
            go.set()

        while t.is_alive():
            t.join( timeout = 0.1)

    @property
    def libs(self):
        maps_raw = open('/proc/%d/maps' % self.pid).read()
        maps = {}
        for line in maps_raw.splitlines():
            if "/" not in line:
                continue

            path = line [ line.index('/'): ]
            addr_range, perms = line.split(' ')[0:2]
            start, end = addr_range.split('-')
            start = int(start, 16)
            end = int(end, 16)
            if path not in maps:
                maps[path] = []
            maps[ path ].append( (start, end, perms ))
        return maps


class TcpSocketHandler(object):
    def __init__(self, host, port, timeout = 5 ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.socket.connect( (host, port ) )
        print("connected to TCP:{h}:{p}".format(h = host, p = port))

        self.buffer = bytes()

    def __send(self, data):
        ready = select.select( [], [ self.socket ], [], self.timeout )
        if ready[1]:
            self.socket.send( data )
        else:
            raise CtfException("failed to tx data")

    def __recv(self, n ):
        r = self.buffer
        ready = select.select( [ self.socket ], [], [], self.timeout )
        if ready[0]:
            n = n - len(r)
            if n >= 0:
                r += self.socket.recv(n) 
            if len(r) and len(self.buffer):
                self.buffer = bytes()

            else:
                return r

        raise CtfException("failed to rx data")

    def send( self, data ):
        self.__send( data )

    def sendline( self, data ):
        if not data.endswith(b'\n'):
            data += b'\n'
        self.__send( data )

    def recv( self, n=4096 ):
        r = self.__recv( n )
        return r

    def recv_until_either( self, keywords , tries = 3):
        r = b""
        idx = -1
        count = 0
        kw_len = 0
        while idx == -1 and count < tries:
            r += self.__recv( 4096 )
            for kw in keywords:
                idx = r.rfind( kw )
                if idx != -1:
                    kw_len = len(kw)
                    break
            count +=1

        if count == tries:
            raise CtfException("failed to rx data until keyword")

        offset = idx + kw_len
        self.buffer = r[ offset : ]
        r = r[:offset]

        return r

    def recv_until( self, until, tries = 3):
        r = b""
        idx = -1
        count = 0
        while idx == -1 and count < tries:
            r += self.__recv( 4096 )
            idx = r.rfind( until )
            count +=1

        if count == tries:
            raise CtfException("failed to rx data until keyword")

        offset = idx + len(until)
        self.buffer = r[ offset : ]
        r = r[:offset]

        return r

    def interact( self ):
        go = threading.Event()
        def recv_thread():
            while not go.isSet():
                try:
                    cur = self.recv()
                    if cur:
                        _stdout = getattr( sys.stdout, "buffer", sys.stdout)
                        _stdout.write( cur )
                        _stdout.flush()
                except Exception as e:
                    break

        t = threading.Thread( target = recv_thread )
        t.daemon = True
        t.start()

        try:
            while not go.isSet():
                _stdin = getattr( sys.stdin, "buffer", sys.stdin )
                data = _stdin.read(1)
                if data:
                    try:
                        self.send(data)
                    except Exception as e:
                        go.set()
                else:
                    go.set()
        except KeyboardInterrupt:
            go.set()

        while t.is_alive():
            t.join( timeout = 0.1)

def de_bruijn(alphabet, n):
    k = len(alphabet)
    a = [0] * k * n

    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c

    return db(1, 1)

def pybytes(x):
    return bytes(str(x), encoding="utf-8")

def generate_cyclic_pattern(length, cycle=8):
    charset = bytearray(b"abcdefghijklmnopqrstuvwxyz")
    return bytearray(itertools.islice(de_bruijn(charset, cycle), length))

def search_pattern( pattern, size, cycle=8 ):
    pattern_be = bytes(pattern, encoding="utf-8")
    pattern_le = bytes(pattern[::-1], encoding="utf-8")

    cyclic_pattern = generate_cyclic_pattern(size, cycle)
    found = False
    off = cyclic_pattern.find(pattern_le)
    if off >= 0:
        print("Found at offset {:d} (little-endian search) ".format(off ))
        found = True

    off = cyclic_pattern.find(pattern_be)
    if off >= 0:
        found = True
        print("Found at offset {:d} (big-endian search) ".format(off ))

    if not found:
        print("Pattern '{}' not found".format(pattern))
