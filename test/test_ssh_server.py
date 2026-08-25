#!/usr/bin/env python3
"""Minimal SSH server for e2e testing (password auth: testuser/testpass).

Simulates nvidia-smi output, system info, and a real filesystem root for SFTP.
"""
import os
import re
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time

import paramiko
from paramiko.sftp import SFTP_OK, SFTP_FAILURE

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
ROOT = tempfile.mkdtemp(prefix="sshtest_")
os.mkdir(os.path.join(ROOT, "home"))
os.mkdir(os.path.join(ROOT, "var"))
with open(os.path.join(ROOT, "hello.txt"), "w") as f:
    f.write("hello from mock server\n")
# The user's home dir, as a normal subdir of the SFTP root (mirrors a real
# server where SFTP root is / and $HOME is /home/<user>).
HOME = os.path.join(ROOT, "home", "testuser")
os.makedirs(HOME, exist_ok=True)

print(f"ROOT={ROOT}", flush=True)

try:
    HOST_KEY = paramiko.Ed25519Key.generate()
except Exception:
    HOST_KEY = paramiko.RSAKey.generate(2048)


def apply_attr(path, attr):
    """Apply an SFTPAttributes object to a local file (paramiko >= 5 removed
    SFTPServerInterface._set_file_attr)."""
    mode = getattr(attr, "st_mode", None)
    if mode is not None:
        os.chmod(path, stat.S_IMODE(mode))
    atime = getattr(attr, "st_atime", None)
    mtime = getattr(attr, "st_mtime", None)
    if atime is not None and mtime is not None:
        os.utime(path, (atime, mtime))


def handle_exec(channel, command):
    print(f"EXEC: {command!r}", flush=True)
    cmd = command.decode()
    out = b""
    code = 0
    # Give the transport a moment to finish opening the channel before we
    # reply, avoiding a paramiko 5.0 response-ordering race.
    time.sleep(0.05)
    try:
        if cmd.startswith("command -v nvidia-smi"):
            out = b"/usr/bin/nvidia-smi\n"
        elif cmd.strip() == "echo $HOME":
            out = (HOME + "\n").encode()
        elif cmd.startswith("readlink -f "):
            # Extract the quoted path from: readlink -f -- '<path>'
            m = re.search(r"readlink -f -- '([^']*)'", cmd)
            target = m.group(1) if m else ""
            # Map the (possibly absolute) path into the mock root and
            # canonicalize, so the result stays inside the SFTP root.
            if target.startswith(ROOT):
                real = os.path.normpath(target)
            else:
                real = os.path.normpath(os.path.join(ROOT, target.lstrip("/")))
            out = (real + "\n").encode()
        elif cmd.startswith("nvidia-smi --query-gpu="):
            out = (
                "0, NVIDIA A100-SXM4-80GB, 550.54.15, 73, 41, 40960, 81920, 58, 250.5, 400.0\n"
                "1, NVIDIA A100-SXM4-80GB, 550.54.15, 12, 8, 10240, 81920, 44, 80.2, 400.0\n"
            ).encode()
        elif cmd.startswith("nvidia-smi --query-compute-apps="):
            out = b"1234, python, 40952\n"
        elif "===LOAD===" in cmd:
            out = (
                b"===LOAD===\n0.52 0.74 0.91\n"
                b"===CPU===\n64\n"
                b"===MEM===\n512000 204800 307200\n"
                b"===DISK===\n1024000M 512000M 50%\n"
                b"===OS===\nUbuntu 22.04.4 LTS\n"
                b"===UPTIME===\n90061\n"
                b"===HOSTNAME===\nmock-gpu-node\n"
            )
        elif cmd.startswith("ps -o pid=,user= -p"):
            out = b"1234 admin\n"
        elif cmd.startswith("ps -o pid=,args= -p"):
            out = b"1234 python /root/projects/train.py --epochs 10 --batch-size 32\n"
        elif cmd.startswith("rm -rf"):
            m = re.search(r"rm -rf -- '([^']+)'", cmd)
            if m:
                target = os.path.normpath(os.path.join(ROOT, m.group(1).lstrip("/")))
                if not target.startswith(ROOT):
                    code = 1
                else:
                    if os.path.isdir(target):
                        shutil.rmtree(target, ignore_errors=True)
                    elif os.path.exists(target):
                        os.remove(target)
            out = b""
        else:
            out = (b"mock-exec: " + cmd.encode()[:200] + b"\n")
    except Exception as e:
        out = str(e).encode()
        code = 1
    channel.sendall(out)
    channel.send_exit_status(code)
    channel.close()


def handle_shell(channel):
    try:
        while True:
            data = channel.recv(1024)
            if not data:
                break
            channel.sendall(b"\r\nmock-shell echo: " + data)
    except Exception:
        pass
    finally:
        channel.close()


class SFTPHandle(paramiko.SFTPHandle):
    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.file.fileno()))
        except OSError:
            return SFTP_FAILURE

    def chattr(self, attr):
        try:
            apply_attr(self.requested_name, attr)
        except OSError:
            return SFTP_FAILURE
        return SFTP_OK


class SFTPServer(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = ROOT

    def _realpath(self, path):
        # Map the (possibly absolute) path into the mock root, then guard
        # against escaping it.
        if path.startswith(self.root):
            p = os.path.normpath(path)
        else:
            p = os.path.normpath(os.path.join(self.root, path.lstrip("/")))
        if not (p == self.root or p.startswith(self.root + os.sep)):
            raise paramiko.SFTPException("path escape")
        return p

    def list_folder(self, path):
        p = self._realpath(path)
        out = []
        for name in os.listdir(p):
            attr = paramiko.SFTPAttributes.from_stat(os.lstat(os.path.join(p, name)))
            attr.filename = name
            out.append(attr)
        return out

    def stat(self, path):
        return paramiko.SFTPAttributes.from_stat(os.stat(self._realpath(path)))

    def lstat(self, path):
        return paramiko.SFTPAttributes.from_stat(os.lstat(self._realpath(path)))

    def chattr(self, path, attr):
        # Path-based setattr (CMD_SETSTAT); ssh2 falls back here if fchmod fails.
        try:
            apply_attr(self._realpath(path), attr)
        except OSError:
            return SFTP_FAILURE
        return SFTP_OK

    def open(self, path, flags, attr):
        p = self._realpath(path)
        try:
            mode = getattr(attr, "st_mode", None) or 0o644
            f = os.open(p, flags, mode)
        except OSError:
            return SFTP_FAILURE
        if flags & os.O_WRONLY:
            fstr = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            fstr = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            fstr = "rb"
        h = SFTPHandle(flags)
        h.requested_name = p
        fobj = os.fdopen(f, fstr)
        h.file = fobj
        h.fileobj = fobj
        # paramiko >= 5: default read()/write() look for these attributes
        h.readfile = fobj
        h.writefile = fobj
        return h

    def remove(self, path):
        try:
            os.remove(self._realpath(path))
        except OSError as e:
            return SFTP_FAILURE
        return SFTP_OK

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._realpath(path))
        except OSError:
            return SFTP_FAILURE
        return SFTP_OK

    def rmdir(self, path):
        try:
            os.rmdir(self._realpath(path))
        except OSError:
            return SFTP_FAILURE
        return SFTP_OK

    def rename(self, oldpath, newpath):
        try:
            os.rename(self._realpath(oldpath), self._realpath(newpath))
        except OSError:
            return SFTP_FAILURE
        return SFTP_OK


class MyServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        print(f"AUTH {username}", flush=True)
        if username == "testuser" and password == "testpass":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        print(f"CHANNEL_REQ {kind}", flush=True)
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *a):
        print(f"PTY_REQ", flush=True)
        return True

    def check_channel_exec_request(self, channel, command):
        print(f"EXEC_REQ {command!r}", flush=True)
        threading.Thread(target=handle_exec, args=(channel, command), daemon=True).start()
        return True

    def check_channel_shell_request(self, channel):
        print(f"SHELL_REQ", flush=True)
        threading.Thread(target=handle_shell, args=(channel,), daemon=True).start()
        return True




def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", PORT))
    sock.listen(16)
    print(f"mock sshd listening on 127.0.0.1:{PORT}", flush=True)
    while True:
        client, _ = sock.accept()
        t = threading.Thread(target=serve_client, args=(client,), daemon=True)
        t.start()


def serve_client(client):
    try:
        t = paramiko.Transport(client)
        t.add_server_key(HOST_KEY)
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, SFTPServer)
        server = MyServer()
        t.start_server(server=server)
        # paramiko 5.0 uses WeakValueDictionary for channels:
        # the app MUST keep strong references to accepted channels,
        # or they get GC'd and their requests are silently dropped.
        channels = []
        while t.is_active():
            ch = t.accept()
            if ch is None:
                break
            channels.append(ch)
    except Exception as e:
        print(f"client error: {e}", flush=True)
    finally:
        try:
            client.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
