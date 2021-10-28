#!/usr/bin/env python3

#
# A more complete FTP protocol fuzzer to look for bugs.
#

from boofuzz import *


def entry_point(prc_path=["C:\ftp\ftp.exe"],
                prc_addr="127.0.0.1", prc_port=26002,
                ftp_addr="127.0.0.1", ftp_port=21):

    procmon = ProcessMonitor(prc_addr, prc_port)
    procmon.set_options(start_commands=[prc_path])

    session = Session(
        target=Target(
            connection=TCPSocketConnection(ftp_addr, ftp_port),
            monitors=[procmon],
            ),
        sleep_time=0.5
    )

    define_proto(session=session)

    session.fuzz()


def define_proto(session):
    user = Request("user", children=(
        String(name="key", default_value="USER"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="anonymous"),
        Static(name="end", default_value="\r\n"),
    ))

    passw = Request("pass", children=(
        String(name="key", default_value="PASS"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="james"),
        Static(name="end", default_value="\r\n"),
    ))

    stor = Request("stor", children=(
        String(name="key", default_value="STOR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    retr = Request("retr", children=(
        String(name="key", default_value="RETR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    rnfr = Request("rnfr", children=(
        String(name="key", default_value="RNFR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="test_old.txt"),
        Static(name="end", default_value="\r\n")
    ))

    rnto = Request("rnto", children=(
        String(name="key", default_value="RNTO"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="test_new.txt"),
        Static(name="end", default_value="\r\n")
    ))

    size = Request("size", children=(
        String(name="key", default_value="SIZE"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="test_old.txt"),
        Static(name="end", default_value="\r\n")
    ))

    stat = Request("stat", children=(
        String(name="key", default_value="STAT"),
        Delim(name="space", default_value=" "),

        Static(name="end", default_value="\r\n")
    ))

    nlst = Request("nlst", children=(
        String(name="key", default_value="NLST"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="/"),
        Static(name="end", default_value="\r\n")
    ))

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)
    session.connect(passw, rnfr)
    session.connect(passw, size)
    session.connect(passw, nlst)
    session.connect(rnfr, rnto)


if __name__ == "__main__":
    entry_point()
