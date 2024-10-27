#!/usr/bin/env python

import ipaddress

import cli
from tabulate import tabulate

import db

def add_sourcenetwork(ip_range, name):
    fmt_iprange = ""
    try:
        fmt_iprange = format(ipaddress.ip_network(ip_range))
    except ValueError:
        cli.success(f"[!] The provided IP range string is not a valid network representation!")

    sourcenetwork = db.SqlHandler.SourceNetwork(
        name=name,
        ip_range=fmt_iprange
    )

    db.sqlhandler.insert(sourcenetwork)

    cli.print_success(f"[+] SourceNetwork \"{name}\" with value {fmt_iprange} added correctly!")

def rm_sourcenetwork(snid):
    if not snid:
        cli.print_error("[!] Error: SourceNetwork ID is required.")
        return
    
    with db.sqlhandler.Session() as sess:
        sourcenetwork = sess.query(db.SqlHandler.SourceNetwork).get(snid)
        if not sourcenetwork:
            cli.print_error(f"No SourceNetwork with this identifier.")
            return

        _tabulate_sourcenetworks([sourcenetwork])

        cli.print_warn("Are you sure you want to remove this SourceNetwork? [N/y] ")
        choice = input()
        if choice != "y":
            return
          
        sess.delete(sourcenetwork)
        sess.commit()
        cli.print_success(f"SourceNetwork successfully removed from DB. [ID: {snid}]")


def list_sourcenetworks(filter=None):
    with db.sqlhandler.Session() as sess:
        sourcenetworks = sess.query(db.SqlHandler.SourceNetwork).order_by(db.SqlHandler.SourceNetwork.ip_range)
        _tabulate_sourcenetworks(sourcenetworks)

def _tabulate_sourcenetworks(sourcenetworks):
    headers = ["ID", "Name", "IP range"]
    data = [ [sourcenetwork.id, sourcenetwork.name, sourcenetwork.ip_range] for sourcenetwork in sourcenetworks ]
    cli.repl.print(tabulate(data, headers=headers, tablefmt='grid'))