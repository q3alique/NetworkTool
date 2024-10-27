#!/usr/bin/env python

import ipaddress
import re

import cli
from tabulate import tabulate

import db

def add_target(ip_range, ports, name):
    fmt_iprange = ""
    try:
        fmt_iprange = format(ipaddress.ip_network(ip_range))
    except ValueError:
        cli.print_error(f"[!] The provided IP range string is not a valid network representation!")
        return
    
    if not _validate_ports_format(ports):
        cli.print_error(f"[!] The ports must be specified as CSV with values \"<port>-tcp\" / \"<port>-udp\" / \"<port>\" (TCP will be considered if not indicated).")
        return

    target = db.SqlHandler.Target(
        name=name,
        ip_range=fmt_iprange,
        ports=ports
    )

    db.sqlhandler.insert(target)

    cli.print_success(f"[+] Target \"{name}\" with value {fmt_iprange} and ports {ports} added correctly!")

def rm_target(targetid):
    if not targetid:
        cli.print_error("[!] Error: Target ID is required.")
        return
    
    with db.sqlhandler.Session() as sess:
        target = sess.query(db.SqlHandler.Target).get(targetid)
        if not target:
            cli.print_error(f"No Target with this identifier.")
            return

        _tabulate_targets([target])

        cli.print_warn("Are you sure you want to remove this Target? [N/y] ")
        choice = input()
        if choice != "y":
            return
          
        sess.delete(target)
        sess.commit()
        cli.print_success(f"Target successfully removed from DB. [ID: {targetid}]")


def list_targets(filter=None):
    with db.sqlhandler.Session() as sess:
        targets = sess.query(db.SqlHandler.Target).order_by(db.SqlHandler.Target.ip_range)
        _tabulate_targets(targets)

def _tabulate_targets(targets):
    headers = ["ID", "Name", "IP range", "Ports"]
    data = [ [target.id, target.name, target.ip_range, target.ports] for target in targets ]
    if len(data) > 0:
        cli.repl.print(tabulate(data, headers=headers, tablefmt='grid'))

def _validate_ports_format(csv_string):
    # Format must be a CSV that contains values like "<integer>[-<integer>][-tcp|-udp]"
    pattern = r"^(\d+(-\d+)?(-tcp|-udp)?)(,\d+(-\d+)?(-tcp|-udp)?)*$"
    return bool(re.match(pattern, csv_string))