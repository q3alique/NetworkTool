#!/usr/bin/env python

import ipaddress
import re

import cli
from tabulate import tabulate

import db

def rm_rule(ruleid):
    if not ruleid:
        cli.print_error("[!] Error: Rule ID is required.")
        return
    
    with db.sqlhandler.Session() as sess:
        rule = sess.query(db.SqlHandler.Rule).get(ruleid)
        if not rule:
            cli.print_error(f"No Rule with this identifier.")
            return

        _tabulate_rules([rule])

        cli.print_warn("Are you sure you want to remove this Rule? [N/y] ")
        choice = input()
        if choice != "y":
            return
          
        sess.delete(rule)
        sess.commit()
        cli.print_success(f"[+] Rule successfully removed from DB. [ID: {ruleid}]")


def list_rules(filter=None):
    with db.sqlhandler.Session() as sess:
        if filter == "hidden":
            rules = sess.query(db.SqlHandler.Rule).filter(db.SqlHandler.Rule.hidden == True).order_by(db.SqlHandler.Rule.id).all()
        elif filter == "all":
            rules = sess.query(db.SqlHandler.Rule).order_by(db.SqlHandler.Rule.id).all()
        elif filter and re.match(r'^(?:[1-9]\d*|[1-9]\d*-[1-9]\d*)(,(?:[1-9]\d*|[1-9]\d*-[1-9]\d*))*$', filter): # Comma-separated positive integers and ranges
            ids = []
            for id_range in filter.split(","):
                if "-" in id_range:
                    start, end = map(int, id_range.split('-'))
                    ids.extend(range(start, end + 1))
                else:
                    ids.append(id_range)
            rules = sess.query(db.SqlHandler.Rule).filter(db.SqlHandler.Rule.id.in_(ids)).order_by(db.SqlHandler.Rule.id).all()
        else:
            rules = sess.query(db.SqlHandler.Rule).filter(db.SqlHandler.Rule.hidden == False).order_by(db.SqlHandler.Rule.id).all()
        _tabulate_rules(rules)

def show_rule(ruleid):
    if not ruleid:
        cli.print_error("[!] Error: Rule ID is required.")
        return

    with db.sqlhandler.Session() as sess:
        rule = sess.query(db.SqlHandler.Rule).get(ruleid)
        if not rule:
            cli.print_error(f"[!] Error: No Rule with this identifier.")
            return
        
        _tabulate_rules([rule])

        detailed_info = [
            ["Expanded SRC Addresses", rule.src_addr_text],
            ["Expanded DST Addresses", rule.dst_addr_text],
            ["Expanded Service Ports", rule.service_text]
        ]

        for item in detailed_info:
            cli.print(item[0])
            cli.print("=" * len(item[0]))
            _pretty_print_nested_structure(item[1])

def hide_rule(ruleid):
    if not ruleid:
        cli.print_error("[!] Error: Rule ID is required.")
        return

    with db.sqlhandler.Session() as sess:
        rule = sess.query(db.SqlHandler.Rule).get(ruleid)
        if not rule:
            cli.print_error(f"[!] Error: No Rule with this identifier.")
            return
        
        if not rule.hidden:
            rule.hidden = True
            sess.commit()
            cli.print_success(f"[+] Rule {ruleid} hidden.")
        else:
            cli.print_warn(f"[!] This rule was already hidden.")

def unhide_rule(ruleid):
    if not ruleid:
        cli.print_error("[!] Error: Rule ID is required.")
        return

    with db.sqlhandler.Session() as sess:
        rule = sess.query(db.SqlHandler.Rule).get(ruleid)
        if not rule:
            cli.print_error(f"[!] Error: No Rule with this identifier.")
            return
        
        if rule.hidden:
            rule.hidden = False
            sess.commit()
            cli.print_success(f"[+] Rule {ruleid} unhidden.")
        else:
            cli.print_warn(f"[!] This rule was already visible.")

def _tabulate_rules(rules):
    headers = ["ID", "Name", "SRC Zone", "SRC Addr", "SRC Addr (IPs)", "DST Zone", "DST Addr", "DST Addr (IPs)", "Appl.", "Service", "Service Ports", "Action"]
    maxcolwidths=[None, 30, None, None, None, None, None, None, None, None, None]
    data = [ [
            rule.id,
            rule.name,
            "\n".join(rule.src_zone.split(";")),
            "\n".join(rule.src_addr.split(";")),
            "\n".join(rule.src_addr_ips.split(";")),
            "\n".join(rule.dst_zone.split(";")),
            "\n".join(rule.dst_addr.split(";")),
            "\n".join(rule.dst_addr_ips.split(";")),
            "\n".join(rule.application.split(";")),
            "\n".join(rule.service.split(";")),
            "\n".join(rule.service_ports.split(";")),
            rule.action
         ] for rule in rules ]
    if len(data) > 0:
        cli.repl.print(tabulate(data, headers=headers, tablefmt='grid', maxcolwidths=maxcolwidths))

def _pretty_print_nested_structure(data):
    # Initialize variables
    indent_level = 0
    i = 0
    length = len(data)
    current_segment = ""
    result = ""

    # Stack-based approach to handled nested parenthesis.
    while i < length:
        char = data[i]

        if char == '(':
            # Print current segment and increase indentation
            result += '\n' + '    ' * indent_level + "- " + current_segment.strip()
            indent_level += 1
            current_segment = ""
        elif char == ')':
            # Print the last segment before closing parenthesis
            if current_segment.strip():
                result += '\n' + '    ' * indent_level + "- " + current_segment.strip()
                current_segment = ""
            indent_level -= 1
        elif char == ';':
            current_segment = ""
        else:
            # Append to the current segment
            current_segment += char
        
        # Move to the next character
        i += 1
    
    # Print any remaining segment
    if current_segment.strip():
        result += '\n' + '    ' * indent_level + "- " + current_segment.strip()
    
    cli.print(result+"\n")