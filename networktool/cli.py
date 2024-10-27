#!/usr/bin/env python

import sys

from riposte import Riposte
from riposte.printer import Palette

import scans, sourcenetworks, targets, rules

COMMANDS = ["scans", "sourcenetworks", "targets"]

SCANS_SUBCOMMANDS = ["new", "list", "show", "export", "kill", "rm", "clean"]
SCANS_NEW_SUBCOMMANDS = ["recon", "serviceid", "segmentation-check", "generic", "custom-nmap"]

SOURCENETWORKS_SUBCOMMANDS = ["add", "rm", "list"]
TARGETS_SUBCOMMANDS = ["add", "rm", "list"]

RULES_SUBCOMMANDS = ["rm", "list", "hide", "unhide"]
RULES_LIST_SUBCOMMANDS = ["hidden", "all"]

global repl

repl = Riposte(prompt="[network-tool] ")

@repl.command("exit")
def exit():
    exit = scans.kill_all_scans()
    if exit:
        sys.exit(0)

@repl.command("help")
def help():
    repl.info(f"Available commands: {"/".join(COMMANDS)}. Execute 'help <command> (<subcommand>)' for additional details.")

@repl.command("scans", description="Execute scans per category.")
def scans_command(str1: str, str2: str = None, str3 = None, str4 = None, str5 = None):
    help_str = f"Usage: scans {"/".join(SCANS_SUBCOMMANDS)}. Execute 'help <command> <subcommand>' for additional details." 

    if str1 == "new":
        target = str3
        if str2 == "recon":
            scans.recon_scan(target)
        elif str2 == "serviceid":
            if str3 == "fromscanid":
                scanid = parse_int(str4)
                if scanid:
                    scans.serviceid_scan(scanid=scanid)
            else:
                ports = str4
                scans.serviceid_scan(target, ports)
        elif str2 == "segmentation-check":
            scans.segmentation_check_scan(target)
        elif str2 == "generic":
            ports = str4
            scans.generic_scan(target, ports)
        elif str2 == "custom-nmap":
            flags = str4
            scans.nmap_custom_scan(target, flags)
        else:
            repl.error("Unknown scan type.")
            repl.info(help_str)
    elif str1 == "kill":
        scanid = parse_int(str2)
        if scanid:
            scans.kill_scan(scanid)
    elif str1 == "rm":
        scanid = parse_int(str2)
        if scanid:
            scans.rm_scan(scanid)
    elif str1 == "list":
        scans.list_scans(filter=str2)
    elif str1 == "show":
        scanid = parse_int(str2)
        if scanid:
            scans.print_scan(scanid)
    elif str1 == "clean":
        scans.clean_scans()
    elif str1 == "export":
        scanid = parse_int(str2)
        if scanid:
            output_file = str3
            scans.export_scan(scanid, output_file)
    else:
        repl.error("Unknown scan option.")
        repl.info(help_str)

@repl.complete("scans")
def start_completer(text, line, start_index, end_index):
    if line.startswith("scans new"):
        if text == "new":
            return SCANS_NEW_SUBCOMMANDS
        return [
            subcommand
            for subcommand in SCANS_NEW_SUBCOMMANDS
            if subcommand.startswith(text)
        ]

    return [
        subcommand
        for subcommand in SCANS_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("sourcenetworks", description="Manage SourceNetworks.")
def sourcenetworks_command(str1: str, str2: str = None, str3 = None):
    help_str = f"Usage: sourcenetworks {"/".join(SOURCENETWORKS_SUBCOMMANDS)}. Execute 'help <command> <subcommand>' for additional details."
    help_add_str = f"Usage: sourcenetworks add <IP_RANGE> \"<NAME>\""

    if str1 == "add":
        if str2 and str3:
            sourcenetworks.add_sourcenetwork(ip_range=str2, name=str3)
        else:
            repl.info(help_add_str)
    elif str1 == "rm":
        snid = parse_int(str2)
        if snid:
            sourcenetworks.rm_sourcenetwork(snid)
    elif str1 == "list":
        sourcenetworks.list_sourcenetworks()
    else:
        repl.error("Unknown sourcenetworks option.")
        repl.info(help_str)

@repl.complete("sourcenetworks")
def start_completer(text, line, start_index, end_index):
    return [
        subcommand
        for subcommand in SOURCENETWORKS_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("targets", description="Manage Targets.")
def targets_command(str1: str, str2: str = None, str3 = None, str4 = None):
    help_str = f"Usage: targets {"/".join(TARGETS_SUBCOMMANDS)}. Execute 'help <command> <subcommand>' for additional details."
    help_add_str = f"Usage: targets add <IP_RANGE> <PORTS_CSV> \"<NAME>\""

    if str1 == "add":
        if str2 and str3 and str4:
            targets.add_target(ip_range=str2, ports=str3, name=str4)
        else:
            repl.info(help_add_str)
    elif str1 == "rm":
        targetid = parse_int(str2)
        if targetid:
            targets.rm_target(targetid)
    elif str1 == "list":
        targets.list_targets()
    else:
        repl.error("Unknown targets option.")
        repl.info(help_str)

@repl.complete("targets")
def start_completer(text, line, start_index, end_index):
    return [
        subcommand
        for subcommand in TARGETS_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

@repl.command("rules", description="Manage Rules.")
def rules_command(str1: str, str2: str = None, str3 = None, str4 = None):
    help_str = f"Usage: rules {"/".join(RULES_SUBCOMMANDS)}. Execute 'help <command> <subcommand>' for additional details."

    if str1 == "show":
        ruleid = parse_int(str2)
        if ruleid:
            rules.show_rule(ruleid)
    elif str1 == "rm":
        ruleid = parse_int(str2)
        if ruleid:
            rules.rm_rule(ruleid)
    elif str1 == "hide":
        ruleid = parse_int(str2)
        if ruleid:
            rules.hide_rule(ruleid)
    elif str1 == "unhide":
        ruleid = parse_int(str2)
        if ruleid:
            rules.unhide_rule(ruleid)
    elif str1 == "list":
        rules.list_rules(filter=str2)
    else:
        repl.error("Unknown rules option.")
        repl.info(help_str)

@repl.complete("rules")
def start_completer(text, line, start_index, end_index):
    if line.startswith("rules list"):
        if text == "list":
            return RULES_LIST_SUBCOMMANDS
        return [
            subcommand
            for subcommand in RULES_LIST_SUBCOMMANDS
            if subcommand.startswith(text)
        ]

    return [
        subcommand
        for subcommand in RULES_SUBCOMMANDS
        if subcommand.startswith(text)
    ]

def parse_int(value, error_msg="Please provide a valid identifier."):
    try:
        return int(value)
    except ValueError:
        print(error_msg)
    return None

def print(msg):
    repl.print(msg)

def print_success(msg):
    repl.print(Palette.GREEN.format(msg))

def print_error(msg):
    repl.print(Palette.RED.format(msg))

def print_warn(msg):
    repl.print(Palette.YELLOW.format(msg))

def print_info(msg):
    repl.print(Palette.CYAN.format(msg))