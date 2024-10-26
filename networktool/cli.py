#!/usr/bin/env python

import sys

from riposte import Riposte
from riposte.printer import Palette

import scans, sourcenetworks, targets

COMMANDS = ["scans", "sourcenetworks", "targets"]

SCANS_SUBCOMMANDS = ["new", "list", "show", "export", "kill", "rm", "clean"]
SCANS_NEW_SUBCOMMANDS = ["recon", "serviceid", "segmentation-check", "generic", "custom-nmap"]

SOURCENETWORKS_SUBCOMMANDS = ["add", "rm", "list"]
TARGETS_SUBCOMMANDS = ["add", "rm", "list"]

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
def scans_command(str1: str, str2: str = None, str3 = None, str4 = None):
    help_str = f"Usage: scans {"/".join(SCANS_SUBCOMMANDS)}. Execute 'help <command> <subcommand>' for additional details." 

    if str1 == "new":
        target = str3
        if str2 == "recon":
            scans.recon_scan(target)
        elif str2 == "serviceid":
            #ports = str4
            #TODO: scans.service_id(target, ports)
            pass
        elif str2 == "segmentation-check":
            scans.segmentation_check_scan(target)
        elif str2 == "generic":
            ports = str4
            #TODO: port format validation
            scans.generic_scan(target, ports)
        elif str2 == "custom-nmap":
            scans.nmap_custom_scan(target)
        else:
            repl.error("Unknown scan type.")
            repl.info(help_str)
    elif str1 == "kill":
        if str2:
            scanid = None
            try:
                scanid = int(str2)
            except ValueError:
                print("Please provide a valid identifier.")
            scans.kill_scan(scanid)
        else:
            repl.error("Please provide a valid identifier.")
            repl.info(help_str)
    elif str1 == "rm":
        if str2:
            scanid = None
            try:
                scanid = int(str2)
            except ValueError:
                print("Please provide a valid identifier.")
            scans.rm_scan(scanid)
        else:
            repl.error("Please provide a valid identifier.")
            repl.info(help_str)
    elif str1 == "list":
        if not str2:
            scans.list_scans()
        elif str2 == "done" or str2 == "running":
            filter = str2
            scans.list_scans(filter)
        else:
            repl.error("Unknown scan type.")
            repl.info(help_str)
    elif str1 == "show":
        if str2:
            scanid = None
            try:
                scanid = int(str2)
            except ValueError:
                print("Please provide a valid identifier.")
            scans.print_scan(scanid)
        else:
            repl.error("Please provide a valid identifier.")
            repl.info(help_str)
    elif str1 == "clean":
        scans.clean_scans()
    elif str1 == "export":
        if str2:
            scanid = None
            try:
                scanid = int(str2)
            except ValueError:
                print("Please provide a valid identifier.")
            output_file = str3
            scans.export_scan(scanid, output_file)
        else:
            repl.error("Please provide a valid identifier.")
            repl.info(help_str)
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
        if str2:
            snid = None
            try:
                snid = int(str2)
            except ValueError:
                print("Please provide a valid identifier.")
            sourcenetworks.rm_sourcenetwork(snid)
        else:
            repl.error("Please provide a valid identifier.")
            repl.info(help_str)
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
        if str2:
            targetid = None
            try:
                targetid = int(str2)
            except ValueError:
                print("Please provide a valid identifier.")
            targets.rm_target(targetid)
        else:
            repl.error("Please provide a valid identifier.")
            repl.info(help_str)
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

def print(msg):
    repl.print(msg)

def print_success(msg):
    repl.print(Palette.GREEN.format(msg))

def print_error(msg):
    repl.print(Palette.RED.format(msg))

def print_warn(msg):
    repl.print(Palette.YELLOW.format(msg))