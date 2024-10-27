#!/usr/bin/env python

import re

def validate_ports_format(csv_string):
    # Format must be a CSV that contains values like "<integer>[-<integer>][-tcp|-udp]"
    pattern = r"^(\d+(-\d+)?(-tcp|-udp)?)(,\d+(-\d+)?(-tcp|-udp)?)*$"
    return bool(re.match(pattern, csv_string))