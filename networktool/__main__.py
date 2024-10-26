#!/usr/bin/env python

import db
import cli
import scans

if __name__ == "__main__":
    db.sqlhandler = db.SqlHandler(url='sqlite:///db.sqlite', echo=False)

    scans.clean_running_scans()

    cli.repl.run()