#!/usr/bin/env python

import db
import cli

if __name__ == "__main__":
    db.sqlhandler = db.SqlHandler(url='sqlite:///db.sqlite', echo=False)

    cli.repl.run()