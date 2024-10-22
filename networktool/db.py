#!/usr/bin/env python

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column
from sqlalchemy import Table
from sqlalchemy import ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.types import DateTime, Integer, Text
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import sessionmaker
from sqlalchemy import func


from libnmap.plugins.backendplugin import NmapBackendPlugin
from libnmap.reportjson import ReportDecoder, ReportEncoder

from ipaddress import ip_address

from typing import List

global sqlhandler

Base = declarative_base()

scans_sourcenetworks_table = Table(
    "scans_sourcenetworks",
    Base.metadata,
    Column("scans_id", ForeignKey("scans.id")),
    Column("sourcenetworks_id", ForeignKey("sourcenetworks.id"))
)

scans_targets_table = Table(
    "scans_targets",
    Base.metadata,
    Column("scans_id", ForeignKey("scans.id")),
    Column("targets_id", ForeignKey("targets.id"))
)

scans_rules_table = Table(
    "scans_rules",
    Base.metadata,
    Column("scans_id", ForeignKey("scans.id")),
    Column("rules_id", ForeignKey("rules.id"))
)

scans_reports_table = Table(
    "scans_reports",
    Base.metadata,
    Column("scans_id", ForeignKey("scans.id")),
    Column("reports_id", ForeignKey("reports.id"))
)

class SqlHandler:
    """
    This class handles the persistence of objects in SQL backend
    Implementation is made using sqlalchemy
    """

    class Scan(Base):
        """
        Embedded class for ORM map Scan
        """

        __tablename__ = "scans"

        STATUS_READY = "READY"
        STATUS_RUNNING = "RUNNING"
        STATUS_FAILED = "FAILED"
        STATUS_CANCELLED = "CANCELLED"
        STATUS_DONE = "DONE"

        id = Column("id", Integer, primary_key=True)
        inserted = Column("inserted", DateTime(), server_default=func.now())
        name = Column("name", Text())
        nmap_target = Column("nmap_target", Text())
        nmap_flags = Column("nmap_flags", Text())
        scan_type = Column("scan_type", Text()) # Recon / ServiceID / SegmentationCheck / Generic
        source_ip = Column("source_ip", Text())
        status = Column("status", Text())
        percentage = Column("percentage", Integer)
        sourcenetworks: Mapped[List["SourceNetwork"]] = relationship(secondary=scans_sourcenetworks_table)
        targets: Mapped[List["Target"]] = relationship(secondary=scans_targets_table)
        rules: Mapped[List["Rule"]] = relationship(secondary=scans_rules_table)
        reports: Mapped[List["Report"]] = relationship(secondary=scans_reports_table)

        def __init__(self, name, nmap_target, nmap_flags, scan_type, source_ip):
            self.name = name
            self.nmap_target = nmap_target
            self.nmap_flags = nmap_flags
            self.scan_type = scan_type
            self.source_ip = source_ip
            self.status = self.STATUS_READY
    
    class SourceNetwork(Base):
        """
        Embedded class for ORM map SourceNetwork
        """

        __tablename__ = "sourcenetworks"

        id = Column("id", Integer, primary_key=True)
        inserted = Column("inserted", DateTime(), server_default=func.now())
        name = Column("name", Text())
        ip_range = Column("ip_range", Text())

        def __init__(self, obj):
            self.name = obj.name
            self.ip_range = obj.ip_range
    
    class Target(Base):
        """
        Embedded class for ORM map Target
        """

        __tablename__ = "targets"

        id = Column("id", Integer, primary_key=True)
        inserted = Column("inserted", DateTime(), server_default=func.now())
        name = Column("name", Text())
        ip_range = Column("ip_range", Text())
        ports = Column("ports", Text())

        def __init__(self, obj):
            self.name = obj.name
            self.ip_range = obj.ip_range
            self.ports = obj.ports
    
    class Rule(Base):
        """
        Embedded class for ORM map Rule
        """

        __tablename__ = "rules"

        id = Column("id", Integer, primary_key=True)
        inserted = Column("inserted", DateTime(), server_default=func.now())
        name = Column("name", Text())
        src_zone = Column("src_zone", Text())
        src_addr_text = Column("src_addr_text", Text())
        src_addr = Column("src_addr", Text())
        dst_zone = Column("dst_zone", Text())
        dst_addr_text = Column("dst_addr_text", Text())
        dst_addr = Column("dst_addr", Text())
        dst_ports_text = Column("dst_ports_text", Text())
        dst_ports = Column("dst_ports", Text())
        action = Column("action", Text())
        info = Column("info", Text())

        def __init__(self, obj):
            self.id = obj.id
            self.name = obj.name
            self.src_zone = obj.src_zone
            self.src_addr_text = obj.src_addr_text
            self.src_addr = obj.src_addr
            self.dst_zone = obj.dst_zone
            self.dst_addr_text = obj.dst_addr_text
            self.dst_addr = obj.dst_addr
            self.dst_ports_text = obj.dst_ports_text
            self.dst_ports = obj.dst_ports
            self.action = obj.action
            self.info = obj.info    
        
    
    class Report(Base):
        """
        Embedded class for ORM map Report
        """

        __tablename__ = "reports"

        id = Column("id", Integer, primary_key=True)
        inserted = Column("inserted", DateTime(), server_default=func.now())
        report_json = Column("report_json", Text())

        def __init__(self, obj):
            dumped_json = json.dumps(obj, cls=ReportEncoder)
            self.report_json = bytes(dumped_json.encode("UTF-8"))
        
        def decode(self):
            json_decoded = self.report_json.decode("utf-8")
            nmap_report_obj = json.loads(json_decoded, cls=ReportDecoder)
            return nmap_report_obj
    
    class ModuleOutput(Base):
        """
        Embedded class for ORM map ModuleOutput
        """

        __tablename__ = "moduleoutputs"

        id = Column("id", Integer, primary_key=True)
        inserted = Column("inserted", DateTime(), server_default=func.now())
        name = Column("name", Text())
        module = Column("module", Text())
        output = Column("output", Text())

        def __init__(self, obj):
            self.name = obj.name
            self.module = obj.module
            self.output = obj.output
    
    def __init__(self, **kwargs):
        self.Session = sessionmaker()

        if "url" not in kwargs:
            raise ValueError
        self.url = kwargs["url"]
        del kwargs["url"]
        try:
            self.engine = create_engine(self.url, **kwargs)
            Base.metadata.create_all(bind=self.engine, checkfirst=True)
            self.Session.configure(bind=self.engine)
        except Exception as e:
            raise (e)
    
    def insert(self, obj):
        sess = self.Session()
        sess.add(obj)
        sess.commit()
        obj_id = obj.id
        sess.close()
        return obj_id
    
    def get(self, obj_type, obj_id=None):
        if obj_type is None or obj_id is None:
            raise ValueError
        sess = self.Session()
        orp = sess.query(obj_type).filter_by(id=obj_id)
        obj = orp.first()
        sess.close()
        return obj
    
    def getall(self, obj_type, orderby):
        if obj_type is None:
            raise ValueError
        sess = self.Session()
        return sess.query(obj_type).order_by(orderby)

    def delete(self, obj_type, obj_id=None):
        if obj_type is None or obj_id is None:
            raise ValueError
        nb_line = 0
        sess = self.Session()
        rpt = sess.query(obj_type).filter_by(id=obj_id)
        nb_line = rpt.delete()
        sess.commit()
        sess.close()
        return nb_line