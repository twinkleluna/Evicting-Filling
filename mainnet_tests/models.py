from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Index, DECIMAL
from sqlalchemy.dialects.mysql import BIGINT, MEDIUMTEXT

Base = declarative_base()


class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    address = Column(String(70), nullable=False)
    port = Column(Integer, nullable=False)
    date = Column(DateTime, nullable=True)
    seen = Column(Boolean, default=False, nullable=False)
    timestamp = Column(BIGINT, nullable=True)
    height = Column(BIGINT, nullable=True)
    version = Column(Integer, nullable=True)
    user_agent = Column(String(150), nullable=True)
    services = Column(BIGINT(unsigned=True), default=0, nullable=False)
    w_tried = Column(Integer, nullable=True)
    os = Column(String(60), nullable=True)
    wfp = Column(String(2000), nullable=True)
    afp = Column(MEDIUMTEXT, nullable=True)
    sync_rate = Column(DECIMAL(7,5), nullable=True)
    same = Column(String(500), nullable=True)
    filter = Column(String(500), nullable=True)
    connslots = Column(Integer, nullable=True)

    Index('idx_node', 'address', 'port', 'date', unique=True)

    def to_dict(self):
        return {
            "id": self.id,
            "address": self.address,
            "port": self.port,
            "date": self.date,
            "seen": self.seen,
            "timestamp": self.timestamp,
            "height": self.height,
            "version": self.version,
            "user_agent": self.user_agent,
            "services": self.services,
            "w_tried": self.w_tried,
            "os": self.os,
            "wfp": self.wfp,
            "afp": self.afp,
            "sync_rate": self.sync_rate,
            "same": self.same,
            "filter": self.filter,
            "connslots": self.connslots
        }

    def from_dict(self, d):
        self.id = d['id']
        self.address = d['address']
        self.port = d['port']
        self.date = d['date']
        self.seen = d['seen']
        self.timestamp = d['timestamp']
        self.height = d['height']
        self.version = d['version']
        self.user_agent = d['user_agent']
        self.services = d['services']
        self.w_tried = d['w_tried']
        self.os = d['os']
        self.wfp = d['wfp']
        self.afp = d['afp']
        self.sync_rate = d['sync_rate']
        self.same = d['same']
        self.filter = d['filter']
        self.connslots = d['connslots']

    @staticmethod
    def new_from_dict(d):
        obj = Node()
        obj.id = d['id'] if 'id' in d else None
        obj.address = d['address'] if 'address' in d else None
        obj.port = d['port'] if 'port' in d else None
        obj.date = d['date'] if 'date' in d else None
        obj.seen = d['seen'] if 'seen' in d else None
        obj.timestamp = d['timestamp'] if 'timestamp' in d else None
        obj.height = d['height'] if 'height' in d else None
        obj.version = d['version'] if 'version' in d else None
        obj.user_agent = d['user_agent'] if 'user_agent' in d else None
        obj.services = d['services'] if 'services' in d else None
        obj.w_tried = d['w_tried'] if 'w_tried' in d else None
        obj.os = d['os'] if 'os' in d else None
        obj.wfp = d['wfp'] if 'wfp' in d else None
        obj.afp = d['afp'] if 'afp' in d else None
        obj.sync_rate = d['sync_rate'] if 'sync_rate' in d else None
        obj.same = d['same'] if 'same' in d else None
        obj.filter = d['filter'] if 'filter' in d else None
        obj.connslots = d['connslots'] if 'connslots' in d else None
        return obj

    def __repr__(self):
        return "<NODE - {}>".format(self.to_dict())

    @validates('port', 'height', 'version', 'services')
    def validate_integers(self, key, field):
        if field is not None:
            if key == 'services' and field > 18446744073709551615:
                print("{}:{} is > SQLite Max Value. Truncating".format(key, field))
                return 18446744073709551615
            elif key != 'services' and field > 9223372036854775807:
                print("{}:{} is > SQLite Max Value. Truncating".format(key, field))
                return 9223372036854775807
            return int(field)
        return None

    @validates('address', 'user_agent', 'os', 'wfp')
    def validate_string(self, key, field):
        if field is not None:
            if key == 'address':
                if len(field) > 70:
                    print(key, field, "over max len")
                    return field[:70]
            elif key == "user_agent":
                if len(field) > 150:
                    print(key, field, "over max len")
                    return field[:150]
            elif key == "os":
                if len(field) > 60:
                    print(key, field, "over max len")
                    return field[:60]
            elif key == "wfp":
                if len(field) > 2000:
                    print(key, field, "over max len")
                    return field[:2000]
            elif len(field) > 60:
                print(key, field, "over max len")
                return field[:60]
        return field