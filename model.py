import configparser

from cryptography.fernet import Fernet

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base

from OpenSSL import crypto

engine = create_engine('sqlite:///test.db')
Base = declarative_base()

config = configparser.ConfigParser()
config.read('config.conf')

# Only needed for new key
# key = Fernet.generate_key()

FERNETKEY = config['ENCRYPTION']['key']
f = Fernet(FERNETKEY)


class CA(Base):
    __tablename__ = 'cas'
    cipher_suite = Fernet(FERNETKEY)

    id = Column(Integer, primary_key=True)
    desc = Column(String)
    cert = Column(String)
    key = Column(String)
    certs = relationship("CERT", back_populates="ca")

    def __init__(self, desc, cert, key):
        self.desc = desc
        self.cert = cert
        self.key = self.cipher_suite.encrypt(bytes(key, encoding='utf8'))

    def get_key(self):
        return self.cipher_suite.decrypt(self.key).decode('utf-8')

    def get_cert(self):
        return self.cert

    def get_pub(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert)
        return crypto.dump_publickey(
            crypto.FILETYPE_PEM, cert.get_pubkey()).decode('utf-8')

    def __repr__(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert)
        return "{}, {}, {}".format(self.id, self.desc, cert.get_subject().CN)


class CERT(Base):
    __tablename__ = 'certs'
    cipher_suite = Fernet(FERNETKEY)

    id = Column(Integer, primary_key=True)
    desc = Column(String)
    cert = Column(String)
    key = Column(String)
    ca_id = Column(Integer, ForeignKey('cas.id'))
    ca = relationship("CA", back_populates="certs")   

    def __init__(self, desc, cert, key, ca):
        self.desc = desc
        self.cert = cert
        self.key = self.cipher_suite.encrypt(bytes(key, encoding='utf8'))
        self.ca = ca

    def get_key(self):
        return self.cipher_suite.decrypt(self.key).decode('utf-8')

    def get_cert(self):
        return self.cert

    def get_pub(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert)
        return crypto.dump_publickey(
            crypto.FILETYPE_PEM, cert.get_pubkey()).decode('utf-8')

    def __repr__(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert)
        return "{}, {}, {}, {}".format(
            self.id, self.desc, cert.get_subject().CN, self.ca.id
        )


Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()
