from peewee import *
from datetime import datetime as dt
from .db import db

# CREATE EXTENSION pgcrypto; first
import uuid
import json

class Member(Model):
    name = CharField()
    username = CharField(unique=True, null=False)
    password = CharField()
    identity = CharField(null=True)
    role_id = CharField(null=True)
    created = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])

    class Meta:
        database = db

if db.table_exists('member') is False:
    db.create_tables([Member])