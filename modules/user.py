from peewee import *
from datetime import datetime as dt
from .db import db
from .member import Member
from .role import Role

# CREATE EXTENSION pgcrypto; first
# LINK FOREGN KEYS..
import uuid
import json

class User(Model):
    member_id = CharField()
    username = CharField(unique=True, null=False)
    firstName = CharField( null=True)
    lastName = CharField( null=True)
    email = CharField( null=True)
    phone = CharField(null=True)
    identity = CharField(unique=True, null=False)
    created_at = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    updated_at = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])

    class Meta:
        database = db

if db.table_exists('user') is False:
    db.create_tables([User])