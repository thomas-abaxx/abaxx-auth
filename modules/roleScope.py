from peewee import *
from datetime import datetime as dt
from .db import db
from .scope import Scope
from .role import Role

# CREATE EXTENSION pgcrypto; first
# TODO: ADD FK
import uuid
import json

class RoleScope(Model):
    scope = ForeignKeyField(Scope, backref='scope')
    role = ForeignKeyField(Role, backref='role')
   
    class Meta:
        database = db

if db.table_exists('rolescope') is False:
    db.create_tables([RoleScope])