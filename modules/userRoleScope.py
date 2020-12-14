from peewee import *
from datetime import datetime as dt
from .db import db
from .roleScope import RoleScope
from .user import User
# CREATE EXTENSION pgcrypto; first
import uuid
import json

class UserRoleScope(Model):
    roleScope  = ForeignKeyField(RoleScope , backref='roleScope')
    user = ForeignKeyField(User, backref='user')
    enabled = BooleanField(default=True)
    created_at = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])
    updated_at = DateTimeField(constraints=[SQL('DEFAULT CURRENT_TIMESTAMP')])

    class Meta:
        database = db

if db.table_exists('userrolescope') is False:
    db.create_tables([UserRoleScope])