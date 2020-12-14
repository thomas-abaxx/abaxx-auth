from peewee import *
from datetime import datetime as dt
from .db import db
from .role import Role
from .user import User

# CREATE EXTENSION pgcrypto; first
import uuid
import json

class UserRole(Model):
    user  = ForeignKeyField(User , backref='user')
    role  = ForeignKeyField(Role , backref='role')
  

    class Meta:
        database = db

if db.table_exists('userrole') is False:
    db.create_tables([UserRole])