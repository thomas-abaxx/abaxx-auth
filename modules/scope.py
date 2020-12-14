from peewee import *
from datetime import datetime as dt
from .db import db

# CREATE EXTENSION pgcrypto; first
import uuid
import json

class Scope(Model):
    scopename =  CharField(unique=True, null=False)
    description =  CharField(null=False)

    class Meta:
        database = db

if db.table_exists('scope') is False:
    db.create_tables([Scope])