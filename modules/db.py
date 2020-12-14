import os
from peewee import PostgresqlDatabase

db = PostgresqlDatabase(
    os.environ['DB_NAME'], user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'], host=os.environ['DB_HOST'], port=os.environ['DB_PORT'], autorollback=True
)