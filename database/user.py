from pony import orm
from . import db


class User(db.Entity):
    username = orm.Required(str, unique=True)
    password = orm.Required(str)
