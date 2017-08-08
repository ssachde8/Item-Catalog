import os
import sys
# import database modules
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


# class to store user info
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    provider = Column(String(25))


# class for books database
class Books(Base):
    __tablename__ = 'books'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    price = Column(String(8), nullable=False)
    author = Column(String(250), nullable=False)
    cover = Column(String(250), nullable=False)
    description = Column(String(250), nullable=False)
    category = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        # return data in serialized format
        return {
            'id': self.id,
            'name': self.name,
            'price': self.price,
            'author': self.author,
            'cover': self.cover,
            'description': self.description,
            'category': self.category
        }

engine = create_engine('sqlite:///books_catalog.db')
Base.metadata.create_all(engine)