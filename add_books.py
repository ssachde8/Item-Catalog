# -*- coding: utf-8 -*-
from database_setup import Base, User, Books
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# bind engine to the metadata in order to access
# the declaratives in a DBSession instance
engine = create_engine('sqlite:///books_catalog.db')
Base.metadata.create_all(engine)

# create db session
DBSession = sessionmaker(bind=engine)
# session instance will help in staging any changes.
# commit can be used to commit changes.
# rollback is used to revert any change
session = DBSession()

# *Create Dummy Data
# 1. Create dummy user
user_1 = User(username="admin", email="satvik.sachdeva@gmail.com")
session.add(user_1)
session.commit()

# 2. create dummy books data

book_1 = Books(
    name="The School of Greatness: A Real-World Guide to Living Bigger, Loving Deeper, and Leaving a Legacy",
    price="16.58",
    author="LEWIS HOWES",
    cover="https://images-na.ssl-images-amazon.com/images/I/517-Dn1lhtL._SX323_BO1,204,203,200_.jpg",
    description='A framework for personal development...',
    category="Motivation",
    user_id=1
)
session.add(book_1)
session.commit()

book_2 = Books(
    name="Unshakeable Your Financial Freedom Playbook",
    price="18.20",
    author="Tony Robbins",
    cover="https://images-na.ssl-images-amazon.com/images/I/516Ic5gWnfL._SX328_BO1,204,203,200_.jpg",
    description="After interviewing fifty of the worlds greatest financial minds ...",
    category="Finance",
    user_id=1
)
session.add(book_2)
session.commit()

book_3 = Books(
    name="Awaken the Giant Within : How to Take Immediate Control of Your Mental,... ",
    price="10.65",
    author="Tony Robbins",
    cover="https://images-na.ssl-images-amazon.com/images/I/51lXzR%2BxTOL._SX327_BO1,204,203,200_.jpg",
    description="Wake up and take control of your life! ...",
    category="Inspiration",
    user_id=1
)
session.add(book_3)
session.commit()

book_4 = Books(
    name="The Sports Gene: Inside the Science of Extraordinary Athletic Performance",
    price="12.75",
    author="David Epstein",
    cover="https://images-na.ssl-images-amazon.com/images/I/51WM5R8Q-yL._SX324_BO1,204,203,200_.jpg",
    description="In this controversial and engaging exploration of athletic success...",
    category="Sports",
    user_id=1
)
session.add(book_4)
session.commit()

book_5 = Books(
    name="Mystery: Perfect Crime (Davenport Mystery Crime Thriller) ",
    price="10.89",
    author="V.S. Vashist",
    cover="https://images-na.ssl-images-amazon.com/images/I/51EzWt76C4L.jpg",
    description="The daughter of one of the most influential man in New York falls for ...",
    category="Mystery",
    user_id=1
)
session.add(book_5)
session.commit()


print "SUCCESS !!!"
