import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import create_engine

Base = declarative_base()


# define classes here
class User(Base):
    __tablename__ = 'user'

    user_id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(80), nullable=False)
    picture = Column(String(250))


class Region(Base):
    """Setup a table for each state."""

    __tablename__ = 'region'

    name = Column(String(80), nullable=False)
    region_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.user_id'))
    user = relationship(User, backref=backref('region', cascade='all, delete-orphan'))

    @property
    def serialize(self):
        """Return object data in easily serializeable format."""
        return {
            'name': self.name,
            'id': self.region_id,
        }


class Trail(Base):
    """Setup a table for each trail in the state."""

    __tablename__ = 'trail'

    name = Column(String(100), nullable=False)
    trail_id = Column(Integer, primary_key=True)
    difficulty = Column(String(10))
    description = Column(String(500))
    city = Column(String(20))
    region_id = Column(Integer, ForeignKey('region.region_id'))
    region = relationship(Region, backref=backref('trail', cascade='all, delete-orphan'))
    user_id = Column(Integer, ForeignKey('user.user_id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Serialize function to be able to send JSON objects in a serializable format."""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.trail_id,
            'difficulty': self.difficulty,
            'city': self.city,
        }

engine = create_engine('sqlite:///mtbtrailswithusers.db')

Base.metadata.create_all(engine)
