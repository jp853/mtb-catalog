from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Region, Trail, User

engine = create_engine('sqlite:///mtbtrailswithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# California
california = Region(user_id=1, name="California")

session.add(california)
session.commit()

trail1 = Trail(user_id=1, name="Braille Flow", difficulty="intermediate-advanced", description="The ridge climb is a bit of a haul, but the Braille Trail delivers nicely. It'll be over quick, but Braille is dense with small to medium (even medium-large) features, all of which are optional. Pick a good line and have a blast.", city="Day Valley", region=california)

session.add(trail1)
session.commit()

trail2 = Trail(user_id=1, name="Downieville Classic", difficulty="intermediate-advanced", description="The Downieville Classic ride. Get your car/shuttle ride to the top. The trail starts immediately on singletrack. There is very, very little climbing. There will be snow in places through May.", city="Downieville", region=california)

session.add(trail2)
session.commit()

# Colorado
colorado = Region(user_id=1, name="Colorado")

session.add(colorado)
session.commit()

trail1 = Trail(user_id=1, name="Monarch Crest-IMBA Epic", difficulty="intermediate-advanced", description="You'll encounter everything: Singletrack, doubletrack, fire road, smooth and packed, rocky and loose, great views, and entirely fun!", city="Salida", region=colorado)

session.add(trail1)
session.commit()

trail2 = Trail(user_id=1, name="Phil's World", difficulty="intermediate", description="If solitude is what you are looking for, this is not the area for you, at the parking lot at least. Because of the one way direction, once the parking lot is left behind, you would think you are the only one on the trails.", city="Cortez", region=colorado)

session.add(trail2)
session.commit()

# Utah
utah = Region(user_id=1, name="Utah")

session.add(utah)
session.commit()

trail1 = Trail(user_id=1, name="The Whole Enchilada", difficulty="advanced", description="From an alpine pass above treeline, down to the sandstone canyon of the Colorado River. From black humus to red slickrock, singletrack to paved bike path.", city="Moab", region=utah)

session.add(trail1)
session.commit()

trail2 = Trail(user_id=1, name="Porcupine Rim", difficulty="advanced", description="The world famous Porcupine Rim ride is a must-do on any mountain bike bucket list and is a classic Moab ride.", city="Moab", region=utah)

session.add(trail2)
session.commit()

print "added mtb trails!"