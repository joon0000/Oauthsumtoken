# seed.py

import datetime
from API_server import app, db, Content

with app.app_context():

    # Create an empty list
    contents = []

    # Add some Pet instances to the list
    contents.append(Content(
                        title='How to create Oauth2',
                        detail='i can\'t find my project',
                        sub='kawn'
                    ))
    
    contents.append(Content(
                        title='Paloalto',
                        detail='I love palo so much',
                        sub='boss'
                    ))
    
    # Insert each Pet in the list into the database table
    db.session.add_all(contents)

    # Commit the transaction
    db.session.commit()