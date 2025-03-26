#To avoid circular imports 
#To save any changes made to the db run python init_db.py

from models import db, user_datastore
from app import create_app

app = create_app()
with app.app_context():
    db.create_all()
    
    user_datastore.find_or_create_role(name='admin')
    user_datastore.find_or_create_role(name='Service_professional')
    user_datastore.find_or_create_role(name='customer')
    admin_user= user_datastore.find_user(id=1)
    if not admin_user:
        new_admin= user_datastore.create_user(email='admin@abc.com', password='admin', roles=['admin'])
        user_datastore.add_role_to_user(new_admin,'admin')
        
    service_professional= user_datastore.find_user(email='prof@abc.com')
    if not service_professional:
        new_prof= user_datastore.create_user(email='prof@abc.com', password='service', roles=['Service_professional'])
        user_datastore.add_role_to_user(new_prof,'Service_professional')
        
    customer= user_datastore.find_user(email='customer@abc.com')
    if not customer:
        new_customer= user_datastore.create_user(email='customer@abc.com', password='customer', roles=['customer'])
        user_datastore.add_role_to_user(new_customer,'customer')
        
        
    db.session.commit()