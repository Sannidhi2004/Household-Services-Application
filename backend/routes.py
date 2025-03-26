from flask_restful import Resource
from flask import request
from flask_security import auth_required, roles_accepted

from models import db, test


class first_restful(Resource):
    @auth_required('token')
    
    def post(self):
        if request.get_json(): # if request.form
            # var1 = request.get_json()['formKey'] # request.form['formKey']
            data = request.get_json()
            print(data)
            new_data = test(name=data['name'], age=data['age'])
            db.session.add(new_data)
            db.session.commit()
            return {"data": f'template print, {new_data.name}!'}
        return {"data": 'no data!'}
    
    @auth_required('token')
     
    def get(self):
        data = test.query.first()
        if data:
            return {"data": data.name}
        return {"msg": 'This is a test API'}

    @auth_required('token')
        
    def put(self):
        data = request.get_json()
        update_data = test.query.filter_by(id=data['id']).first()
        update_data.name = data['name']
        update_data.age = data['age']
        db.session.commit()
        return {"msg": 'Data updated', "name": f'{update_data.name}', "age": f'{update_data.age}'}

    @auth_required('token')
     
    def delete(self):
        data = request.get_json()
        delete_data = test.query.filter_by(id=data['id']).first()
        db.session.delete(delete_data)
        db.session.commit()
        return {"msg": 'Data deleted', "name": f'{delete_data.name}', "age": f'{delete_data.age}'}