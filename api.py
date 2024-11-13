from flask import Flask
from flask_restful import Resource, Api
from app import app
from models import db, User

api = Api(app)

class UserResource(Resource):
    def get(self):
        users = User.query.all()
        return {'users':[{
                        'id': user.id, 
                        'name': user.username   
                }for user in users]
                }
    
api.add_resource(UserResource,'/api/user')