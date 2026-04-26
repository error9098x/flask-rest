from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import sqlite3
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)
api = Api(app)

# Vulnerability 1: SQL Injection
class UserResource(Resource):
    def get(self, user_id):
        conn = sqlite3.connect('api.db')
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE id = ?"
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        conn.close()
        return {'user': result}

# Vulnerability 2: Missing authorization
class AdminResource(Resource):
    def delete(self, user_id):
        conn = sqlite3.connect('api.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return {'message': 'Deleted'}

# Vulnerability 3: XXE - unsafe XML parsing
class XMLResource(Resource):
    def post(self):
        xml_data = request.data
        tree = ET.fromstring(xml_data)
        return {'parsed': tree.tag}

# Vulnerability 4: SSRF - unvalidated URL fetching
class FetchResource(Resource):
    ALLOWED_SCHEMES = {'http', 'https'}
    ALLOWED_HOSTS = {'example.com', 'api.example.com'}

    def get(self):
        url = request.args.get('url')
        parsed = requests.utils.urlparse(url)
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            return {'error': 'Invalid URL scheme'}, 400
        if parsed.hostname not in self.ALLOWED_HOSTS:
            return {'error': 'Invalid URL host'}, 400
        response = requests.get(url)
        return {'content': response.text}

api.add_resource(UserResource, '/users/<user_id>')
api.add_resource(AdminResource, '/admin/users/<user_id>')
api.add_resource(XMLResource, '/parse')
api.add_resource(FetchResource, '/fetch')

if __name__ == '__main__':
    app.run(debug=False)
