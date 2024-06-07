from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage, query
import requests
import json
import io
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client(project='a6-tarpaulin', database='tarpaulin')

USERS = "users"
PHOTO_BUCKET = 'a6_tarpaulin_vu'
PHOTOS = 'photos'
COURSES = 'courses'

# Update the values of the following 3 variables
CLIENT_ID = 'WFeVPNKdMv6sBh1EGFSpiO47fSFJFYJq'
CLIENT_SECRET = 'J7_s-QpcFGt01gMRp12kP34OdBmNY3x8jMgwMryV9lz188P5Ms7KCCiAv_zVtEvJ'
DOMAIN = 'dev-qsk3xmthsv2vlq24.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /businesses to use this API"\



# Generate a JWT for a registered user of the app and return the token
@app.route('/' + USERS + "/login", methods=['POST'])
def users_post():
    content = request.get_json()
    if len(content.keys()) != 2 or 'username' not in content or 'password' not in content:
        return {"Error": "The request body is invalid"}, 400

    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }

    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    if r.status_code == 200:
        response = r.json()
        return {'token': response['id_token']}, 200, {'Content-Type': 'application/json'}
    else:
        return {'Error': 'Unauthorized'}, 401


# GET all users. Summary information of all 9 users
@app.route('/' + USERS, methods=['GET'])
def get_users():
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    query.add_filter('role', '=', 'admin')
    results = list(query.fetch())
    if not results:
        return {"Error": "You don't have permission on this resource"}, 403

    query2 = client.query(kind=USERS)
    results2 = list(query2.fetch())
    for r in results2:
        r['id'] = r.key.id

    return results2


# GET user by ID
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_user(id):
    pass


# Create/Update a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['POST'])
def create_avatar(id):
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return {"Error": "The request body is invalid"}, 400

    # validate jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # validate that jwt belongs to user_id in path
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    results = list(query.fetch())
    for user in results:
        if user.key.id != id:
            return {"Error": "You don't have permission on this resource"}, 403

    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # Create a storage client
    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)

    # Store photo information in Datastore
    new_photo = datastore.Entity(key=client.key(PHOTOS))
    new_photo.update({
        'user_id': id,
        'name': file_obj.filename,
    })
    client.put(new_photo)

    return {'avatar_url': request.scheme + '://' + request.host + '/users/' + str(id) + '/avatar'}, 200


# GET a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['GET'])
def get_avatar(id):
    # validate jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # validate that jwt belongs to user_id in path
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    results = list(query.fetch())
    for user in results:
        if user.key.id != id:
            return {"Error": "You don't have permission on this resource"}, 403

    # Search for user's avatar using user ID
    query = client.query(kind=PHOTOS)
    query.add_filter('user_id', '=', id)
    results = list(query.fetch())
    if not results:
        return {"Error": "Not found"}, 404

    storage_client = storage.Client()
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(results[0]['name'])
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)

    return send_file(file_obj, mimetype='image/png'), 200


# DELETE a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['DELETE'])
def delete_avatar(id):
    # validate jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # validate that jwt belongs to user_id in path
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    results = list(query.fetch())
    for user in results:
        if user.key.id != id:
            return {"Error": "You don't have permission on this resource"}, 403

    # Search for user's avatar using user ID
    query = client.query(kind=PHOTOS)
    query.add_filter('user_id', '=', id)
    results = list(query.fetch())
    print(results)
    if not results:
        return {"Error": "Not found"}, 404
    storage_client = storage.Client()

    # Get a handle on the bucket
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(results[0]['name'])
    blob.delete()
    return '', 204


@app.route('/' + COURSES, methods=['POST'])
def create_courses():
    # validate jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # make sure JWT belongs to an admin
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    query.add_filter('role', '=', 'admin')
    results = list(query.fetch())
    if not results:
        return {"Error": "You don't have permission on this resource"}, 403

    # make sure request body is valid
    content = request.get_json()
    if len(content) < 5:
        return {"Error": "The request body is invalid"}, 400

    # retrieve user entity and check if instructor
    user_key = client.key(USERS, content['instructor_id'])
    user = client.get(key=user_key)
    if user is None:
        return {"Error": "The request body is invalid"}, 400
    elif user['role'] != 'instructor':
        return {"Error": "The request body is invalid"}, 400

    new_course = datastore.Entity(key=client.key(COURSES))
    new_course.update({
        'subject': content['subject'],
        'number': content['number'],
        'title': content['title'],
        'term': content['term'],
        'instructor_id': content['instructor_id']
    })
    client.put(new_course)

    new_course['id'] = new_course.key.id
    new_course['self'] = request.scheme + '://' + request.host + '/courses/' + str(new_course.key.id)

    return (new_course, 201)


@app.route('/' + COURSES, methods=['GET'])
def get_courses():
    # retrieve limit and offset from url
    limit = request.args.get('limit', default=3, type=int)
    offset = request.args.get('offset', default=0, type=int)

    # implement pagination and order by
    query = client.query(kind=COURSES)
    query.order = ['subject']

    # returns an iterator
    course_iterator = query.fetch(limit=limit, offset=offset)
    pages = course_iterator.pages
    results = list(next(pages))

    # add id and self then remove enrollment from courses
    for course in results:
        course['id'] = course.key.id
        course['self'] = request.scheme + '://' + request.host + '/courses/' + str(course.key.id)

    return {'courses': results,
            'next': request.scheme + '://' + request.host + '/courses?offset=' + str(offset + limit) + '&limit=' + str(limit)}


@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)
    if course is None:
        return {"Error": "Not found"}, 404
    else:
        course['id'] = course.key.id
        course['self'] = request.scheme + '://' + request.host + '/courses/' + str(course.key.id) 
        return course


@app.route('/' + COURSES + '/<int:id>', methods=['PATCH'])
def update_course(id):
    # validate jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # make sure JWT belongs to an admin
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    query.add_filter('role', '=', 'admin')
    results = list(query.fetch())
    if not results:
        return {"Error": "You don't have permission on this resource"}, 403

    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    if course is None:
        return {"Error": "You don't have permission on this resource"}, 403

    content = request.get_json()

    if 'subject' in content:
        course['subject'] = content['subject']

    if 'number' in content:
        course['number'] = content['number']

    if 'title' in content:
        course['title'] = content['title']

    if 'term' in content:
        course['term'] = content['term']

    if 'instructor_id' in content:
        user_key = client.key(USERS, content['instructor_id'])
        user = client.get(key=user_key)

        if user is None:
            return {"Error": "The request body is invalid"}, 400
        elif user['role'] != 'instructor':
            return {"Error": "The request body is invalid"}, 400

        course['instructor_id'] = content['instructor_id']

    client.put(course)
    course['id'] = course.key.id
    course['self'] = course['self'] = request.scheme + '://' + request.host + '/courses/' + str(course.key.id)

    return course


@app.route('/' + COURSES + '/<int:id>', methods=['DELETE'])
def delete_course(id):
    pass


@app.route('/' + COURSES + '/<int:id>' + '/students', methods=['PATCH'])
def update_enrollment(id):
    # validate jwt
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401

    # make sure JWT belongs to an admin or course instructor 
    query = client.query(kind=USERS)
    query.add_filter('sub', '=', payload['sub'])
    # query.add_filter('role', '=', 'admin')
    results = list(query.fetch())
    if not results:
        return {"Error": "You don't have permission on this resource"}, 403
    elif results[0].key.id != id and results[0]['role'] != 'admin':
        return {"Error": "You don't have permission on this resource"}, 403
    
    # retrieve course and validate existence
    course_key = client.key(COURSES, id)
    course = client.get(course_key)
    if course is None:
        return {"Error": "You don't have permission on this resource"}, 403

    # validate request 
    content = request.get_json()

    # separate arrays
    course_enroll = content[0]
    course_unenroll = content[1]

    # check if userID appears in both arrays
    for user_id in course_enroll:
        if user_id in course_unenroll:
            return {"Error": "Enrollment data is invalid"}, 409
        
    # check if IDs belong to students then enroll
    for user_id in course_enroll:
        user_key = client.key(USERS, user_id)
        user = client.get(user_key)

        if user is None or user['role'] != 'student':
            return {"Error": "Enrollment data is invalid"}, 409
        
        if id in user_id['courses']:
            continue
        
        # handle whether the user has courses property yet 
        if 'courses' in user:
            if isinstance(user['courses'], list):
                user['courses'].append(id)
                print(user['courses'])
            else:
                user['courses'] = [id]
                print(user['courses'])

    # check if IDs belong to students then unenroll
    for user_id in course_unenroll:
        user_key = client.key(USERS, user_id)
        user = client.get(user_key)
        if user is None or user['role'] != 'student':
            return {"Error": "Enrollment data is invalid"}, 409
        if id in user_id['courses']:
            continue
        
        # handle whether the user has courses property yet 
        if 'courses' in user:
            if isinstance(user['courses'], list):
                user['courses'].remove(id)
                print(user['courses'])
            else:
                continue

    return 


@app.route('/' + COURSES + '/<int:id>' + '/students', methods=['GET'])
def get_enrollment(id):
    pass


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)