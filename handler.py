try:
  import unzip_requirements
except ImportError:
  pass

import requests
import yaml
import os
import json
import logging
import time

# from modules import *
from datetime import timedelta, datetime as dt
from validator import Validator, validate
from jose import jwt
DOMAIN = os.environ.get("DOMAIN")
SECRETKEY = os.environ.get("SECRETKEY")

logger = logging.getLogger("handler_logger") 
logger.setLevel(logging.DEBUG)
JWT_SECRET = os.environ.get("JWT_SECRET")

def temp_function(event, context):
    body = _get_event_body(event)
    body['type'] = 'echoReply'

    #verify & decode Abaxx ID
    id_token = verify_token(body['token'])
    #Decoded data from token AbaxxID Identity and username
    identity = id_token['sub']
    role = 'clearing_super_user'
  
    #Create New Token with Scope
    internalToken = encodeInternalToken(identity,role, 'admin:admin')

    response = {
        "statusCode": 200,
        "body": json.dumps({ 
            "internal_token": internalToken
        })
    }
    return response
  
#send in a token, looks up user, and returns a token with user scope
def auth(event, context):
    
    body = _get_event_body(event)
    body['type'] = 'echoReply'
    

    #verify & decode Abaxx ID
    id_token = verify_token(body['token'])
   
    #Decoded data from token AbaxxID Identity and username
    identity = id_token['data']['signature']
    user = 'MOPS4'

    #create session in Envoy
    envoyToken = envoyLogin()
    
    #check to see if User Exists
    cinnoberUser = getCinnoberUser(envoyToken, user)
    # print(cinnoberUser)
    #get Cinnober Roles:
    if cinnoberUser is not None:
        roles = getCinnoberRoles(cinnoberUser)
        print(roles)
        
        # #get or create userByIdentity
        getOrCreateUserbyIdentity(cinnoberUser, identity)

        #for each role get all scope
        userScopes = []
        for role in roles:
            #look up role by Name
            # print(role)
            role_id = getRolebyName(role.lower())
            # print(role_id)
            #looks up to see if that role Exists
            scope = getRoleScopebyRole(role_id)
            if scope not in userScopes: 
                userScopes.extend(scope) 
        
        #create unique Scope
        uniqueScope = _unique(userScopes)
        
        print(uniqueScope)

        #Create New Token with Scope (oooOOooOO)
        internalToken = encodeInternalToken(identity,roles, uniqueScope)
        #return Token
        response = {
        "statusCode": 200,
        "headers": {
        'Access-Control-Allow-Origin' : '*',
        'Access-Control-Allow-Headers':'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Credentials' : 'true',
        'Content-Type': 'application/json'
         },
        "body": json.dumps({ 
            "token": internalToken
        })
        }

    else:
        # Generate a PENDING scope token
        internalToken = encodeInternalToken(identity,'pending', 'pending:pending' )
        response = {
        "statusCode": 200,
        "headers": {
        'Access-Control-Allow-Origin' : '*',
        'Access-Control-Allow-Headers':'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Credentials' : 'true',
        'Content-Type': 'application/json'
         },
        "body": json.dumps({ 
            "token": internalToken
        })
        }

    return response
    # body = {
    #     "message": "Go Serverless v1.0! Your function executed successfully!",
    #     "input": event
    # }


    # users = User.select()
    # roles = Role.select()
    # scope = Scope.select()
    # rolseScope = RoleScope.select()
    # userRoleScope = UserRoleScope.select()

    # print('users', users)
    # print('roles', roles)
    # print('scope', scope)
    # print('rolseScope', rolseScope)
    # print('userRoleScope', userRoleScope)


    

    # Use this code if you don't use the http event with the LAMBDA-PROXY
    # integration
    """
    return {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "event": event
    }
    """

def getCinnoberRoles(user):
    print(user['rolesList'])
    userRoles = user['rolesList'].split(",")
    return userRoles

def encodeInternalToken(identity, roles, scope):
    signed = jwt.encode({
       'exp':  dt.utcnow() + timedelta(days=1, seconds=0),
       'data': 'signature',
       'sub': identity,
       'scope': roles,
       'permissions': scope,
       'iss': DOMAIN
     }, SECRETKEY, algorithm='HS256')
    return signed


#login to the envoy syetem
def envoyLogin():
    url = 'https://middleware.abaxx.exchange/envoy/v1/auth/login'
    payload = {'user': os.environ.get("SYSTEM_USER"),
             'password': os.environ.get("SYSTEM_PASSWORD"),
              'member': os.environ.get("SYSTEM_MEMBER") }
    
    res = requests.post(url, json=payload)
    response_json = res.json()
    return response_json['token']

def getCinnoberUser(token, user):
    url = 'https://middleware.abaxx.exchange/envoy/v1/users/' + user
    headers = {'X-Token': token}
    res = requests.get(url,  headers=headers)
    response_json = res.json()
    if res.status_code == 200:
        return response_json
    else:
        return None


# used to verify the incoming token
def verify_token(token):
    print(token)
    try:  # to validate the jwt
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
        print("token validated successfully")
        return payload
    except jwt.ExpiredSignatureError:
        print("Token is expired")
        raise Exception('Unauthorized')
    except jwt.JWTClaimsError:
        print("Token has invalid claims")
        raise Exception('Unauthorized')
    except Exception:
        print("Unable to parse token")
        raise Exception('Unauthorized')

def users(event, context):

    try:    
      request = json.dumps(event["httpMethod"])

      if json.loads(request) == 'POST':

          d = '{:03.0f}'.format(dt.utcnow().timestamp())
          data = json.loads(event["body"])

          #set initial role to pending:
        #   user = getOrCreateUserbyIdentity(data)

          #then create USER_ROLE_SCOPE
          userRoleScope = getOrCreateUserRoleScopebyUser(user)

          #then GET all userRoleScope for that user

        #   print(userRoleScope, 'here')

                
          response = {
              "statusCode": 200,
              "body": json.dumps({
                'id': str(user),
                'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
              })
          }
          return response

      elif json.loads(request) == 'GET':

          users = User.select()
          u = []
          for user in users:
              u.append({'email': user.email, 'id': str(user.id), 'created': user.created.strftime('%Y-%m-%d')})
          
          response = {
              "statusCode": 200,
              "body": json.dumps({
                'users': u,
                'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
              })
          }
          return response

    except Exception as e:
      response = {
          "statusCode": 400,
          "body": json.dumps({
            'error': str(e),
            'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
          })
      }
      return response

#takes a user and role and creates the association.
def members(event, context):
    try:
      request = json.dumps(event["httpMethod"])

      if json.loads(request) == 'POST':

          d = '{:03.0f}'.format(dt.utcnow().timestamp())
          data = json.loads(event["body"])

          member = Member(
              username=data["username"],
              password=data["password"],
              identity=data["identity"],
              name=data["name"]
          )
          member.save()

          response = {
              "statusCode": 200,
              "body": json.dumps({
                'id': str(member),
                'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
              })
          }
          return response

      elif json.loads(request) == 'GET':

          members = Member.select()
          m = []
          for member in members:
              m.append({'identity': member.identity, 'id': str(member.id), 'created': member.created.strftime('%Y-%m-%d')})
          
          response = {
              "statusCode": 200,
              "body": json.dumps({
                'users': m,
                'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
              })
          }
          return response

    except Exception as e:
      response = {
          "statusCode": 400,
          "body": json.dumps({
            'error': str(e),
            'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
          })
      }
      return response

#used initially to seed database with roles, and scopes
def init(event, context):
    _generate_scope()
    _generate_roles()
    _generate_role_scope()

    response = {
             "statusCode": 200,
              "body": json.dumps({
                'users': 'user',
                'timestamp': '{:03.0f}'.format(dt.utcnow().timestamp()) 
              })
        }
    return response

#takes a Rolename, and User Identity, and action
#checks if user has associated role in userRoles
#Generate UserRoleScope for each userRole --Default enabled

def updateUserRole(event, context):
    print('foo')

def getRoleScopebyRole(role):

    #return ARRAY
    s = []
    roleScope = RoleScope.select().where(RoleScope.role_id == role)
    for scopes in roleScope:
        # s.append({'scope_id': scopes.scope.id, 'roleScope': scopes.id, 'scope_name': scopes.scope.scopename})
        s.append(scopes.scope.scopename)
        # print(scopes, scopes.scope.scopename)
    return s

#gets the user by unique Identity or Creates a user with default 'pending' role
def getOrCreateUserbyIdentity(userInput, identity):
    try:
        user = User.get(
            (User.identity == identity))
        return user
    except User.DoesNotExist:
        user = User.create(
              member_id=userInput["memberId"],
              username=userInput["userId"],
              firstName=userInput["firstName"],
              lastName=userInput["lastName"],
              email=userInput["emailAddress"],
              phone=userInput["phoneNumber"],
              identity=identity)

    return user

def getRolebyName(name):
    role = Role.get(Role.rolename == name)
    return role
  
def getOrCreateUserRoles(role, user):
    userRole = UserRole.get_or_create(user_id=user, role_id=role)
    return userRole
   
#takes in user and UserRoleScope Array
def getOrCreateUserRoleScopebyUser(user):
    #get all UserRoles
    userRoles = UserRole.select().where(UserRole.user_id == user )
    userScopes = []
    for roles in userRoles:
        #gets all scope associated to that role.
        scope = getRoleScopebyRole(roles.role)
        userScopes.extend(scope)

    # uniqueScopeList = userScopes(set(uniqueScopeList))
    # unique_scope= list(set(userScopes))
    # print(unique_numbers)
    # print( userScopes)

    #for each user scope associate it with userRoleScope
    for userRoleScope in userScopes:
        createUserRoleScope(user, userRoleScope['roleScope'] )

def createUserRoleScope(user, roleScope):
    UserRoleScope.get_or_create(roleScope=roleScope, user=user)

def deleteRole(role):
    print('delete all scopes roles and all roleScope and userRoleScope')

def deleteScope(scopeName):
    print('deletes scope form all roleScope and UserRoleScope')

def deleteUser(user):
    print('deletes user and all userRoleScope')

def deleteUserRole(username):
    print('deletes all userroles and user role scope for that user')

def deleteUserRoleScope(user, role):
    print('UserRoleScope')

#looks up from the role_scope.yaml and associates the scope to the ROLES.
def _generate_role_scope():
    with open('./data/role_scope.yaml') as f:
        docs = yaml.load_all(f, Loader=yaml.FullLoader)
        for doc in docs:
            for r, s in doc.items():
                # print(r, "->", s)
                try:
                    roles = Role.get(Role.rolename == r)
                    for roleScope in s:
                        scopes = Scope.get(Scope.scopename == roleScope)
                        print(scopes, roles)
                        RoleScope.get_or_create(scope_id=scopes, role_id=roles)
                except :
                    raise ValueError('No instance of Role exists at {}'.format(r))

def _generate_roles():
    with open('./data/role.json') as json_file:
        data = json.load(json_file)
        for item in data:
            
            role = Role(
              rolename=item['role'],
              description=item['description']
            )
            role.get_or_create(rolename=item['role'],
              description=item['description'])
            print(item['role'], item['description'] )

def _generate_scope():
    with open('./data/scope.json') as json_file:
        data = json.load(json_file)
        # print(data)
        for item in data:
            
            scopes = Scope(
              scopename=item['name'],
              description=item['description']
            )
            scopes.get_or_create(scopename=item['name'],
              description=item['description'])
            print(item['name'], item['description'] )
                # scope.save()
            # scope = Scope(
            #   scope=item['scope'],
            #   description=item['description']
            # )
                # scope.get_or_create(scope=item['scope'], description=item['description'])


            
    # print(data)

def _get_event_body(event):
    try:
        return json.loads(event.get("body", ""))
    except ValueError:
        print("event body could not be JSON decoded.")
        return {}

# function to get unique values 
def _unique(list): 
  
    # intilize a null list 
    unique_list = [] 
      
    # traverse for all elements 
    for x in list: 
        # check if exists in unique_list or not 
        if x not in unique_list: 
            unique_list.append(x) 
    return unique_list
        