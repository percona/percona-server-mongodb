// name: Add Local Users
// mode: auth
// sequence: 10 

db = db.getSiblingDB( 'admin' )

assert( db.auth( 'localadmin' , 'localadmin9a5S' ) )

// user counters
var localtest=0
var localother=0

// localtestro has only read on test database
db.getSiblingDB( 'test' ).createUser({
  user: 'localtestro',
  pwd: 'localtestro9a5S',
  roles: [ 'read' ] 
})
localtest++;

// localtestrw has create and write on test database
db.getSiblingDB( 'test' ).createUser({
  user: 'localtestrw',
  pwd: 'localtestrw9a5S',
  roles: [ 'readWrite' ]
})
localtest++;

// localotherro has read on other database
db.getSiblingDB( 'other' ).createUser({
  user: 'localotherro',
  pwd: 'localotherro9a5S',
  roles: [ 'read' ]
})
localother++;

// localotherrw has 
db.getSiblingDB( 'other' ).createUser({
  user: 'localotherrw',
  pwd: 'localotherrw9a5S',
  roles: [ 'readWrite' ]
})
localother++

// display users from test database

print( 'test database:' )
print( '--------------' )

var findtest=0
db.getSiblingDB( 'admin' ).system.users.find(
  { '$and': [
    { user: /local.*/ },
    { roles: { '$elemMatch': {db: 'test'} } } ]
  }).forEach(
    function(u) {
      print( "user: " + u.user );
      findtest++;
    }
)
assert ( localtest == findtest )

// display users from other database

print( '' )
print( 'other database:' )
print( '--------------' )

var findother=0
db.getSiblingDB( 'admin' ).system.users.find(
  { '$and': [
    { user: /local.*/ },
    { roles: { '$elemMatch': {db: 'other'} } } ]
  }).forEach(
    function(u) {
      print( "user: " + u.user );
      findother++;
    }
)
assert ( localother == findother )

