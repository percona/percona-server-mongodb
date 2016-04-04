// name: Local user login 
// mode: auth
// sequence: 30 

db = db.getSiblingDB( 'test' )

assert(
  db.auth({
    user: 'localtestro',
    pwd: 'localtestro9a5S'
  })
)
