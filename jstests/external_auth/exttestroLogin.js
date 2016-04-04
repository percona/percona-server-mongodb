// name: External user login 
// mode: auth
// sequence: 35 

assert(
  db.getSiblingDB('$external').auth({
    user: 'exttestro',
    pwd: 'exttestro9a5S',
    mechanism: 'PLAIN',
    digestPasswd: false
  })
)

