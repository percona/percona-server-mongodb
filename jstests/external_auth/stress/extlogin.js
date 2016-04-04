// external login stress test

// we are going to check all of these accounts

var accounts = [
  "exttestro",
  "exttestrw",
  "extotherro",
  "extotherrw",
  "extbothro",
  "extbothrw",
  "exttestrwotherro",
  "exttestrootherrw"
];

var passSuffix='9a5S';

// iterate over all of the accounts
var count = 0;

// login and logout forever
//
while (true) {

  for (var i in accounts) {

    account = accounts[i];

    strUser=account;
    strPassword=account+passSuffix;

    db.getSiblingDB( '$external' ).auth({
      user: strUser,
      pwd: strPassword,
      mechanism: 'PLAIN',
      digestPasswd: false
    });

    count++;

    db.logout();

  }

}
