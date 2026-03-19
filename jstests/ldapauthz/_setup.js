// Utility to create 'root' user on a mongod instance.
// Used by tests that need a local admin user (e.g., for setParameter).

export function createAdminUser(conn) {
    var db = conn.getDB("admin");
    db.createUser({
        user: "admin",
        pwd: "password",
        roles: ["root"],
    });
}
