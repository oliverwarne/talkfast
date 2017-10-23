use super::schema::users;

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub name: &'a str,
    pub crypto_key: &'a str,
}

#[derive(Queryable,Debug,Clone)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub crypto_key: String,
}
