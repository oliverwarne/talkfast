use diesel::prelude::*;
use diesel;
use dotenv::dotenv;
use std::env;

use super::schema;
use super::models::*;


pub fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    SqliteConnection::establish(&database_url).expect(&format!(
        "Error connecting to {}",
        database_url
    ))
}

pub fn show_users() {
    use schema::users::dsl::*;

    let connection = establish_connection();
    let results = users
        .limit(5)
        .load::<User>(&connection)
        .expect("Error loading posts");

    println!("Displaying {} users", results.len());
    for user in results {
        print!("{} is ", user.id);
        println!("{}", user.name);
    }
}

pub fn create_user<'a>(name: &'a str, key: &'a str) {
    use schema::users;
    let connection = establish_connection();

    let new_user = NewUser {
        name: name,
        crypto_key: key,
    };

    diesel::insert(&new_user).into(users::table)
            .execute(&connection)
            .expect("Error saving post");
}

pub fn get_key<'a>(name: &'a str) {
    let connection = establish_connection();

    use schema::users::dsl::*;

    let results = users
        .filter(name.eq(name))
        .load::<User>(&connection)
        .expect("Error loading users");

    for i in results {
        println!("{:?}", i);
    }
}
