#[macro_use]
extern crate magic_crypt;

use magic_crypt::{MagicCrypt64, MagicCryptTrait};
use postgres::{Client, NoTls};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
enum Cli {
    #[structopt(about = "Save Password")]
    Save {
        provider: String,
        email: String,
        pass: String,
        secret_key: String,
    },
    #[structopt(about = "Get Password")]
    Get {
        provider: String,
        email: String,
        secret_key: String,
    },
}

// struct Error(String);
fn main() -> Result<(), postgres::Error> {
    let cli: Cli = Cli::from_args();
    println!("\u{001b}[32mConnecting To Database \u{001b}[0m------------");
    let mut client = Client::connect(
        "host=localhost port=5432 user=postgres dbname=sam password=Smile31@",
        NoTls,
    )?;
    println!("\u{001b}[32mConnected Successfully \u{001b}[0m------------");
    let pass: (String, bool) = match cli {
        Cli::Save {
            provider,
            email,
            secret_key,
            pass,
        } => (
            save_pass(&provider, &email, &pass, &secret_key, &mut client),
            true,
        ),
        Cli::Get {
            provider,
            email,
            secret_key,
        } => (get_pass(&provider, &email, &secret_key, &mut client), false),
    };
    if pass.1 {
        println!("\u{001b}[34mYour Password Saved:\u{001b}[m {}", pass.0);
    } else {
        println!("\u{001b}[34mYour Password:\u{001b}[m {}", pass.0);
    }
    Ok(())
}

fn save_pass(
    provider: &String,
    email: &String,
    pass: &String,
    secret_key: &String,
    client: &mut Client,
) -> String {
    let mc: MagicCrypt64 = new_magic_crypt!(secret_key, 64);
    let encrypted_pass = mc.encrypt_str_to_base64(pass);
    let create_query = "CREATE TABLE  IF NOT EXISTS pass_table 
    (
        id SERIAL PRIMARY KEY,
        email varchar(25) NOT NULL,
        pass varchar(30) NOT NULL,
        provider varchar(20) NOT NULL,
    )";
    let insert_query = "INSERT INTO pass_table(email,pass,provider) values($1,$2,$3)";
    client
        .execute(create_query, &[])
        .expect("Error In Create Query\n");
    client
        .execute(insert_query, &[email, &encrypted_pass, provider])
        .expect("Error in Insert Query\n");
    encrypted_pass
}

fn get_pass(provider: &String, email: &String, secret_key: &String, client: &mut Client) -> String {
    println!("\u{001b}[32mGetting Password \u{001b}[0m-------");
    let mc: MagicCrypt64 = new_magic_crypt!(secret_key, 64);
    let query = "SELECT pass FROM pass_table WHERE email = $1 and provider= $2";
    let result = &client.query(query, &[email, provider]).expect("");
    if result.is_empty() {
        panic!("No Email Found!!");
    }
    let row = &result[0];
    let pass: String = row.get(0);
    mc.decrypt_base64_to_string(pass)
        .expect("Invalid Secret Key")
}
