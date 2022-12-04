use std::env;
use exitfailure::ExitFailure;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]

struct IpData {
    cpes: Vec<String>,
    hostnames: Vec<String>,
    ip: String,
    ports: Vec<i32>,
    tags: Vec<String>,
    vulns: Vec<String>,
}

fn print_data(data: IpData) {
    println!("    ip: {}", data.ip);
    println!("\n    ports:");
    for n in data.ports.iter() {
        println!("        |-- {}", n);
    }
    println!("\n    hostnames:");
    for n in data.hostnames.iter() {
        println!("        |-- {}", n);
    }

    println!("\n    tags:");
    for n in data.tags.iter() {
        println!("        |-- {}", n);
    }

    println!("\n    cpes:");
    for n in data.cpes.iter() {
        println!("        |-- {}", n);
    }

    println!("\n    vulnerabilities:");
    for n in data.vulns.iter() {
        println!("        |-- {} (https://nvd.nist.gov/vuln/detail/{})", n, n);
    }
}

#[tokio::main]

async fn main() -> Result<(), ExitFailure> {
    let args: Vec<String> = env::args().collect();

    let arg_len: usize = env::args().len();

    if arg_len == 2 {
        let ip: &String = &args[1];
        let query_string: String = format!("https://internetdb.shodan.io/{ip}");
        let fetched_data = reqwest::Client::new().get(query_string).send().await?;

        match fetched_data.status() {
            reqwest::StatusCode::OK => {
                print_data(fetched_data.json::<IpData>().await?);
            },
            _ => {println!("Failed to send request, most likely invalid IP");}
        }
    }
    else {
        println!("Usage `ip-check <ip>`");
    }
    Ok(())
}
