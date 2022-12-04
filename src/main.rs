use std::env;
use ipgeolocate::{Locator, Service};
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

#[derive(Debug, Serialize, Deserialize)]
struct RemoteIp {
    ip: String,
}

async fn get_local_ip(buff: &mut String) {
    let req = reqwest::Client::new().get("https://api.ipify.org/?format=json").send().await.expect("one").json::<RemoteIp>().await.expect("two");

    buff.push_str(&req.ip);
}

async fn get_geoloc(ip: String) {
    match Locator::get(&ip, Service::IpApi).await {
        Ok(ip) => {
            println!("\n  Geolocation:");
            println!("      |-- Region: {}", ip.region);
            println!("      |-- Country: {}", ip.country);
            println!("      |-- City: {}", ip.city);
            println!("      |-- Lat&Long: {}, {}", ip.latitude, ip.longitude);
            println!("      |-- Timezone: {}", ip.timezone);
        },
        _ => (),
    }
}

async fn print_data(data: IpData) {
    println!("  ip: {}", data.ip);
    get_geoloc(data.ip).await;

    println!("\n  ports:");
    for n in data.ports.iter() {
        println!("      |-- {}", n);
    }
    println!("\n  hostnames:");
    for n in data.hostnames.iter() {
        println!("      |-- {}", n);
    }

    println!("\n  tags:");
    for n in data.tags.iter() {
        println!("        |-- {}", n);
    }

    println!("\n  cpes:");
    for n in data.cpes.iter() {
        println!("      |-- {}", n);
    }

    println!("\n  vulnerabilities:");
    for n in data.vulns.iter() {
        println!("      |-- {} (https://nvd.nist.gov/vuln/detail/{})", n, n);
    }
}

#[tokio::main]

async fn main() -> Result<(), reqwest::Error> {
    let args: Vec<String> = env::args().collect();

    let arg_len: usize = env::args().len();

    if arg_len <= 2 {
        let mut ip = String::new();
        get_local_ip(&mut ip).await;

        if arg_len == 2 { ip = String::from(&args[1]); };

        println!("{}", ip);

        let query_string: String = format!("https://internetdb.shodan.io/{ip}");
        let fetched_data = reqwest::Client::new().get(query_string).send().await?;

        match fetched_data.status() {
            reqwest::StatusCode::OK => {
                print_data(fetched_data.json::<IpData>().await?).await;
            },
            _ => println!("[ip-check] Failed to send request, no data available or invalid IP")
        }
    }
    else {
        println!("Usage `ip-check <ip>`");
    }
    Ok(())
}
