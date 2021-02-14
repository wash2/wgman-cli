#[macro_use] extern crate prettytable;

use std::{fs::OpenOptions, path::Path, vec};
use std::path::PathBuf;
use std::io::{self, Read, stdin, BufReader};
use std::io::prelude::*;
use std::fs;

use types::*;
use wgman_core::types;
use structopt::StructOpt;
use prettytable::{Table};
use reqwest::{Response, StatusCode, header::AUTHORIZATION};
use futures::executor::block_on;
use ipnetwork::IpNetwork;
use serde::{Deserialize, de::DeserializeOwned};

macro_rules! printdbg {
    ($dbg_enabled:expr, $fmt:expr) => { if $dbg_enabled { (println!($fmt)); } };
    ($dbg_enabled:expr, $fmt:expr, $($arg:tt)*) => { if $dbg_enabled { (println!($fmt, $($arg)*)); } };
}

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "wgmancli", about = "Wgman cli StructOpt.")]
struct Opt {
    /// Activate verbose mode
    #[structopt(short, long)]
    verbose: bool,
    
    // Use `env` to enable specifying the option with an environment
    // variable. Command line arguments take precedence over env.
    /// URL for the API server
    #[structopt(long, env="WGMAN_API_URL")]
    api_url: String,

    /// Activate admin authentication
    #[structopt(long, requires_all(&["admin-name", "admin-pw"]))]
    admin_auth: bool,
    
    // Use `env` to enable specifying the option with an environment
    // variable. Command line arguments take precedence over env.
    /// URL for the API server
    #[structopt(long, env = "WGMAN_API_ADMIN")]
    admin_name: Option<String>,

    // Use `env` to enable specifying the option with an environment
    // variable. Command line arguments take precedence over env.
    /// URL for the API server
    #[structopt(long, env = "WGMAN_API_ADMIN_PW")]
    admin_pw: Option<String>,

    /// Wireguard interface to manage
    #[structopt(short, long, required_unless("admin_auth"))]
    interface: Option<String>,

    /// Resource to interact with: (all, interface, peers, endpoints, admin)/(pw)
    /// eg: interface, interface/pw, admin/pw
    #[structopt(short = "r", long = "resource", default_value = "interface")]
    resource: String,

    /// Action to apply to resource: (list, push, pull, remove)
    #[structopt(short = "a", long = "action", default_value = "list")]
    action: String,

    /// Action to apply to resource: (list, push, pull, remove)
    #[structopt(short = "w", long = "wgman-dir", default_value = "/etc/wgman")]
    wgman_dir: PathBuf,

    /// Enable json input for the selected action
    #[structopt(long = "input-json")]
    input_json: bool,

    /// Input file, stdin if not present
    #[structopt(long, parse(from_os_str))]
    input: Option<PathBuf>,

    // /// Output file, stdout if not present
    // #[structopt(long, parse(from_os_str))]
    // output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run(Opt::from_args()).unwrap();

    Ok(())
}

fn run(opt: Opt) -> io::Result<()> {
    printdbg!(opt.verbose.clone(), "running cmd");
    let mut reader: Option<Box<dyn Read>> = match (&opt.input_json, &opt.input) {
        (false, _) => None,
        (true, None) => Some(Box::new(stdin())),
        (true, Some(i)) => Some(Box::new(fs::File::open(i)?))
    };
    let Opt { api_url, resource, action, .. } = &opt.clone();
    let client = reqwest::Client::new();
    printdbg!(opt.verbose.clone(), "getting auth");
    let auth_type = match &opt.admin_auth {
        true => "aauth",
        false => "iauth"
    };
    let auth = get_auth_header(&opt);
    match (resource.as_str(), action.as_str()) {
        ("confs", "get") => {
            let url = format!("http://{}/{}/interfaces/{}/configs", api_url, auth_type, &opt.interface.clone().unwrap());

            let config = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send()));
            
            interface_config_table(config).printstd();
        },
        ("confs", "list") => {
            let url = format!("http://{}/{}/configs", api_url, auth_type);

            let configs: Vec<ApiConfig> = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send()));
            
            for config in configs {
                interface_config_table(config).printstd();
            }
        },
        ("confs", "push") => {
            let conf = ApiConfig::from(load_interface_cfg(&opt));
            let url = format!("http://{}/{}/configs", api_url, auth_type);

            printdbg!(opt.verbose.clone(), "interface config push");
            interface_config_table(conf.clone());

            handle_response(opt.clone(), block_on(client
            .post(url.as_str())
            .json(&conf)
            .header(AUTHORIZATION, auth.clone())
            .send()));
            interface_config_table(conf);
        },
        ("confs", "pull") => {
            let url = format!("http://{}/{}/interfaces/{}/configs", api_url, auth_type, &opt.interface.clone().unwrap());

            let config = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send()));

            write_config(config, opt);
        },
        ("interfaces", "list") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/{}", api_url, auth_type, resource);
            printdbg!(opt.verbose.clone(), "{}", url.as_str());
            let interfaces = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send()));
            interfaces_table(interfaces).printstd();
        },
        ("interfaces", "get") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let interface_name = &opt.interface.clone().unwrap();
            let url = format!("http://{}/{}/{}/{}", api_url, auth_type, resource, interface_name);
            printdbg!(opt.verbose.clone(), "interfaces get {}", url.as_str());

            let interface: ApiInterface = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send()));
            interfaces_table(vec![interface]).printstd();

        },
        ("interfaces", "push") => {
            let url = format!("http://{}/{}/{}", api_url, auth_type, resource);
            printdbg!(opt.verbose.clone(), "interfaces push");
            let interface = get_interface(&opt, reader.as_mut());
            handle_response(opt.clone(), block_on(client
            .post(url.as_str())
            .json(&interface)
            .header(AUTHORIZATION, auth)
            .send()));
            dbg!(interface.clone().public_key.unwrap().len());
            // render_interfaces(vec![interface.clone()]);
        },
        ("interfaces", "remove") => {
            printdbg!(opt.verbose.clone(), "interface remove");
            let interface = get_interface(&opt, reader.as_mut());
            let url = format!("http://{}/{}/{}/{}", api_url, auth_type, resource, interface.u_name);
            printdbg!(opt.verbose.clone(), "interfaces remove {}", url.as_str());

            handle_response(opt.clone(), block_on(client
            .delete(url.as_str())
            .header(AUTHORIZATION, auth)
            .send()));
        },
        ("peer", "list") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/interfaces/{}/peers", api_url, auth_type,opt.interface.as_ref().unwrap());

            let peers: Vec<ApiPeerRelation> = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send()));

            peer_relation_table(peers).printstd();
        },
        ("endpoint", "list") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/interfaces/{}/endpoints", api_url, auth_type, opt.interface.as_ref().unwrap());

            let endpoints: Vec<ApiPeerRelation> = handle_json_response(opt.clone(), block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send()));

            peer_relation_table(endpoints).printstd();
        },
        ("peer-relation", "push") => {
            match &opt.admin_auth {
                false => println!("pushing peer-relations is only available with admin authentication."),
                true => {
                    let url = format!("http://{}/{}/{}", api_url, auth_type, resource);
                    printdbg!(opt.verbose.clone(), "peer_relation push");
                    let peer_relation: ApiPeerRelation = get_json_input(&opt, reader.as_mut().unwrap(), &mut String::new());
                    handle_response(opt.clone(), block_on(client
                    .post(url.as_str())
                    .json(&peer_relation)
                    .header(AUTHORIZATION, auth)
                    .send()));
                    peer_relation_table(vec![peer_relation.clone()]).printstd();
                }
            }
           
        },
        ("peer-relation", "remove") => {
            match &opt.admin_auth {
                false => println!("removing peer-relations is only available with admin authentication."),
                true => {
                    printdbg!(opt.verbose.clone(), "peer_relation remove");
                    let peer_relation: ApiPeerRelation = get_json_input(&opt, reader.as_mut().unwrap(), &mut String::new());
                    let url = format!("http://{}/{}/pr/remove/{}/{}", api_url, auth_type, peer_relation.endpoint_name.as_ref().unwrap(), peer_relation.peer_name.as_ref().unwrap());
        
                    handle_response(opt.clone(), block_on(client
                    .delete(url.as_str())
                    .header(AUTHORIZATION, auth)
                    .send()));
                    peer_relation_table(vec![peer_relation.clone()]).printstd();
                }
            }
        }, 
        ("admin", "remove") => {
            match &opt.admin_auth {
                false => printdbg!(opt.verbose.clone(), "removing admin users is only available with admin authentication."),
                true => {
                    match reader {
                        Some(mut reader) => {
                            let _admin: ApiAdmin = get_json_input(&opt, &mut reader, &mut String::new());

                            println!("Method unimplemented by API")
                        }
                        None => println!("removing admin users is only available with input."),
                    }
                }
            }
        },
        ("admin/pw", "push") => {
            match &opt.admin_auth {
                false => printdbg!(opt.verbose.clone(), "pushing admin user pw is only available with admin authentication."),
                true => {
                    match reader {
                        Some(mut reader) => {
                            let admin_pw: ApiAdminPassword = get_json_input(&opt, &mut reader, &mut String::new());
                            let url = format!("http://{}/{}/admins/passwords/", api_url, auth_type);

                            handle_response(opt.clone(), block_on(client
                                .post(url.as_str())
                                .json(&admin_pw)
                                .header(AUTHORIZATION, auth)
                                .send()));
                        }
                        None => println!("pushing admin user pw is only available with input."),
                    }
                }
            }
        },
        ("interface/pw", "push") => {
            match reader {
                Some(mut reader) => {
                    let interface_pw: ApiInterfacePassword = get_json_input(&opt, &mut reader, &mut String::new());
                    let url = format!("http://{}/{}/interfaces/passwords/", api_url, auth_type);
                    dbg!(url.clone());
                    handle_response(opt.clone(), block_on(client
                        .post(url.as_str())
                        .json(&interface_pw)
                        .header(AUTHORIZATION, auth)
                        .send()));
                }
                None => println!("pushing interface user pw is only available with input."),
            }
        },
        (resource, action) => {
            println!("Invalid action / resource combo: {} {}", action, resource);
            std::process::exit(1);
        }
    };
    Ok(())
}

fn get_auth_header(opt: &Opt) -> String {
    if opt.admin_auth {
        return BasicAuth{ name: opt.admin_name.as_ref().unwrap().to_string(), password: opt.admin_pw.as_ref().unwrap().to_string() }.to_string();
    }
    let mut auth = opt.wgman_dir.clone();
    auth.push(opt.interface.as_ref().unwrap().to_string());
    auth.push(Path::new("auth"));
    let mut file = fs::File::open(auth).expect("Something went wrong reading the password file");
    
    let mut password = String::new();
    file.read_to_string(&mut password).expect("could not read from input");

    BasicAuth { name: opt.interface.clone().unwrap(), password: password.trim().to_string() }.to_string()
}

fn load_interface_cfg(opt: &Opt) -> InterfaceConfig {
    printdbg!(opt.verbose.clone(), "loading interface conf");
    let mut conf_path = opt.wgman_dir.clone();
    let interface_name = opt.interface.as_ref().unwrap().to_string();
    conf_path.push(&interface_name);
    conf_path.push(Path::new(&format!("{}.conf", &interface_name)));
    let file = fs::File::open(conf_path).expect("Something went wrong reading the conf file");

    let mut conf = InterfaceConfig { interface: ApiInterface { u_name: String::new(), public_key: None, port: None, ip: None, fqdn: None }, peers: Vec::new()};
    conf.interface.u_name = interface_name;
    let mut cur_block = None;
    for line in BufReader::new(file).lines() {
        let l = line.expect("Something went wrong reading the password file");
        let l = l.trim();
        // ignore empty or commented lines
        if l.len() == 0 || l.chars().next().unwrap() == '#' {
            continue;
        }

        // Block identifiers
        if l == "[Interface]" {
            cur_block = Some(InterfaceConfigBlockKind::Interface);
            continue;
        }
        if l == "[Peer]" {
            cur_block = Some(InterfaceConfigBlockKind::Peer);
            conf.peers.push(InterfaceConfigPeer { public_key: String::new(), allowed_ip: Vec::new(), endpoint: None});
            continue;
        }

        // kv pairs
        let mut kv= l.splitn(2, "=");
        let k = kv.next().expect("Failed to parse password file.").trim();

        match cur_block {
            Some(InterfaceConfigBlockKind::Interface) => {
                let v = kv.next().expect("Failed to parse password file.").trim().to_string();
                match k {
                    "PrivateKey" => {},
                    "ListenPort" => conf.interface.port = Some(v.parse::<i32>().unwrap()),
                    "Address" => conf.interface.ip = Some(v.parse::<IpNetwork>().unwrap()),
                    _ => {
                        printdbg!(opt.verbose.clone(), "Warning: '{}' not recognized as key in [Interface]", k);
                    }
                };
            },
            Some(InterfaceConfigBlockKind::Peer) => {
                let v = kv.next().expect("Failed to parse password file.").trim().to_string();
                let cur_peer = conf.peers.last_mut().unwrap();
                match k {
                    // "NAME" => name = Some(v),
                    // "PASSWORD" => password = Some(v),
                    "PublicKey" => {
                        cur_peer.public_key = v;
                    },
                    "AllowedIPs" => {
                        cur_peer.allowed_ip = v
                        .split(", ")
                        .map(|s| s.parse::<IpNetwork>().unwrap())
                        .collect();
                    },
                    "Endpoint" => {
                        cur_peer.endpoint = Some(v);
                    },
                    _ => {
                        printdbg!(opt.verbose.clone(), "Warning: '{}' not recognized as key in [Peer]", k);
                    }                
                };
            },
            None => {
                printdbg!(opt.verbose.clone(), "Warning: '{}' not a valid config block, or not associated with a valid config block", k);
            }
        };
        
    }

    // get public key
    let mut pub_path = opt.wgman_dir.clone();
    let interface_name = opt.interface.as_ref().unwrap().to_string();
    pub_path.push(interface_name);
    pub_path.push(Path::new("pubkey"));
    let mut file = fs::File::open(pub_path).expect("Something went wrong reading the conf file");
    let mut pubkey = String::new();
    file.read_to_string(&mut pubkey).expect("failed to read the public key file");
    conf.interface.public_key = Some(pubkey.trim().to_string());

    // fqdn to be loaded from file somewhere as well?

    conf
}

fn get_interface(opt: &Opt, reader: Option<&mut Box<dyn Read>>) -> ApiInterface {
    if let Some(r) = reader {
        let mut in_buffer = String::new();
        r.read_to_string(&mut in_buffer).expect("could not read from input");
        serde_json::from_str(&in_buffer).expect("failed to parse json input")
    }
    ApiConfig::from(load_interface_cfg(&opt)).interface
}

fn get_json_input<'a, T: Deserialize<'a>>(_opt: &Opt, reader: &mut Box<dyn Read>, mut in_buffer: &'a mut String) -> T {
    reader.read_to_string(&mut in_buffer).expect("could not read from input");
    let input: &'a str = in_buffer.as_str();
    serde_json::from_str(input).expect("failed to parse json input")
}

fn handle_json_response<T: DeserializeOwned>(_opt: Opt, resp: Result<Response, reqwest::Error>) -> T {
    match resp {
        Ok(resp) => match resp.status() {
            StatusCode::OK => match block_on(resp.json::<T>()) {
                Ok(parsed_t) => parsed_t,
                Err(_) => {
                    println!("Status code OK, but failed to parse response, exiting.");
                    std::process::exit(1);
                }
            },
            code => {
                match block_on(resp.json::<ErrorMessage>()) {
                    Ok(parsed_err) => render_api_error_message(parsed_err),
                    Err(_) => {
                        println!("Status code {}, and failed to parse response, exiting.", code);
                    }
                }
                std::process::exit(1);
            }
        },
        Err(error) => {
            println!("Error getting response:\n {}", error);
            std::process::exit(1);
        }
    }
    
}

fn handle_response(_opt: Opt, resp: Result<Response, reqwest::Error>) {
    match resp {
        Ok(resp) => match resp.status() {
            StatusCode::OK => println!("Success!"),
            StatusCode::CREATED => println!("Resource successfully created."),
            code => {
                match block_on(resp.json::<ErrorMessage>()) {
                    Ok(parsed_err) => render_api_error_message(parsed_err),
                    Err(_) => {
                        println!("Status code {}, and failed to parse response, exiting.", code);
                    }
                }
                std::process::exit(1);
            }
        },
        Err(error) => {
            println!("Error getting response:\n {}", error);
            std::process::exit(1);
        }
    }
    
}

fn render_api_error_message (err: ErrorMessage) {
    let mut table = Table::new();
    table.add_row(row!["CODE", "API ERROR MESSAGE"]);
    table.add_row(row![err.code, err.message]);
    table.printstd();
}

fn interfaces_table(interfaces: Vec<ApiInterface>) -> Table{
    // Create the table
    let mut table = Table::new();
    table.add_row(row![cH5 => "INTERFACE"]);
    table.add_row(row!["NAME", "PUBLIC KEY", "PORT", "IP", "FQDN"]);

    for interface in interfaces {
        table.add_row(row![
            interface.u_name, 
            interface.public_key.unwrap_or_default(), 
            interface.port.unwrap_or_default(), 
            &interface.ip.map_or("".to_string(), |ip| ip.to_string()), 
            interface.fqdn.unwrap_or_default()
        ]);
    }
    table
}

fn peer_relation_table(peer_relations: Vec<ApiPeerRelation>) -> Table {
    // Create the table
    let mut table = Table::new();
    table.add_row(row![cH5 => "PEER"]);
    table.add_row(row!["ENDPOINT", "ENDPOINT NAME", "PEER NAME", "ENDPOINT PUBKEY", "PEER PUBKEY", "ENDPOINT ALLOWED IPs", "PEER ALLOWED IPs"]);

    for pr in peer_relations {
        table.add_row(row![
            pr.endpoint.unwrap_or(String::new()),
            pr.endpoint_name.unwrap_or(String::new()),
            pr.peer_name.unwrap_or(String::new()),
            pr.endpoint_public_key.unwrap_or(String::new()), 
            pr.peer_public_key.unwrap_or(String::new()),
            match pr.endpoint_allowed_ip {
                Some(allowed_ip) => allowed_ip
                                    .iter()
                                    .map(|allowed| allowed.to_string())
                                    .collect::<Vec<String>>()
                                    .join("\n"), 
                None => String::new()
            },
            match pr.peer_allowed_ip {
                Some(allowed_ip) => allowed_ip
                                    .iter()
                                    .map(|allowed| allowed.to_string())
                                    .collect::<Vec<String>>()
                                    .join("\n"), 
                None => String::new()
            },
        ]);
    }
    table
}

fn interface_config_table(ApiConfig { interface, peers }: ApiConfig) -> Table {
    // Create the table
    let mut table = Table::new();
    table.add_row(row![c => "INTERFACE CONFIG"]);
    table.add_row(row![interfaces_table(vec![interface])]);
    table.add_row(row![peer_relation_table(peers)]);
    table
}

fn write_config(ApiConfig { interface, peers }: ApiConfig, Opt { interface: interface_name, wgman_dir, .. }: Opt) {
    let mut interface_path = wgman_dir.clone();
    let interface_name = interface_name.as_ref().unwrap().to_string();
    interface_path.push(&interface_name);

    let mut priv_path = interface_path.clone();
    priv_path.push("private");
    let mut priv_reader = fs::File::open(priv_path).expect("Could not open file containing private key.");
    let mut priv_key = String::new();
    priv_reader.read_to_string(&mut priv_key).expect("could not read from input");
    let port = match interface.port {
        Some(p) => p.to_string(),
        None => String::new()
    };

    // verify configured public key is a match for private key, else throw error?

    let mut interface_data = format!("[Interface]\n\
                                              PrivateKey = {}\n\
                                              ListenPort = {}\n\
    ", priv_key.trim(), port);

    match interface.ip {
        Some(ip) => interface_data.push_str(&format!("IP = {}\n", ip.to_string())),
        None => {}
    }

    let mut config_path = interface_path.clone();
    config_path.push(&format!("{}.conf.test", &interface_name));

    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(config_path.clone()).expect("could not open or create the interface config file");
        
    f.write_all(interface_data.as_bytes()).expect("Unable to write interface data");
    
    let mut f = OpenOptions::new()
    .append(true)
    .create(true)
    .open(config_path.clone()).expect("could not open or create the interface config file");

    if interface.public_key.as_ref().is_some() {
        for peer in peers {
            let (pk, allowed_ips) = match interface.clone() {
                interface if peer.peer_public_key == interface.public_key =>
                (
                    peer.endpoint_public_key, 
                    peer.endpoint_allowed_ip
                    .unwrap_or(vec![])
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
                ),
                interface if peer.endpoint_public_key == interface.public_key =>
                (
                    peer.peer_public_key,  
                    peer.peer_allowed_ip
                    .unwrap_or(vec![])
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
                ),
                _ => (None, String::new())
            };

            let peer_data = format!("\n[Peer]\n\
                                              PublicKey = {}\n\
                                              AllowedIPs = {}\n\
            ", pk.unwrap_or(String::new()), allowed_ips);
            f.write_all(peer_data.as_bytes()).expect("Unable to write interface data");
        }
    }
}

