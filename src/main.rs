#[macro_use] extern crate prettytable;

use std::{path::Path, vec};
use std::path::PathBuf;
use std::io::{self, Read, stdin, BufReader};
use std::io::prelude::*;
use std::fs;

use types::*;
use wgman_core::types;
use structopt::StructOpt;
use prettytable::{Table};
use reqwest::{StatusCode, header::AUTHORIZATION};
use futures::executor::block_on;
use ipnetwork::IpNetwork;
use serde::{Deserialize};

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "wgmancli", about = "Wgman cli StructOpt.")]
struct Opt {
    /// Activate debug mode
    // short and long flags (-d, --debug) will be deduced from the field's name
    #[structopt(short, long)]
    debug: bool,
    
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
    resource: PathBuf,

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
    println!("getting opt");

    run(Opt::from_args()).unwrap();

    Ok(())
}

fn run(opt: Opt) -> io::Result<()> {
    println!("running cmd");
    let mut reader: Option<Box<dyn Read>> = match (&opt.input_json, &opt.input) {
        (false, _) => None,
        (true, None) => Some(Box::new(stdin())),
        (true, Some(i)) => Some(Box::new(fs::File::open(i)?))
    };
    let Opt { api_url, resource, action, .. } = &opt.clone();
    let client = reqwest::Client::new();
    let resource = resource.to_str().unwrap();
    println!("getting auth");
    let auth_type = match &opt.admin_auth {
        true => "aauth",
        false => "iauth"
    };
    let auth = get_auth_header(&opt);
    match (resource, action.as_str()) {
        ("conf", "list") => {
            let url = format!("http://{}/{}/{}/list", api_url, auth_type, resource);

            let resp = match block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send()) {
                Ok(response) => response,
                Err(error) => {
                    println!("Error getting interface list:\n {}", error);
                    std::process::exit(1);
                }
            };
            
            let interfaces = block_on(resp.json::<Vec<types::ApiInterface>>()).unwrap();

            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/{}/list/{}", api_url, auth_type, resource, &opt.interface.clone().unwrap());

            let resp = block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send())
            .unwrap();

            let peer = block_on(resp.json::<Vec<types::ApiPeerRelation>>()).unwrap();
            
            let url = format!("http://{}/{}/{}/list/{}", api_url, auth_type, resource, &opt.interface.clone().unwrap());

            let resp = block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send())
            .unwrap();

            let endpoint = block_on(resp.json::<Vec<types::ApiPeerRelation>>()).unwrap();

            render_interfaces(interfaces);
            render_peer_relations(endpoint);
            render_peer_relations(peer);
        },
        ("conf", "push") => {
            let conf = ApiConfig::from(load_interface_cfg(&opt));
            let interface = conf.interface;
            
            let url = format!("http://{}/{}/interface/set", api_url, auth_type);
            println!("interface push");
            let resp = block_on(client
            .post(url.as_str())
            .json(&interface)
            .header(AUTHORIZATION, auth.clone())
            .send())
            .unwrap();
            println!("Sent:");

            match resp.status() {
                StatusCode::OK => println!("Success!"),
                _ => println!("Oops! {}", block_on(resp.text()).unwrap())
            }

            let interface_name = &opt.interface.unwrap();
            let peer_url = format!("http://{}/{}/peer/set/{}", api_url, auth_type, interface_name);
            let endpoint_url = format!("http://{}/{}/endpoint/set/{}", api_url, auth_type, interface_name);

            match interface.public_key.clone() {
                Some(ipk) => {
                    for pr in conf.peers {
                        if ipk == pr.peer_public_key.clone() {
                            println!("peer push");
                            let resp = block_on(client
                            .post(peer_url.as_str())
                            .json(&interface)
                            .header(AUTHORIZATION, auth.clone())
                            .send())
                            .unwrap();
                            println!("Sent:");
                            match resp.status() {
                                StatusCode::OK => println!("Success!"),
                                _ => println!("Oops! {}", block_on(resp.text()).unwrap())
                            }
                        }
                        if ipk == pr.endpoint_public_key.clone() {
                            println!("endpoint push");
                            let resp = block_on(client
                            .post(endpoint_url.as_str())
                            .json(&interface)
                            .header(AUTHORIZATION, auth.clone())
                            .send())
                            .unwrap();
                            println!("Sent:");
                            match resp.status() {
                                StatusCode::OK => println!("Success!"),
                                _ => println!("Oops! {}", block_on(resp.text()).unwrap())
                            }
                        }
                    }
                }
                _ => println!("selected interface is missing a public key, can't push any peer relations.")
            }
            

            render_interfaces(vec![interface.clone()]);

        },
        ("conf", "pull") => {
            let interface_name = &opt.interface.clone().unwrap();
            let url = format!("http://{}/{}/{}/{}", api_url, auth_type, resource, interface_name);
            let mut local_interface = get_interface(&opt, reader.as_mut());

            let resp = match block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send()) {
                Ok(response) => response,
                Err(error) => {
                    println!("Error getting interface:\n {}", error);
                    std::process::exit(1);
                }
            };
            
            let api_interface = block_on(resp.json::<ApiInterface>()).unwrap();
            local_interface.coallesce(api_interface);
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/{}/list/{}", api_url, auth_type, resource, interface_name);

            let resp = block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send())
            .unwrap();

            let peer = block_on(resp.json::<Vec<ApiPeerRelation>>()).unwrap();
            
            let url = format!("http://{}/{}/{}/list/{}", api_url, auth_type, resource, interface_name);

            let resp = block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, &auth)
            .send())
            .unwrap();

            let endpoint = block_on(resp.json::<Vec<ApiPeerRelation>>()).unwrap();

            // coallesce

            render_interfaces(vec![local_interface.clone()]);
            render_peer_relations(endpoint.clone());
            render_peer_relations(peer.clone());

            write_config(local_interface, peer, endpoint);
        },
        ("interface", "list") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/{}/list", api_url, auth_type, resource);

            match block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send()) {
                Ok(response) => match response.status() {
                    StatusCode::OK => {
                        match block_on(response.json::<Vec<ApiInterface>>()) {
                            Ok(interfaces) => {
                                render_interfaces(interfaces);
                                println!("Success!")
                            },
                            _ => println!("Couldn't deserialize response.")
                        }
                        
                    },
                    r => println!("Oops! {} {}", r, block_on(response.text()).unwrap())
                },
                Err(error) => {
                    println!("Error getting interface list:\n {}", error);
                    std::process::exit(1);
                }
            };
            
            


        },
        ("interface", "push") => {
            let url = format!("http://{}/{}/{}", api_url, auth_type, resource);
            println!("interface push");
            let interface = get_interface(&opt, reader.as_mut());
            let resp = block_on(client
            .post(url.as_str())
            .json(&interface)
            .header(AUTHORIZATION, auth)
            .send())
            .unwrap();
            println!("Sent:");
            render_interfaces(vec![interface.clone()]);

            match resp.status() {
                StatusCode::OK => println!("Success!"),
                _ => println!("Oops! {}", block_on(resp.text()).unwrap())
            }
        },
        ("interface", "remove") => {
            println!("interface remove");
            let interface = get_interface(&opt, reader.as_mut());
            let url = format!("http://{}/{}/interface/remove/{}", api_url, auth_type, interface.u_name);

            let resp = block_on(client
            .delete(url.as_str())
            .header(AUTHORIZATION, auth)
            .send())
            .unwrap();
            println!("Sent:");
            render_interfaces(vec![interface.clone()]);

            match resp.status() {
                StatusCode::OK => println!("Success!"),
                _ => println!("Oops! {}", block_on(resp.text()).unwrap())
            }
        },
        ("peer", "list") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/{}/list/{}", api_url, auth_type, resource, &opt.interface.unwrap());

            let resp = block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send())
            .unwrap();

            let peer = block_on(resp.json::<Vec<ApiPeerRelation>>()).unwrap();
            render_peer_relations(peer);
        },
        ("endpoint", "list") => {
            // in_out(&mut reader, &mut writer, &opt, ).unwrap();
            let url = format!("http://{}/{}/{}/list/{}", api_url, auth_type, resource, &opt.interface.unwrap());

            let resp = block_on(client
            .get(url.as_str())
            .header(AUTHORIZATION, auth)
            .send())
            .unwrap();

            let endpoint = block_on(resp.json::<Vec<ApiPeerRelation>>()).unwrap();
            render_peer_relations(endpoint);
        },
        ("peer-relation", "push") => {
            match &opt.admin_auth {
                false => println!("pushing peer-relations is only available with admin authentication."),
                true => {
                    let url = format!("http://{}/{}/{}", api_url, auth_type, resource);
                    println!("peer_relation push");
                    let peer_relation: ApiPeerRelation = get_json_input(&opt, reader.as_mut().unwrap(), &mut String::new());
                    let resp = block_on(client
                    .post(url.as_str())
                    .json(&peer_relation)
                    .header(AUTHORIZATION, auth)
                    .send())
                    .unwrap();
                    println!("Sent:");
                    render_peer_relations(vec![peer_relation.clone()]);
        
                    match resp.status() {
                        StatusCode::OK => println!("Success!"),
                        _ => println!("Oops! {}", block_on(resp.text()).unwrap())
                    }
                }
            }
           
        },
        ("peer-relation", "remove") => {
            match &opt.admin_auth {
                false => println!("removing peer-relations is only available with admin authentication."),
                true => {
                    println!("peer_relation remove");
                    let peer_relation: ApiPeerRelation = get_json_input(&opt, reader.as_mut().unwrap(), &mut String::new());
                    let url = format!("http://{}/{}/pr/remove/{}/{}", api_url, auth_type, peer_relation.endpoint_public_key, peer_relation.peer_public_key);
        
                    let resp = block_on(client
                    .delete(url.as_str())
                    .header(AUTHORIZATION, auth)
                    .send())
                    .unwrap();
                    println!("Sent:");
                    render_peer_relations(vec![peer_relation.clone()]);
        
                    match resp.status() {
                        StatusCode::OK => println!("Success!"),
                        _ => println!("Oops! {}", block_on(resp.text()).unwrap())
                    }
                }
            }
        }, 
        ("admin", "remove") => {
            match &opt.admin_auth {
                false => println!("removing admin users is only available with admin authentication."),
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
        ("pw/admin", "push") => {
            match &opt.admin_auth {
                false => println!("pushing admin user pw is only available with admin authentication."),
                true => {
                    match reader {
                        Some(mut reader) => {
                            let admin_pw: ApiAdminPassword = get_json_input(&opt, &mut reader, &mut String::new());
                            let url = format!("http://{}/{}/pw/admin/", api_url, auth_type);

                            let resp = block_on(client
                                .post(url.as_str())
                                .json(&admin_pw)
                                .header(AUTHORIZATION, auth)
                                .send());
                                
                                println!("Sent:");
                    
                                match resp {
                                    Ok(resp) if resp.status() == StatusCode::OK => println!("Success!"),
                                    Ok(resp) => println!("Oops! {} {}", resp.status(), block_on(resp.text()).unwrap()),
                                    Err(err) => println!("Oops! {}", err)
                                }
                        }
                        None => println!("pushing admin user pw is only available with input."),
                    }
                }
            }
        },
        ("pw/interface", "push") => {
            match reader {
                Some(mut reader) => {
                    let interface_pw: ApiInterfacePassword = get_json_input(&opt, &mut reader, &mut String::new());
                    let url = format!("http://{}/{}/pw/interface/", api_url, auth_type);
                    dbg!(url.clone());
                    let resp = block_on(client
                        .post(url.as_str())
                        .json(&interface_pw)
                        .header(AUTHORIZATION, auth)
                        .send());
                        
                        println!("Sent:");
            
                        match resp {
                            Ok(resp) if resp.status() == StatusCode::OK => println!("Success!"),
                            Ok(resp) => println!("Oops! {} {}", resp.status(), block_on(resp.text()).unwrap()),
                            Err(err) => println!("Oops! {}", err)
                        }
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
    // cat(reader, writer)
}

fn get_auth_header(opt: &Opt) -> String {
    if opt.admin_auth {
        return BasicAuth{ name: opt.admin_name.as_ref().unwrap().to_string(), password: opt.admin_pw.as_ref().unwrap().to_string() }.to_string();
    }
    let mut auth = opt.wgman_dir.clone();
    auth.push(opt.interface.as_ref().unwrap().to_string());
    auth.push(Path::new("auth"));
    let file = fs::File::open(auth).expect("Something went wrong reading the password file");

    let mut name = None;
    let mut password = None;
    for line in BufReader::new(file).lines() {
        let l = line.expect("Something went wrong reading the password file");
        let l = l.trim();
        // ignore empty or commented lines
        if l.len() == 0 || l.chars().next().unwrap() == '#' {
            continue;
        }
        let mut kv= l.splitn(2, "=");
        let k = kv.next().expect("Failed to parse password file.").trim();
        let v = kv.next().expect("Failed to parse password file.").trim().to_string();
        match k {
            "NAME" => name = Some(v),
            "PASSWORD" => password = Some(v),
            _ => {}
        };
    }
    // println!("{}:{}", name.as_ref().unwrap(), password.as_ref().unwrap());
    BasicAuth{ name: name.expect("Interface password file missing NAME key"), password: password.expect("Interface password file missing PASSWORD key") }.to_string()
}

fn load_interface_cfg(opt: &Opt) -> InterfaceConfig {
    println!("loading interface conf");
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
                        println!("Warning: '{}' not recognized as key in [Interface]", k);
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
                        println!("Warning: '{}' not recognized as key in [Peer]", k);
                    }                
                };
            },
            None => {
                println!("Warning: '{}' not a valid config block, or not associated with a valid config block", k);
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

    // fqdn to be loaded from file as well?

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

fn render_interfaces(interfaces: Vec<ApiInterface>) {
    // Create the table
    let mut table = Table::new();

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
    table.printstd();
}

fn render_peer_relations(peer_relations: Vec<ApiPeerRelation>) {
    // Create the table
    let mut table = Table::new();

    table.add_row(row!["ENDPOINT PUBKEY", "PEER PUBKEY", "ENDPOINT ALLOWED IPs", "PEER ALLOWED IPs"]);

    for pr in peer_relations {
        table.add_row(row![
            pr.endpoint_public_key, 
            pr.peer_public_key,
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
    table.printstd();
}

fn write_config(interface: ApiInterface, peers: Vec<ApiPeerRelation>, endpoints: Vec<ApiPeerRelation>) {
    
}
