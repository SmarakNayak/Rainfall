//! `meshchain chat`: two clients talking over one TCP connection.
//!
//! Each line typed becomes a `post` record on your own chain and is sent to
//! the peer as one JSON record per line. A record is sent with whatever part
//! of its ancestry this connection hasn't carried yet, so the peer can always
//! validate it. There is no catch-up: messages written while disconnected
//! arrive only as ancestry of the next message.

use meshchain::{AccountId, Client, Id, Payload, Record};
use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

const USAGE: &str = "usage: meshchain chat --data DIR --name NAME (--listen ADDR | --connect ADDR)";

enum Peer {
    Listen(String),
    Connect(String),
}

struct Args {
    data: PathBuf,
    name: String,
    peer: Peer,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("chat") {
        return Err(USAGE.into());
    }
    let (mut data, mut name, mut peer) = (None, None, None);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--data" => data = Some(PathBuf::from(value)),
            "--name" => name = Some(value),
            "--listen" => peer = Some(Peer::Listen(value)),
            "--connect" => peer = Some(Peer::Connect(value)),
            _ => return Err(format!("unknown option {flag}\n{USAGE}")),
        }
    }
    match (data, name, peer) {
        (Some(data), Some(name), Some(peer)) => Ok(Args { data, name, peer }),
        _ => Err(USAGE.into()),
    }
}

struct Session {
    client: Client,
    account: AccountId,
    state_file: PathBuf,
    /// Records this connection has already carried, in either direction.
    carried: HashSet<Id>,
}

impl Session {
    fn open(data: &Path, name: &str) -> io::Result<Self> {
        fs::create_dir_all(data)?;
        let state_file = data.join("state.json");
        let mut client = match fs::read(&state_file) {
            Ok(bytes) => Client::load(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Client::new(name),
            Err(e) => return Err(e),
        };
        let account = match client.own_accounts().first() {
            Some(&account) => account,
            None => client.create_account(name),
        };
        let session = Session { client, account, state_file, carried: HashSet::new() };
        session.save()?;
        Ok(session)
    }

    // Written to a temporary file and renamed, so a crash never leaves half a file.
    fn save(&self) -> io::Result<()> {
        let tmp = self.state_file.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.client.save())?)?;
        fs::rename(tmp, &self.state_file)
    }

    /// The part of `id`'s ancestry this connection hasn't carried yet, oldest first.
    fn uncarried(&mut self, id: Id) -> Vec<Record> {
        let missing: Vec<Record> = self.client.ancestry(id).into_iter().filter(|r| !self.carried.contains(&r.id)).cloned().collect();
        self.carried.extend(missing.iter().map(|r| r.id));
        missing
    }

    fn post(&mut self, text: &str) -> io::Result<Vec<Record>> {
        let id = self.client.post(self.account, text).map_err(|e| io::Error::other(format!("{e:?}")))?;
        self.save()?;
        Ok(self.uncarried(id))
    }

    fn receive(&mut self, record: Record) -> io::Result<()> {
        self.carried.insert(record.id);
        for id in self.client.receive([record]) {
            let record = self.client.record(id).expect("just added");
            if let Payload::Post { text } = &record.payload {
                let author = record.account_id();
                if author != self.account {
                    println!("{}: {text}", self.client.name_of(author).unwrap_or("?"));
                }
            }
        }
        self.save()
    }
}

fn connect(peer: &Peer) -> io::Result<TcpStream> {
    match peer {
        Peer::Listen(addr) => {
            let listener = TcpListener::bind(addr)?;
            println!("waiting for a peer on {addr}");
            Ok(listener.accept()?.0)
        }
        Peer::Connect(addr) => TcpStream::connect(addr),
    }
}

fn run(args: Args) -> io::Result<()> {
    let session = Session::open(&args.data, &args.name)?;
    let me = session.client.name_of(session.account).unwrap_or("?").to_owned();
    println!("you are {me} ({:?})", session.account);

    let stream = connect(&args.peer)?;
    println!("connected to {}; type a message and press Enter", stream.peer_addr()?);
    let session = Arc::new(Mutex::new(session));

    let incoming = BufReader::new(stream.try_clone()?);
    let reader_session = Arc::clone(&session);
    thread::spawn(move || {
        for line in incoming.lines() {
            let Ok(line) = line else { break };
            match serde_json::from_str::<Record>(&line) {
                Ok(record) => {
                    if let Err(e) = reader_session.lock().expect("session lock").receive(record) {
                        eprintln!("could not save: {e}");
                    }
                }
                Err(e) => eprintln!("ignoring malformed message: {e}"),
            }
        }
        println!("peer disconnected");
        std::process::exit(0);
    });

    let mut outgoing = stream;
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let records = session.lock().expect("session lock").post(line.trim())?;
        for record in records {
            serde_json::to_writer(&mut outgoing, &record)?;
            outgoing.write_all(b"\n")?;
        }
        outgoing.flush()?;
    }
    Ok(())
}

fn main() {
    let result = parse_args().map_err(io::Error::other).and_then(run);
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
