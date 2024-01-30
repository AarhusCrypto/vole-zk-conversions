use clap;
use eyre::Result;
use git_version::git_version;
use scuttlebutt::{SyncChannel, TrackChannel};
use serde::Serialize;
use std::{
    fmt,
    fs::{read_to_string, File},
    io::{BufRead, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    process, thread,
    time::Duration,
};

#[derive(Clone, Debug, Serialize)]
pub struct BenchmarkMetaData {
    pub hostname: String,
    pub username: String,
    pub timestamp: String,
    pub cmdline: Vec<String>,
    pub pid: u32,
    pub git_version: String,
}

impl BenchmarkMetaData {
    pub fn collect() -> Self {
        BenchmarkMetaData {
            hostname: get_hostname(),
            username: get_username(),
            timestamp: get_timestamp(),
            cmdline: get_cmdline(),
            pid: get_pid(),
            git_version: git_version!(args = ["--abbrev=40", "--always", "--dirty"]).to_string(),
        }
    }
}

pub fn run_command_with_args(cmd: &str, args: &[&str]) -> String {
    String::from_utf8(
        process::Command::new(cmd)
            .args(args)
            .output()
            .expect("process failed")
            .stdout,
    )
    .expect("utf-8 decoding failed")
    .trim()
    .to_string()
}

pub fn run_command(cmd: &str) -> String {
    String::from_utf8(
        process::Command::new(cmd)
            .output()
            .expect("process failed")
            .stdout,
    )
    .expect("utf-8 decoding failed")
    .trim()
    .to_string()
}

pub fn read_file(path: &str) -> String {
    read_to_string(path).expect("read_to_string failed")
}

pub fn get_username() -> String {
    run_command("whoami")
}

pub fn get_hostname() -> String {
    read_file("/proc/sys/kernel/hostname").trim().to_string()
}

pub fn get_timestamp() -> String {
    run_command_with_args("date", &["--iso-8601=s"])
}

pub fn get_cmdline() -> Vec<String> {
    let f = File::open("/proc/self/cmdline").expect("cannot open file");
    let mut reader = BufReader::new(f);
    let mut cmdline: Vec<String> = Vec::new();
    loop {
        let mut bytes = Vec::<u8>::new();
        let num_bytes = reader.read_until(0, &mut bytes).expect("read failed");
        if num_bytes == 0 {
            break;
        }
        bytes.pop();
        cmdline.push(String::from_utf8(bytes).expect("utf-8 decoding failed"))
    }
    cmdline
}

pub fn get_pid() -> u32 {
    process::id()
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum Party {
    Prover,
    Verifier,
    Both,
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Party::Prover => write!(f, "Prover"),
            Party::Verifier => write!(f, "Verifier"),
            Party::Both => write!(f, "Both"),
        }
    }
}

#[derive(Debug, Clone, clap::Parser, Serialize)]
pub struct NetworkOptions {
    /// Listen for incoming connections
    #[clap(short, long)]
    listen: bool,
    /// Which address to listen on/to connect to
    #[clap(short, long, default_value = "localhost")]
    host: String,
    /// Which port to listen on/to connect to
    #[clap(short, long, default_value_t = 1337)]
    port: u16,
    /// How long to try connecting before aborting
    #[clap(long, default_value_t = 100)]
    connect_timeout_seconds: usize,
}

type NetworkChannel = TrackChannel<SyncChannel<BufReader<TcpStream>, BufWriter<TcpStream>>>;

fn connect(host: &str, port: u16, timeout_seconds: usize) -> Result<NetworkChannel> {
    fn connect_socket(host: &str, port: u16, timeout_seconds: usize) -> Result<TcpStream> {
        for _ in 0..(10 * timeout_seconds) {
            if let Ok(socket) = TcpStream::connect((host, port)) {
                return Ok(socket);
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(TcpStream::connect((host, port))?)
    }
    let socket = connect_socket(host, port, timeout_seconds)?;
    let reader = BufReader::new(socket.try_clone()?);
    let writer = BufWriter::new(socket);
    let channel = TrackChannel::new(SyncChannel::new(reader, writer));
    Ok(channel)
}

fn listen(host: &str, port: u16) -> Result<NetworkChannel> {
    let listener = TcpListener::bind((host, port))?;
    let (socket, _addr) = listener.accept()?;
    let reader = BufReader::new(socket.try_clone()?);
    let writer = BufWriter::new(socket);
    let channel = TrackChannel::new(SyncChannel::new(reader, writer));
    Ok(channel)
}

pub fn setup_network(options: &NetworkOptions) -> Result<NetworkChannel> {
    if options.listen {
        listen(&options.host, options.port)
    } else {
        connect(&options.host, options.port, options.connect_timeout_seconds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum FieldParameter {
    F40b,
    F61p,
}

impl fmt::Display for FieldParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            FieldParameter::F40b => write!(f, "F40b"),
            FieldParameter::F61p => write!(f, "F61p"),
        }
    }
}
