#[forbid(unsafe_code)]
use anyhow::Error;
use fast_socks5::{
    ReplyError, Result, Socks5Command, SocksError, server::Socks5ServerProtocol,
    util::target_addr::TargetAddr,
};
use std::future::Future;
use std::num::ParseFloatError;
use std::time::Duration;
use structopt::StructOpt;
use tokio::io::AsyncReadExt;
use std::io::IoSlice;
use tokio::net::TcpStream;
use tokio::{io::AsyncWriteExt, net::TcpListener, task};
use tracing::{error, info};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "kirikiri",
    about = "A minimal proxy that performs DPI evasion by modifying HTTP and TlS packets sent over it"
)]
struct Opt {
    /// Bind on specific addresses or ports
    #[structopt(short, long, default_value = "127.0.0.1:1080")]
    pub listen_addr: String,

    /// Request timeout, in seconds
    #[structopt(short = "t", long, default_value = "10", parse(try_from_str=parse_duration))]
    pub request_timeout: Duration,
}

fn parse_duration(s: &str) -> Result<Duration, ParseFloatError> {
    let seconds = s.parse()?;
    Ok(Duration::from_secs_f64(seconds))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"))
        )
        .init();

    let opt: &'static Opt = Box::leak(Box::new(Opt::from_args()));

    let listener = TcpListener::bind(&opt.listen_addr).await?;

    println!("Listening for SOCKS5 proxy connections at {} (you may have to change your browser settings)", &opt.listen_addr);

    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                spawn_and_log_error(proxy_requests(opt, socket));
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }
}

async fn proxy_requests(opt: &Opt, socket: TcpStream) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;

    if cmd != Socks5Command::TCPConnect {
        proto.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ReplyError::CommandNotSupported.into());
    }

    info!("Received request to connect to {:?} ", &target_addr);

    let resolved_addr = match target_addr.resolve_dns().await? {
        TargetAddr::Ip(addr) => addr,
        TargetAddr::Domain(_, _) => {
            error!("Could not resolve domain");
            return Err(ReplyError::CommandNotSupported.into());
        }
    };

    info!("Resolved address to {:?}, proxying...", resolved_addr);

    let mut outbound = tokio::time::timeout(opt.request_timeout, TcpStream::connect(resolved_addr))
        .await
        .map_err(|_| SocksError::Other(Error::msg("connect timeout")))?
        .map_err(SocksError::Io)?;

    let local_addr = outbound.local_addr()?;
    let mut inbound = proto.reply_success(local_addr).await?; // respond to the SOCKS5 client with success of the local addr, and receive a TCP stream

    let mut buf = vec![0u8; 1024 * 16];
    let n = inbound.read(&mut buf).await.map_err(SocksError::Io)?;
    info!("First request is {} bytes", n);
    if n == 0 {
        return Ok(());
    }

    match buf[0] {
        // HTTP cases: the first byte is one of the first chars of HTTP methods
        b'G'   // GET
        | b'H' // HEAD
        | b'P' // POST, PATCH, PUT
        | b'D' // DELETE
        | b'C' // CONNECT
        | b'O' // OPTIONS
        | b'T' // TRACE
        => {
            // Handle http
            info!("Segmenting request as http...");
            outbound.write(&buf[..1]).await.map_err(SocksError::Io)?; // Write the first byte
            outbound.write(&buf[1..n]).await.map_err(SocksError::Io)?;
        },
        // the TLS case: the first byte is 0x16, signifying TLS
        0x16 => {
            info!("Segmenting request as TLS... ");
            let mut successfully_segmented = false;
            'segment: {
                if n <= 61 { break 'segment } // 61 is the minimum byte count of a TLS record that contains a SNI
                if buf[1] != 0x03 { break 'segment } // [1] is the record layer major version, anything not 0x03 isn't TLS
                let tls_version_minor = buf[2];
                if tls_version_minor >= 0x04 || tls_version_minor == 0x02 { break 'segment } // exclude any future TLS versions, and tls 1.1 explicitly
                let record_length: u16 = (buf[3] as u16) << 8 | buf[4] as u16; // record payload length, in big endian
                if record_length <= 56 { break 'segment } // record is either already segmented or contains no extensions
                if buf[5] != 0x01 { break 'segment } // [5] is the first byte of the record payload; 0x01 is ClientHello, don't care about anything else
                let handshake_length: u32 = (buf[6] as u32) << 16 | (buf[7] as u32) << 8 | buf[8] as u32; // technically u24, but closest is u32 (though technically should never exceed u16)
                if handshake_length != (record_length - 4) as u32 { break 'segment } // either there are multiple handshake messages, or the lengths are inconsistent. either way let it pass
                if buf[9] != 0x03 { break 'segment } // ClientHello's legacy version field; same as before; anything with major!=0x03 isn't TLS
                if buf[10] >= 0x04 || buf[10] == 0x02 { break 'segment } // minor ver, same thing, break if new ver or TLS1.1
                let session_id_length = buf[43]; // skip 32 bytes of random
                let mut i: usize = 43 + session_id_length as usize + 1 ; // the 43 bytes we skipped, plus the session id bytes, plus 1 is the start of:
                if n <= (i + 1) || record_length as usize <= i - 4 { break 'segment } // first thing checks the next two bytes exist, second thing checks that the TLS record length matches up
                let cipher_suite_list_length: u16 = (buf[i] as u16) << 8 | buf[i + 1] as u16;
                if cipher_suite_list_length & 1 == 1 { break 'segment } // every cipher suite is 2 bytes, so the total length should be even
                i += cipher_suite_list_length as usize + 2; // add the read cipher suites, and the length of those suites
                if n <= i || record_length as usize <= i - 5 { break 'segment; } // checks we can read the next byte
                let compression_methods_length = buf[i];
                i += 1 + compression_methods_length as usize; // skip past the byte for the len and the methods themselves
                if n <= (i + 1) || record_length as usize <= i - 4 { break 'segment; } // checks we can read the next two bytes
                let extensions_length: u16 = (buf[i] as u16) << 8 | buf[i + 1] as u16; // read the big endian encoded length
                if extensions_length <= 9 { break 'segment; } // min SNI extension is 10 bytes
                i += 2; // for reading the two length bytes
                if record_length as usize + 5 != i + extensions_length as usize { break 'segment; } // extensions should be the rest of the record
                let mut extension_length;
                'walk_extensions: loop {
                    let extension_type: u16 = (buf[i] as u16) << 8 | buf[i + 1] as u16;  // read type
                    i += 2;
                    extension_length = (buf[i] as u16) << 8 | buf[i + 1] as u16; // read length
                    i += 2;
                    if extension_type == 0x0000 { break 'walk_extensions; } // SNI's extension type; i now points to the first byte of the data and the length is above
                    i += extension_length as usize;
                    if n <= (i + 3) || record_length as usize <= i - 2 { break 'segment; } // checks we can read the next four bytes
                }
                if n <= (i + 1) || record_length as usize <= i - 4 { break 'segment; } // next two bytes
                let server_name_list_length: u16 = (buf[i] as u16) << 8 | buf[i + 1] as u16;
                i += 2;
                if server_name_list_length != extension_length - 2 { break 'segment } // checks for consistent extension data lengths
                if extension_length <= 5 { break 'segment } // SNI data needs at least 6 bytes to contain a 1 char hostname
                if extension_length >= extensions_length { break 'segment } // otherwise structurally impossible
                'walk_server_name_list: loop {
                    if n <= (i + 2) || record_length as usize <= i - 3 { break 'segment; } // next three bytes
                    let name_type = buf[i];
                    i += 1;
                    let opaque_data_length: u16 = (buf[i] as u16) << 8 | buf[i + 1] as u16;
                    i += 2;
                    if name_type == 0x00 { // the only defined name type in RFC 6066
                        if opaque_data_length > server_name_list_length - 3 { break 'segment } // malformed
                        if opaque_data_length == 0 { break 'segment } // empty hostname can't be split
                        break 'walk_server_name_list
                    }
                    i += opaque_data_length as usize;
                }
                let first_buffer_size = (i - 5) as u16; // header is 5 bytes, payload goes to i-1
                let second_buffer_size = (n - i) as u16; // everything else
                if second_buffer_size == 0 { break 'segment } // should be impossible but would mean malformed
                buf[3] = (first_buffer_size >> 8) as u8;
                buf[4] = (first_buffer_size & 0xff) as u8;
                let second_buffer_header: [u8; 5] = [0x16, 0x03, tls_version_minor, (second_buffer_size >> 8) as u8, (second_buffer_size & 0xff) as u8];
                outbound.write_vectored(&[IoSlice::new(&buf[..i]), IoSlice::new(&second_buffer_header), IoSlice::new(&buf[i..n])]).await.map_err(SocksError::Io)?; // write up to the SNI
                successfully_segmented = true;
            };
            info!("successfully segmented: {}", successfully_segmented);

            if !successfully_segmented {
                outbound.write(&buf[..n]).await.map_err(SocksError::Io)?;
            }
        },
        _ => {
            outbound.write(&buf[..n]).await.map_err(SocksError::Io)?;
        }
    }

    info!("Proxying...");
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => error!("{:#}", &err),
        }
    })
}
