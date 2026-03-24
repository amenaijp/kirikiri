# kirikiri

`kirikiri` is a minimal SOCKS5 proxy designed to be run locally that modifies http and https requests to bypass Deep Packet Inspection (DPI) on some networks.

It works by slicing packets in half, which is expensive for DPI filters to undo but easy for the target server's TCP stack, hence the name, which is the onomatopoeia for slicing in Japanese! 

## Installation

The easiest option for most users will be to pick the binary that suits you from the [releases page](https://github.com/amenaijp/kirikiri/releases), then run the binary from your downloads folder, or move the binary into your PATH. 

Alternatively, you can build the latest version from github:
```shell
git clone https://github.com/amenaijp/kirikiri
cd kirikiri
cargo run
# Or, use `cargo install` to compile and install from source directly into your PATH:
# cargo install --path ./
```

## Usage
```
$ kirikiri --help
kirikiri 0.1.3
A minimal proxy that performs DPI evasion by modifying HTTP and TlS packets sent over it

USAGE:
    kirikiri [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --listen-addr <listen-addr>            Bind on specific addresses or ports [default: 127.0.0.1:1080]
    -t, --request-timeout <request-timeout>    Request timeout, in seconds [default: 10]
```
Most users will be fine simply running `kirikiri`, which starts a SOCKS5 proxy running at `localhost:1080`. 

Then, update your browser settings (search for 'proxy') to use a manually defined proxy. The proxy is at `localhost` or `127.0.0.1` (either works), and the port is `1080`. 

If desired, debug information can be viewed using `RUST_LOG=info`. `kirikiri` will probably log a lot of errors during normal usage, and that's okay! Many of these are external to `kirikiri` and can safely be ignored, but if you really don't want to see those errors, use `RUST_LOG=off`.

## License
`kirikiri` is provided under the terms of the MIT license.
