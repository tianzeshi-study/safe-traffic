# safe-server-traffic 

a simple-use  firewall, control   traffic dynamically.  Support adding and removing netfilter table  rules  automatically. 

### How to Use 

first  clone this repo, and run the following command   
```
sudo cargo run -- -c ./example.toml 
```

or 

```
cargo build  --release 
sudo ./target/release/safe-server-traffic -c ./SimpleExample.toml
```

make sure you have rust toolchain installed.

notice: It require sudo   to communicate  with nft command, make sure you have root permissions to run    the binary 