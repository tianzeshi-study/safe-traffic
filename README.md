# safe-traffic 

a simple-use  firewall, control   traffic dynamically.  Support adding and removing netfilter table  rules  automatically. 

### How to Use 

first  clone this repo, and run the following command   
```
cargo build  --release 
chmod 700 target/release/safe-traffic-*
sudo ./target/release/safe-traffic-daemon -c ./SimpleExample.toml &
sudo ./target/release/safe-traffic-cli --help
```

make sure you have rust toolchain installed before running the command.

notice: It require sudo   to communicate  with nft command, make sure you have root permissions to run    the binary 