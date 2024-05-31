# JA3Proxy

Corn R1 / Alps R1 TLS (JA3) Fingerprints through HTTP Proxy

This project is a fork of [ja3proxy](https://github.com/LyleMi/ja3proxy).

Inspired by [DavidBuchanan314](https://github.com/DavidBuchanan314) & his [tests of R1 WebSocket API](https://gist.github.com/DavidBuchanan314/aafce6ba7fc49b19206bd2ad357e47fa). 

## Usage

### Building from source

```bash
git clone https://github.com/CORN-R1/ja3proxy_r1
cd ja3proxy
make
./ja3proxy -port 8080 -client Custom

curl -v -k --proxy http://localhost:8080 https://www.example.com
```

------------------------

### CLI usage

```bash
Usage of ja3proxy:
  -addr string
        proxy listen host
  -port string
        proxy listen port (default "8080")
  -cert string
        proxy tls cert (default "cert.pem")
  -key string
        proxy tls key (default "key.pem")
  -client string
        utls client "Custom" for Corn R1 / Alps R1)
  -version string
        utls client version (default "0")
  -upstream string
        upstream proxy, e.g. 127.0.0.1:1080, socks5 only
  -debug
        enable debug
```

---------------------

## Contribution

If you have any ideas or suggestions, please feel free to submit a pull request. We appreciate any contributions.

## Contact

If you have any questions or suggestions, please feel free to contact us.
