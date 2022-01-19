# Tor Proxy

### Description
Standalone Tor proxy for Windows, macOS, and Linux that allows proxying HTTP and HTTPS requests through the Tor network.

### Building
This program can be built with the following commands:
```
make dependencies
make
```

### Usage
Once this program connects to the Tor network, it will start listening on localhost:9060. HTTP and HTTPS requests can then be proxied through the Tor network by making an HTTP request to localhost:9060 with the desired URI as the path. Here's some examples of how the URI should look: 
```
http://localhost:9060/http://example.com
http://localhost:9060/https://check.torproject.org
http://localhost:9060/https://www.facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion
```
