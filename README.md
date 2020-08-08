# SENG Go-Server
This is a multi-threaded rewrite of the [SENG Server](https://github.com/sengsgx/sengsgx/tree/master/seng_server) in Go.
The SENG Go-Server is meant to scale better for high numbers of connected SENG Runtime/SDK clients.
It is based on the [pion DTLS](https://github.com/pion/dtls) library and currently only supports ECDSA server and client certificates.
The SGX certificate extensions and attestation checks have been reimplemented by us in native Go.
Note that not all features have been ported yet.
The SENG Go-Server currently uses the `ECDHE-ECDSA-AES128-GCM-SHA256` cipher suite and is compatible with the SENG Runtime and the SENG SDK (with ECDSA enabled).

## Server Preparation
0. follow the [SENG Server](https://github.com/sengsgx/sengsgx/tree/master/seng_server#build) instructions for preparing SENG, plus the tunnel interface and firewall

1. generate the ECDSA key and certificate for the SENG Go-Server:
	```
	# create server ECDSA key and certificate
	openssl ecparam -out gosrv_key.pem -name secp384r1 -genkey
	openssl req -new -key gosrv_key.pem -x509 -nodes -days 365 -out gosrv_cert.pem
	```

	CAUTION: remember to replace the content of the `srv_cert.pem` file in the SENG Runtime repo with the SENG Go-Server certificate and replace the hardcoded certificate in the SENG SDK code to let them pin the SENG Go-Server certificate.

2. download Intel Attestation Report Root CA Certificate:
	```
	wget https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem
	```

3. for `-db` run option: generate the SQLite3 demo database of the SENG Server (cf. [run instructions](https://github.com/sengsgx/sengsgx/tree/master/seng_server#run)):
	```
	# create demo database (note: get the file from the main sengsgx repo)
	sqlite3 demo_sqlite3.db < seng_db_creator.sql
	```

## Client-side Preparation
The SENG Go-Server is  compatible with the [SENG Runtime](https://github.com/sengsgx/sengsgx/tree/master/seng_runtime) and the [SENG SDK](https://github.com/sengsgx/sengsgx/tree/master/seng_sdk).
As the SENG Server currently only supports RSA certificates and the SENG Go-Server only ECDSA certificates, you have to adapt and re-compile the client-side components.

Uncomment the `#define USE_ECDSA 1` line in the following SENG Runtime files:
* [DT_RaSSLTunnelNetif_OpenSSL.cpp](https://github.com/sengsgx/sengsgx/blob/master/seng_runtime/lwip_based_client_lib/dtls_tunnel_netif/src/DT_RaSSLTunnelNetif_OpenSSL.cpp)
* [DT_SSLEngineClient_OpenSSL.cpp](https://github.com/sengsgx/sengsgx/blob/master/seng_runtime/lwip_based_client_lib/dtls_tunnel_netif/src/DT_SSLEngineClient_OpenSSL.cpp)
* sgx-ra-tls/openssl-ra-attester.c

Uncomment the `#define USE_ECDSA 1` line in the following SENG SDK files:
* [DT_SSLEngineClient_OpenSSL.cpp](https://github.com/sengsgx/sengsgx/blob/master/seng_sdk/enclave/seng/src/DT_SSLEngineClient_OpenSSL.cpp)
* [seng_tunnelmodule.cpp](https://github.com/sengsgx/sengsgx/blob/master/seng_sdk/enclave/seng/src/seng_tunnelmodule.cpp)
* [trusted/openssl-ra-attester.c](https://github.com/sengsgx/sengsgx/blob/master/seng_sdk/external/sgx-ra-tls/trusted/openssl-ra-attester.c)

and then re-build the sgx-ra-tls libraries, the SENG Runtime and the SENG SDK.
Ensure that the SENG Runtime and SENG SDK pin the SENG Go-Server instead of the SENG Server certificate.


## Run
```
go run ./sengsrv [options] <tunnel_ipv4> <tunnel_port>

Arguments:
    tunnel_ipv4     = IPv4 address on which the server will listen
    tunnel_port     = UDP port on which the server will listen

Options:
-cert string
    server certificate path (only ECDSA)
-db string
    optional path to SQLite3 database
-key string
    server private key path (only ECDSA)
-netfilter
    not supported yet
-shadowing
    not supported yet
```

Sample invocation:
```
go run ./sengsrv/ -cert ./gosrv_cert.pem -key ./gosrv_key.pem -db ./demo_sqlite3.db 127.0.0.1 12345
```

## Limitations
The SENG Go-Server prototype does not yet support the following features of the SENG Server:
* SENG Netfilter Extension support
* Automatic Port Shadowing (unlikely to be added)
* Missing a clean, graceful shutdown process and timeouts for established application tunnels
* Tests are rudimentary / just serve as placeholders
* SGX certificate checks currently consider any certificate of the chain, not only the leaf certificate
