# go-huawei-client

Unofficial client library to get data from Huawei router.

This project provides 3 Go modules:

- Cient library (root dir)
- Prometheus exporter binary (`./exporter` dir)
- CLI client binary (`./wei` dir)

Also Docker image for the Prometheus exporter

```sh
docker pull ghcr.io/chickenzord/go-huawei-client:latest
```

## Supported devices

### EG8145V5

- Login and Logout
- List User Devices
- Get Resource Usage
