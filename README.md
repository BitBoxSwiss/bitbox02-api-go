# BitBox02 Go library

The API of the api packages are currenly unstable. Expect frequent breaking changes until we start
tagging versions.

## Comand to update the BitBox02 protobuf message files

Clone the [BitBox02 firmware repo](https://github.com/BitBoxSwiss/bitbox02-firmware):

Make sure you have `protoc` and
[protoc-gen-go](https://developers.google.com/protocol-buffers/docs/reference/go-generated)
installed:

`git clone https://github.com/BitBoxSwiss/bitbox02-firmware.git`

```sh
rm -rf api/firmware/messages/{*.pb.go,*.proto}
cp /path/to/bitbox02-firmware/messages/*.proto api/firmware/messages/
rm api/firmware/messages/backup.proto
./api/firmware/messages/generate.sh
```
