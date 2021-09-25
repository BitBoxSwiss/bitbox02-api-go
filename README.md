# BitBox02 Go library

The API of the api packages are currenly unstable. Expect frequent breaking changes until we start
tagging versions.

## Comand to update the BitBox02 protobuf message files

Clone the [BitBox02 firmware repo](https://github.com/digitalbitbox/bitbox02-firmware):

`git clone https://github.com/digitalbitbox/bitbox02-firmware.git`

```sh
rm -rf api/firmware/messages/*
cp /path/to/bitbox02-firmware/messages/*.proto api/firmware/messages/
rm api/firmware/messages/backup.proto
go generate ./...
```
