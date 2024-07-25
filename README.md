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

## Simulator tests

The `TestSimulator*` tests run integration against BitBox02 simulators. They are automatically
downloaded based on [api/firmware/testdata/simulators.json](api/firmware/testdata/simulators.json),
and each one is tested with.

To run them, use:

    go test -v -run TestSimulator ./...

If you want to test against a custom simulator build (e.g. when developing new firmware features),
you can run:

    SIMULATOR=/path/to/simulator go test -v -run TestSimulator ./...

In this case, only the given simulator will be used, and the ones defined in simulators.json will be
ignored.
