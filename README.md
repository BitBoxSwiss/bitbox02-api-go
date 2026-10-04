# BitBox02 Go library

The API exposed by the `api` packages is currently unstable. Expect frequent breaking changes until
we start tagging versions.

## Updating the BitBox02 protobuf message files

Make sure you have `protoc` and
[protoc-gen-go](https://developers.google.com/protocol-buffers/docs/reference/go-generated)
installed, then clone the [BitBox02 firmware repository](https://github.com/BitBoxSwiss/bitbox02-firmware):

`git clone https://github.com/BitBoxSwiss/bitbox02-firmware.git`

```sh
rm -rf api/firmware/messages/{*.pb.go,*.proto}
cp /path/to/bitbox02-firmware/messages/*.proto api/firmware/messages/
rm api/firmware/messages/backup.proto
./api/firmware/messages/generate.sh
```

## Updating the Bitcoin transaction test vectors

The vectors in [api/firmware/testdata/btc-transaction-test-vectors.json](api/firmware/testdata/btc-transaction-test-vectors.json)
are generated in the BitBox02 firmware repository. Do not modify this JSON file directly.

The source of truth is the Rust constructors in
[`src/rust/bitbox-test-vectors/src/btc_transaction/cases/`](https://github.com/BitBoxSwiss/bitbox02-firmware/tree/master/src/rust/bitbox-test-vectors/src/btc_transaction/cases).
Make changes there and regenerate the canonical JSON following the
[test vector generation instructions](https://github.com/BitBoxSwiss/bitbox02-firmware/blob/master/src/rust/bitbox-test-vectors/README.md).
Then copy the generated file byte-for-byte into this repository:

```sh
cp /path/to/bitbox02-firmware/src/rust/bitbox-test-vectors/testdata/btc-transaction-test-vectors.json \
    api/firmware/testdata/btc-transaction-test-vectors.json
```

## Simulator tests

The `TestSimulator*` integration tests run against BitBox02 simulators. The simulators are
automatically downloaded based on
[api/firmware/testdata/simulators.json](api/firmware/testdata/simulators.json), and the tests run
against each one.

To run them, use:

    go test -v -run TestSimulator ./...

If you want to test against a custom simulator build (e.g. when developing new firmware features),
you can run:

    SIMULATOR=/path/to/simulator go test -v -run TestSimulator ./...

In this case, only the given simulator will be used, and the ones defined in `simulators.json` will be
ignored. Make sure to use an absolute path to the simulator.
