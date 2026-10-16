# Protocol fixtures

These files are interoperability cases for the [protocol
reference](../../docs/protocol/README.md), with its license and additional permission
for compatible implementations.

All `insecure-test` and `auth/insecure-*` keys are public test material. Never use them
as deployment trust anchors.

## Regenerate fixtures

After an intentional change to the example policy or protocol format, regenerate
the fixtures and update any affected examples in the protocol reference:

```sh
go test ./pkg/bundle/ -run TestGoldenBundle -update
go test ./pkg/endpointauth/ -run TestGoldenFiles -update
```

Signatures are deterministic (Ed25519 and RFC 6979 ECDSA), so running the generators
with unchanged inputs should leave bytes unchanged.

See [Golden files](../../docs/protocol/README.md#golden-files) for the fixed clock,
request order and expected accept/reject outcomes.
