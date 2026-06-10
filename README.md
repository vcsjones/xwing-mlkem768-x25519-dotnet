X-Wing ML-KEM-768-X25519 for .NET
========

This is an implementation of the X-Wing composite KEM for .NET 11 preview 5 and later.

Resources:
* X-Wing Internet-Draft: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/

# Using

```C#
using XWingMLKem768X25519;

using XWingMLKem768X25519 recipient = XWingMLKem768X25519.GenerateKey();
byte[] encapsulationKey = recipient.ExportEncapsulationKey();

using XWingMLKem768X25519 sender = XWingMLKem768X25519.ImportEncapsulationKey(encapsulationKey);
sender.Encapsulate(out byte[] ciphertext, out byte[] senderSharedSecret);

byte[] recipientSharedSecret = recipient.Decapsulate(ciphertext);
```

Span-based overloads are also available for encapsulation, decapsulation, and raw key export.

# Tests

Tests include an X-Wing draft test vector and can be run with `dotnet test`.
