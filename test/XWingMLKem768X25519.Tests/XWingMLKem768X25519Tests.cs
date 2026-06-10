using System.Runtime.CompilerServices;
using System.Text;

namespace XWingMLKem768X25519.Tests;

public static class XWingMLKem768X25519Tests {
    public static bool IsSupported => XWingMLKem768X25519.IsSupported;

    [ConditionalFact]
    public static void Constants_MatchDraftSizes() {
        Assert.Equal(32, XWingMLKem768X25519.DecapsulationKeySizeInBytes);
        Assert.Equal(1216, XWingMLKem768X25519.EncapsulationKeySizeInBytes);
        Assert.Equal(1120, XWingMLKem768X25519.CiphertextSizeInBytes);
        Assert.Equal(32, XWingMLKem768X25519.SharedSecretSizeInBytes);
    }

    [ConditionalFact]
    public static void EncapsulateDecapsulate_Roundtrip() {
        using XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        key.Encapsulate(out byte[] ciphertext, out byte[] encapsulatedSharedSecret);

        byte[] decapsulatedSharedSecret = key.Decapsulate(ciphertext);

        Assert.Equal(XWingMLKem768X25519.CiphertextSizeInBytes, ciphertext.Length);
        Assert.Equal(XWingMLKem768X25519.SharedSecretSizeInBytes, encapsulatedSharedSecret.Length);
        Assert.Equal(encapsulatedSharedSecret, decapsulatedSharedSecret);
    }

    [ConditionalFact]
    public static void GenerateKey_ProducesUniqueKeys() {
        using XWingMLKem768X25519 first = XWingMLKem768X25519.GenerateKey();
        using XWingMLKem768X25519 second = XWingMLKem768X25519.GenerateKey();

        Assert.NotEqual(first.ExportDecapsulationKey(), second.ExportDecapsulationKey());
        Assert.NotEqual(first.ExportEncapsulationKey(), second.ExportEncapsulationKey());
    }

    [ConditionalFact]
    public static void Encapsulate_ProducesUniqueCiphertextsAndSharedSecrets() {
        using XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        byte[] encapsulationKey = key.ExportEncapsulationKey();

        using XWingMLKem768X25519 publicKey = XWingMLKem768X25519.ImportEncapsulationKey(encapsulationKey);
        publicKey.Encapsulate(out byte[] firstCiphertext, out byte[] firstSharedSecret);
        publicKey.Encapsulate(out byte[] secondCiphertext, out byte[] secondSharedSecret);

        Assert.NotEqual(firstCiphertext, secondCiphertext);
        Assert.NotEqual(firstSharedSecret, secondSharedSecret);
    }

    [ConditionalFact]
    public static void ImportEncapsulationKey_EncapsulatesForDecapsulationKey() {
        using XWingMLKem768X25519 privateKey = XWingMLKem768X25519.GenerateKey();
        using XWingMLKem768X25519 publicKey = XWingMLKem768X25519.ImportEncapsulationKey(privateKey.ExportEncapsulationKey());

        publicKey.Encapsulate(out byte[] ciphertext, out byte[] encapsulatedSharedSecret);
        byte[] decapsulatedSharedSecret = privateKey.Decapsulate(ciphertext);

        Assert.Equal(encapsulatedSharedSecret, decapsulatedSharedSecret);
    }

    [ConditionalFact]
    public static void SpanOverloads_Roundtrip() {
        using XWingMLKem768X25519 generated = XWingMLKem768X25519.GenerateKey();

        byte[] decapsulationKey = new byte[XWingMLKem768X25519.DecapsulationKeySizeInBytes];
        generated.ExportDecapsulationKey(decapsulationKey);

        using XWingMLKem768X25519 privateKey = XWingMLKem768X25519.ImportDecapsulationKey(decapsulationKey.AsSpan());

        byte[] encapsulationKey = new byte[XWingMLKem768X25519.EncapsulationKeySizeInBytes];
        privateKey.ExportEncapsulationKey(encapsulationKey);

        using XWingMLKem768X25519 publicKey = XWingMLKem768X25519.ImportEncapsulationKey(encapsulationKey.AsSpan());

        byte[] ciphertext = new byte[XWingMLKem768X25519.CiphertextSizeInBytes];
        byte[] encapsulatedSharedSecret = new byte[XWingMLKem768X25519.SharedSecretSizeInBytes];
        publicKey.Encapsulate(ciphertext.AsSpan(), encapsulatedSharedSecret.AsSpan());

        byte[] decapsulatedSharedSecret = new byte[XWingMLKem768X25519.SharedSecretSizeInBytes];
        privateKey.Decapsulate(ciphertext.AsSpan(), decapsulatedSharedSecret.AsSpan());

        Assert.Equal(encapsulatedSharedSecret, decapsulatedSharedSecret);
    }

    [ConditionalFact]
    public static void ExportImportDecapsulationKey_PreservesEncapsulationKey() {
        using XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        byte[] decapsulationKey = key.ExportDecapsulationKey();
        byte[] encapsulationKey = key.ExportEncapsulationKey();

        using XWingMLKem768X25519 imported = XWingMLKem768X25519.ImportDecapsulationKey(decapsulationKey);

        Assert.Equal(decapsulationKey, imported.ExportDecapsulationKey());
        Assert.Equal(encapsulationKey, imported.ExportEncapsulationKey());
    }

    [ConditionalFact]
    public static void DraftTestVector_DerivesPublicKeyAndDecapsulates() {
        byte[] seed = FromHex("""
            7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
            """);
        byte[] expectedEncapsulationKey = FromHex("""
            e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d
            a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b
            2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534
            01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361
            0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c
            1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06
            3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae
            a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e
            ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40
            b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c
            1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362
            543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564
            955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e
            d55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af
            829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519
            317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4
            87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be
            3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587
            ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584
            fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c
            8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09
            0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95
            2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406
            5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5
            7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173
            46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573
            cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369
            8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c
            1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44
            d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96
            9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611
            d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734
            9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06
            eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534
            """);
        byte[] ciphertext = FromHex("""
            b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a273f8f96
            e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb831f68251219aabdd
            723bc6512041acbaef8af44265524942b902e68ffd23221cda70b1b55d776a92d1143ea3
            a0c475f63ee6890157c7116dae3f62bf72f60acd2bb8cc31ce2ba0de364f52b8ed38c79d
            719715963a5dd3842d8e8b43ab704e4759b5327bf027c63c8fa857c4908d5a8a7b88ac7f
            2be394d93c3706ddd4e698cc6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c12
            44b699046f5a01caa0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb88
            70dc328c5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787
            517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2f49384e5
            5456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be582dbee985e038ff
            c346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f89bc5e5442f51f9a5937b102b
            a3beaebf6e1c58380a4a5fedce4a4e5026f88f528f59ffd2db41752b3a3d90efabe46389
            9b7d40870c530c8841e8712b733668ed033adbfafb2d49d37a44d4064e5863eb0af0a08d
            47b3cc888373bc05f7a33b841bc2587c57eb69554e8a3767b7506917b6b70498727f16ea
            c1a36ec8d8cfaf751549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b
            594d6e247f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee0936
            7976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b535175373461b77600
            2d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b895ef7f0147a0dc8
            1bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e44e17aa2f8177010afd78a97
            ce0868d1629ebb294c5151812c583daeb88685220f4da9118112e07041fcc24d5564a99f
            dbde28869fe0722387d7a9a4d16e1cc8555917e09944aa5ebaaaec2cf62693afad42a3f5
            18fce67d273cc6c9fb5472b380e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe6
            2d00e4c790d965d7a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f
            08942278a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b3
            5fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb8943015b243
            14cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547bb2cc40c9d38cbd30
            99b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b1d2bcb4baaf21cc7fef1e038
            06ca96299df0dfbc56e1b2b43e4fc20c37f834c4af62127e7dae86c3c25a2f696ac8b589
            dec71d595bfbe94b5ed4bc07d800b330796fda89edb77be0294136139354eb8cd3759157
            8f9c600dd9be8ec6219fdd507adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d63240
            7f31ed6f7cb1600de56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3
            e6fb2e15
            """);
        byte[] expectedSharedSecret = FromHex("""
            d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384
            """);

        using XWingMLKem768X25519 key = XWingMLKem768X25519.ImportDecapsulationKey(seed);

        Assert.Equal(expectedEncapsulationKey, key.ExportEncapsulationKey());
        Assert.Equal(expectedSharedSecret, key.Decapsulate(ciphertext));
    }

    [ConditionalFact]
    public static void PublicKey_DoesNotExportOrDecapsulatePrivateKey() {
        using XWingMLKem768X25519 privateKey = XWingMLKem768X25519.GenerateKey();
        using XWingMLKem768X25519 publicKey = XWingMLKem768X25519.ImportEncapsulationKey(privateKey.ExportEncapsulationKey());

        Assert.Throws<InvalidOperationException>(() => publicKey.ExportDecapsulationKey());
        Assert.Throws<InvalidOperationException>(() => publicKey.Decapsulate(new byte[XWingMLKem768X25519.CiphertextSizeInBytes]));
    }

    [ConditionalFact]
    public static void ArgValidation_InvalidSizes() {
        Assert.Throws<ArgumentException>("source", static () =>
            XWingMLKem768X25519.ImportDecapsulationKey(
                new byte[XWingMLKem768X25519.DecapsulationKeySizeInBytes - 1]));
        Assert.Throws<ArgumentException>("source", static () =>
            XWingMLKem768X25519.ImportEncapsulationKey(
                new byte[XWingMLKem768X25519.EncapsulationKeySizeInBytes - 1]));

        using XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        Assert.Throws<ArgumentException>("ciphertext", () => key.Decapsulate(new byte[XWingMLKem768X25519.CiphertextSizeInBytes - 1]));
        Assert.Throws<ArgumentException>("destination", () => key.ExportEncapsulationKey(new byte[XWingMLKem768X25519.EncapsulationKeySizeInBytes - 1]));
    }

    [ConditionalFact]
    public static void Encapsulate_ArgValidation_OverlappingBuffers() {
        using XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        byte[] buffer = new byte[XWingMLKem768X25519.CiphertextSizeInBytes];

        Assert.Throws<ArgumentException>("sharedSecret", () =>
            key.Encapsulate(
                buffer.AsSpan(0, XWingMLKem768X25519.CiphertextSizeInBytes),
                buffer.AsSpan(1, XWingMLKem768X25519.SharedSecretSizeInBytes)));
    }

    [ConditionalFact]
    public static void Decapsulate_ArgValidation_OverlappingBuffers() {
        using XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        byte[] buffer = new byte[XWingMLKem768X25519.CiphertextSizeInBytes];

        Assert.Throws<ArgumentException>("sharedSecret", () =>
            key.Decapsulate(
                buffer.AsSpan(0, XWingMLKem768X25519.CiphertextSizeInBytes),
                buffer.AsSpan(1, XWingMLKem768X25519.SharedSecretSizeInBytes)));
    }

    [ConditionalFact]
    public static void UseAfterDispose() {
        XWingMLKem768X25519 key = XWingMLKem768X25519.GenerateKey();
        key.Dispose();
        key.Dispose();

        byte[] ciphertext = new byte[XWingMLKem768X25519.CiphertextSizeInBytes];
        byte[] sharedSecret = new byte[XWingMLKem768X25519.SharedSecretSizeInBytes];
        byte[] encapsulationKey = new byte[XWingMLKem768X25519.EncapsulationKeySizeInBytes];
        byte[] decapsulationKey = new byte[XWingMLKem768X25519.DecapsulationKeySizeInBytes];

        Assert.Throws<ObjectDisposedException>(() => key.Encapsulate(ciphertext, sharedSecret));
        Assert.Throws<ObjectDisposedException>(() => key.Encapsulate(out _, out _));
        Assert.Throws<ObjectDisposedException>(() => key.Decapsulate(ciphertext));
        Assert.Throws<ObjectDisposedException>(() => key.Decapsulate(ciphertext, sharedSecret));
        Assert.Throws<ObjectDisposedException>(() => key.ExportEncapsulationKey());
        Assert.Throws<ObjectDisposedException>(() => key.ExportEncapsulationKey(encapsulationKey));
        Assert.Throws<ObjectDisposedException>(() => key.ExportDecapsulationKey());
        Assert.Throws<ObjectDisposedException>(() => key.ExportDecapsulationKey(decapsulationKey));
    }

    internal sealed class ConditionalFactAttribute : FactAttribute {
        public ConditionalFactAttribute(
            [CallerFilePath] string sourceFilePath = "",
            [CallerLineNumber] int sourceLineNumber = 0) : base(sourceFilePath, sourceLineNumber) {
            Skip = "X-Wing ML-KEM-768-X25519 is not supported on this platform.";
            SkipType = typeof(XWingMLKem768X25519Tests);
            SkipUnless = nameof(XWingMLKem768X25519Tests.IsSupported);
        }
    }

    private static byte[] FromHex(string hex) {
        StringBuilder normalized = new(hex.Length);

        foreach (char c in hex) {
            if (!char.IsWhiteSpace(c)) {
                normalized.Append(c);
            }
        }

        return Convert.FromHexString(normalized.ToString());
    }
}
