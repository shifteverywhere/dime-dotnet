//
//  Crypto.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class CryptoTests
    {

        [TestMethod]
        public void GenerateSignatureTest1() 
        {
            const string data = "Racecar is racecar backwards.";
            var key = Crypto.GenerateKey(KeyType.Identity);
            var sig = Crypto.GenerateSignature(data, key);
            Crypto.VerifySignature(data, sig, key);
        }

        [TestMethod]
        public void GenerateSignatureTest2() 
        {
            const string sig = "Ey5hGXAXFq1WgVS0bhzmx4qfT6VdsTQtZDF4PSRTBAcWZmO/2jhFPmV2YEy5bIA8PHDwRHXtbdU5Psi3ln7cBA";
            var encoded = "Di:KEY.eyJ1aWQiOiJmNjYxMGUyNS1jYTA1LTQzMWItODhlZS1iYzczNmZiNWQxZmUiLCJwdWIiOiIyVERYZG9Odm9NZFd4VGh4Z2FxVG5McTl0aFdWYXZFeUFWaUx2ekNrc2VxMWtlRDNrOGJ4UkY2cVciLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjQ4OjAxLjEyMDUxOFoiLCJrZXkiOiJTMjFUWlNMQmFjYXhURVVBVFExVG91dENIRkI1NFA2R25vTTNLU0hXMUpvNTgxZUZzalZYajZEWHBYMjdKTFRCSFVQaWNmbUVKZ2FxNnhaeEoxeVN3TldieTQ2cUdzQ3hrUmpCIn0";
            var key = Item.Import<Key>(encoded);
            Crypto.VerifySignature("Racecar is racecar backwards.", sig, key);
        }

        [TestMethod]
        public void GenerateGenerateSharedSecretTest1() 
        {
            var clientKey = Key.Generate(KeyType.Exchange);
            var c1 = clientKey.Export();
            var c2 = clientKey.PublicCopy().Export();
            var serverKey = Key.Generate(KeyType.Exchange);
            var s1 = serverKey.PublicCopy().Export();
            var s2 = serverKey.Export();
            var shared1 = Crypto.GenerateSharedSecret(clientKey, serverKey.PublicCopy());
            var k = shared1.Secret;
            var shared2 = Crypto.GenerateSharedSecret(clientKey.PublicCopy(), serverKey);
            Assert.AreEqual(KeyType.Encryption, shared1.Type);
            Assert.AreEqual(KeyType.Encryption, shared2.Type);
            Assert.AreEqual(shared1.Secret, shared2.Secret);
        }

        [TestMethod]
        public void GenerateGenerateSharedSecretTest2() 
        {
            const string encodedClient = "Di:KEY.eyJ1aWQiOiJlMTEyMTk2Mi1lMmFiLTQ3M2YtYjJhMS0zZjc5NGU0YTYwMjciLCJwdWIiOiIyREJWdG5NWnkxZG1SR3BxWjV3dDhwUmtUeUZxRU51SHZzMTJadDFjSHc2Y0oyblJLS0w1Z1RKN2YiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjYzNDAyN1oiLCJrZXkiOiIyREJWdDhWOHg0TVJNRml5blI5anZYaGp2S2NGZ1E5c2Zka2NBUGp3czFhYk5idGhVd1NmcWlUdXIifQ";
            const string encodedServer = "Di:KEY.eyJ1aWQiOiIzNmU4NzJkOC1hYzJhLTQ4OGYtYjE1ZC1iNjAyNDg5NmZjYTMiLCJwdWIiOiIyREJWdG5NWnU3MUV5WmVmZURpUUVmOEtNOHBySFlZeHVxdHk5M2pQVzREWnVvOWlwbXZoSkh3RkYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjY0MTQyNFoifQ";
            const string encodedShared = "22etZAN9s1puDZrjP4eetjWwm2fCRC3yXxf4czVWXH5FuyrVhHVREb3L3";
            var clientKey = Item.Import<Key>(encodedClient);
            var serverKey = Item.Import<Key>(encodedServer);
            var shared = Crypto.GenerateSharedSecret(clientKey, serverKey);
            Assert.AreEqual(encodedShared, shared.Secret);
        }

        [TestMethod]
        public void GenerateGenerateSharedSecretTest3() 
        {
            const string encodedClient = "Di:KEY.eyJ1aWQiOiJlMTEyMTk2Mi1lMmFiLTQ3M2YtYjJhMS0zZjc5NGU0YTYwMjciLCJwdWIiOiIyREJWdG5NWnkxZG1SR3BxWjV3dDhwUmtUeUZxRU51SHZzMTJadDFjSHc2Y0oyblJLS0w1Z1RKN2YiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjY0MTExOVoifQ";
            const string encodedServer = "Di:KEY.eyJ1aWQiOiIzNmU4NzJkOC1hYzJhLTQ4OGYtYjE1ZC1iNjAyNDg5NmZjYTMiLCJwdWIiOiIyREJWdG5NWnU3MUV5WmVmZURpUUVmOEtNOHBySFlZeHVxdHk5M2pQVzREWnVvOWlwbXZoSkh3RkYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjY0MTQxOVoiLCJrZXkiOiIyREJWdDhWOTlSYmZoOVp6bUhYZnlWREpVVG5NWENYc3I2YXJNOW5HY1NZM0tMcTdqMkhtUVJ2UGMifQ";
            const string encodedShared = "22etZAN9s1puDZrjP4eetjWwm2fCRC3yXxf4czVWXH5FuyrVhHVREb3L3";
            var clientKey = Item.Import<Key>(encodedClient);
            var serverKey = Item.Import<Key>(encodedServer);
            var shared = Crypto.GenerateSharedSecret(clientKey, serverKey);
            Assert.AreEqual(encodedShared, shared.Secret);
        }

        [TestMethod]
        public void EncryptTest1() 
        {
            const string data = "Racecar is racecar backwards.";
            var key = Key.Generate(KeyType.Encryption);
            var cipherText = Crypto.Encrypt(Encoding.UTF8.GetBytes(data), key);
            Assert.IsNotNull(cipherText);
            var plainText = Crypto.Decrypt(cipherText, key);
            Assert.IsNotNull(plainText);
            Assert.AreEqual(data, System.Text.Encoding.UTF8.GetString(plainText));
        }

        [TestMethod]
        public void EncryptTest2() 
        {
            const string data = "Racecar is racecar backwards.";
            const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            var key = Item.Import<Key>(encoded);
            var cipherText = Crypto.Encrypt(Encoding.UTF8.GetBytes(data), key);
            Assert.IsNotNull(cipherText);
            var plainText = Crypto.Decrypt(cipherText, key);
            Assert.IsNotNull(plainText);
            Assert.AreEqual(data, System.Text.Encoding.UTF8.GetString(plainText));
        }

        [TestMethod]
        public void DecryptTest1() 
        {
            const string cipherText = "Haau0FPwXKpwv8IL4R0n5bhG5IIhlVFEllSwm4r6lN2Ur9LGIX7yfMr1jZeHsqbCsvcq5d3EF2pV0P5Xe7z5grwKNRIy";
            const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            var key = Item.Import<Key>(encoded);
            var plainText = Crypto.Decrypt(Utility.FromBase64(cipherText), key);
            Assert.IsNotNull(plainText);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(plainText));
        }

        [TestMethod]
        public void GenerateHashTest1() {
            const string expected = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
            var data = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            var hash = Crypto.GenerateHash(data);
            Assert.IsNotNull(hash);
            var hex = Utility.ToHex(hash);
            Assert.AreEqual(expected, hex);
        }

        [TestMethod]
        public void GenerateSharedSecretExchangeTest1()
        {
            var clientKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiIzOWYxMzkzMC0yYTJhLTQzOWEtYjBkNC1lMzJkMzc4ZDgyYzciLCJwdWIiOiIyREJWdG5NWlVjb0dZdHd3dmtjYnZBSzZ0Um1zOUZwNGJ4dHBlcWdha041akRVYkxvOXdueWRCUG8iLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0LjQ0NDA0MVoiLCJrZXkiOiIyREJWdDhWOEF4UWR4UFZVRkJKOWdScFA1WDQzNnhMbVBrWW9RNzE1cTFRd2ZFVml1NFM3RExza20ifQ");
            var serverKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiJjY2U1ZDU1Yi01NDI4LTRhMDUtOTZmYi1jZmU4ZTE4YmM3NWIiLCJwdWIiOiIyREJWdG5NYTZrcjNWbWNOcXNMSmRQMW90ZGtUMXlIMTZlMjV0QlJiY3pNaDFlc3J3a2hqYTdaWlEiLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0Ljg0NjEyMVoiLCJrZXkiOiIyREJWdDhWOTV5N2lvb1A0bmRDajd6d3dqNW1MVExydVhaaGg0RTJuMUE0SHoxQkIycHB5WXY1blIifQ");

            var shared1 = Crypto.GenerateSharedSecret(clientKey, serverKey.PublicCopy());
            var shared2 = Crypto.GenerateSharedSecret(clientKey.PublicCopy(), serverKey);

            var hash1 = Utility.ToHex(shared1.RawSecret);
            var hash2 = Utility.ToHex(shared2.RawSecret);

            Assert.AreEqual("8c0c2c98d5839bc59a61fa0bea987aea6f058c08c214ab65d1a87e2a7913cea9", hash1);
            Assert.AreEqual(hash1, hash2);
        }

    }

}