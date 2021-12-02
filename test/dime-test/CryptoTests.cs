//
//  Crypto.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class CryptoTests
    {

        [TestMethod]
        public void GenerateSignatureTest1() 
        {
            String data = "Racecar is racecar backwards.";
            Key key = Crypto.GenerateKey(KeyType.Identity);
            String sig = Crypto.GenerateSignature(data, key);
            Crypto.VerifySignature(data, sig, key);
        }

        [TestMethod]
        public void GenerateSignatureTest2() 
        {
            String sig = "Ey5hGXAXFq1WgVS0bhzmx4qfT6VdsTQtZDF4PSRTBAcWZmO/2jhFPmV2YEy5bIA8PHDwRHXtbdU5Psi3ln7cBA";
            String encoded = "Di:KEY.eyJ1aWQiOiJmNjYxMGUyNS1jYTA1LTQzMWItODhlZS1iYzczNmZiNWQxZmUiLCJwdWIiOiIyVERYZG9Odm9NZFd4VGh4Z2FxVG5McTl0aFdWYXZFeUFWaUx2ekNrc2VxMWtlRDNrOGJ4UkY2cVciLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjQ4OjAxLjEyMDUxOFoiLCJrZXkiOiJTMjFUWlNMQmFjYXhURVVBVFExVG91dENIRkI1NFA2R25vTTNLU0hXMUpvNTgxZUZzalZYajZEWHBYMjdKTFRCSFVQaWNmbUVKZ2FxNnhaeEoxeVN3TldieTQ2cUdzQ3hrUmpCIn0";
            Key key = Item.Import<Key>(encoded);
            Crypto.VerifySignature("Racecar is racecar backwards.", sig, key);
        }

        [TestMethod]
        public void GenerateGenerateSharedSecretTest1() 
        {
            Key clientKey = Key.Generate(KeyType.Exchange);
            String c1 = clientKey.Export();
            String c2 = clientKey.PublicCopy().Export();
            Key serverKey = Key.Generate(KeyType.Exchange);
            String s1 = serverKey.PublicCopy().Export();
            String s2 = serverKey.Export();
            Key shared1 = Crypto.GenerateSharedSecret(clientKey, serverKey.PublicCopy());
            String k = shared1.Secret;
            Key shared2 = Crypto.GenerateSharedSecret(clientKey.PublicCopy(), serverKey);
            Assert.AreEqual(KeyType.Encryption, shared1.Type);
            Assert.AreEqual(KeyType.Encryption, shared2.Type);
            Assert.AreEqual(shared1.Secret, shared2.Secret);
        }

        [TestMethod]
        public void GenerateGenerateSharedSecretTest2() 
        {
            string encodedClient = "Di:KEY.eyJ1aWQiOiJlMTEyMTk2Mi1lMmFiLTQ3M2YtYjJhMS0zZjc5NGU0YTYwMjciLCJwdWIiOiIyREJWdG5NWnkxZG1SR3BxWjV3dDhwUmtUeUZxRU51SHZzMTJadDFjSHc2Y0oyblJLS0w1Z1RKN2YiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjYzNDAyN1oiLCJrZXkiOiIyREJWdDhWOHg0TVJNRml5blI5anZYaGp2S2NGZ1E5c2Zka2NBUGp3czFhYk5idGhVd1NmcWlUdXIifQ";
            string encodedServer = "Di:KEY.eyJ1aWQiOiIzNmU4NzJkOC1hYzJhLTQ4OGYtYjE1ZC1iNjAyNDg5NmZjYTMiLCJwdWIiOiIyREJWdG5NWnU3MUV5WmVmZURpUUVmOEtNOHBySFlZeHVxdHk5M2pQVzREWnVvOWlwbXZoSkh3RkYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjY0MTQyNFoifQ";
            string encodedShared = "22etZAN9s1puDZrjP4eetjWwm2fCRC3yXxf4czVWXH5FuyrVhHVREb3L3";
            Key clientKey = Item.Import<Key>(encodedClient);
            Key serverKey = Item.Import<Key>(encodedServer);
            Key shared = Crypto.GenerateSharedSecret(clientKey, serverKey);
            Assert.AreEqual(encodedShared, shared.Secret);
        }

        [TestMethod]
        public void GenerateGenerateSharedSecretTest3() 
        {
            string encodedClient = "Di:KEY.eyJ1aWQiOiJlMTEyMTk2Mi1lMmFiLTQ3M2YtYjJhMS0zZjc5NGU0YTYwMjciLCJwdWIiOiIyREJWdG5NWnkxZG1SR3BxWjV3dDhwUmtUeUZxRU51SHZzMTJadDFjSHc2Y0oyblJLS0w1Z1RKN2YiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjY0MTExOVoifQ";
            string encodedServer = "Di:KEY.eyJ1aWQiOiIzNmU4NzJkOC1hYzJhLTQ4OGYtYjE1ZC1iNjAyNDg5NmZjYTMiLCJwdWIiOiIyREJWdG5NWnU3MUV5WmVmZURpUUVmOEtNOHBySFlZeHVxdHk5M2pQVzREWnVvOWlwbXZoSkh3RkYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjEwOjUyLjY0MTQxOVoiLCJrZXkiOiIyREJWdDhWOTlSYmZoOVp6bUhYZnlWREpVVG5NWENYc3I2YXJNOW5HY1NZM0tMcTdqMkhtUVJ2UGMifQ";
            string encodedShared = "22etZAN9s1puDZrjP4eetjWwm2fCRC3yXxf4czVWXH5FuyrVhHVREb3L3";
            Key clientKey = Item.Import<Key>(encodedClient);
            Key serverKey = Item.Import<Key>(encodedServer);
            Key shared = Crypto.GenerateSharedSecret(clientKey, serverKey);
            Assert.AreEqual(encodedShared, shared.Secret);
        }

        [TestMethod]
        public void EncryptTest1() 
        {
            string data = "Racecar is racecar backwards.";
            Key key = Key.Generate(KeyType.Encryption);
            byte[] cipherText = Crypto.Encrypt(Encoding.UTF8.GetBytes(data), key);
            Assert.IsNotNull(cipherText);
            byte[] plainText = Crypto.Decrypt(cipherText, key);
            Assert.IsNotNull(plainText);
            Assert.AreEqual(data, System.Text.Encoding.UTF8.GetString(plainText));
        }

        [TestMethod]
        public void EncryptTest2() 
        {
            string data = "Racecar is racecar backwards.";
            string encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            Key key = Item.Import<Key>(encoded);
            byte[] cipherText = Crypto.Encrypt(Encoding.UTF8.GetBytes(data), key);
            Assert.IsNotNull(cipherText);
            byte[] plainText = Crypto.Decrypt(cipherText, key);
            Assert.IsNotNull(plainText);
            Assert.AreEqual(data, System.Text.Encoding.UTF8.GetString(plainText));
        }

        [TestMethod]
        public void DecryptTest1() 
        {
            string cipherText = "Haau0FPwXKpwv8IL4R0n5bhG5IIhlVFEllSwm4r6lN2Ur9LGIX7yfMr1jZeHsqbCsvcq5d3EF2pV0P5Xe7z5grwKNRIy";
            string encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            Key key = Item.Import<Key>(encoded);
            byte[] plainText = Crypto.Decrypt(Utility.FromBase64(cipherText), key);
            Assert.IsNotNull(plainText);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(plainText));
        }

        [TestMethod]
        public void GenerateHashTest1() {
            string expected = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
            byte[] data = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            byte[] hash = Crypto.GenerateHash(data);
            Assert.IsNotNull(hash);
            String hex = Utility.ToHex(hash);
            Assert.AreEqual(expected, hex);
        }

    }

}