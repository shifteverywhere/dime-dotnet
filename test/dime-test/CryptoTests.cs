//
//  CryptoTests.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class CryptoTests
{

    [TestMethod]
    public void GenerateSignatureTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() { KeyCapability.Sign }, null);
        var sig = Dime.Crypto.GenerateSignature(Commons.Payload, key);
        Dime.Crypto.VerifySignature(Commons.Payload, sig, key);
    }

    [TestMethod]
    public void GenerateSignatureTest2() 
    {
        byte[] sig = Utility.FromBase64("Ey5hGXAXFq1WgVS0bhzmx4qfT6VdsTQtZDF4PSRTBAcWZmO/2jhFPmV2YEy5bIA8PHDwRHXtbdU5Psi3ln7cBA");
        const string encoded = "Di:KEY.eyJ1aWQiOiJmNjYxMGUyNS1jYTA1LTQzMWItODhlZS1iYzczNmZiNWQxZmUiLCJwdWIiOiIyVERYZG9Odm9NZFd4VGh4Z2FxVG5McTl0aFdWYXZFeUFWaUx2ekNrc2VxMWtlRDNrOGJ4UkY2cVciLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjQ4OjAxLjEyMDUxOFoiLCJrZXkiOiJTMjFUWlNMQmFjYXhURVVBVFExVG91dENIRkI1NFA2R25vTTNLU0hXMUpvNTgxZUZzalZYajZEWHBYMjdKTFRCSFVQaWNmbUVKZ2FxNnhaeEoxeVN3TldieTQ2cUdzQ3hrUmpCIn0";
        var key = Item.Import<Key>(encoded);
        Dime.Crypto.VerifySignature(Commons.Payload, sig, key);
    }

    [TestMethod]
    public void GenerateGenerateSharedSecretTest1() 
    {
        var clientKey = Key.Generate(new List<KeyCapability>() { KeyCapability.Exchange }, null);
        var serverKey = Key.Generate(new List<KeyCapability>() { KeyCapability.Exchange }, null);
        var shared1 = clientKey.GenerateSharedSecret(serverKey.PublicCopy(), new List<KeyCapability>() {KeyCapability.Encrypt});
        var shared2 = clientKey.PublicCopy().GenerateSharedSecret(serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        Assert.IsTrue(shared1.HasCapability(KeyCapability.Encrypt));
        Assert.IsTrue(shared2.HasCapability(KeyCapability.Encrypt));
        Assert.AreEqual(shared1.Secret, shared2.Secret);
    }

    [TestMethod]
    public void GenerateGenerateSharedSecretTest2() 
    {
        const string encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjQ2ODE0OFoiLCJrZXkiOiIyREJWdDhWOWhSOTU0Mjl5MWdja3lXaVBoOXhVRVBxb2hFUTFKQjRnSjlodmpaV1hheE0zeWVURXYiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
        const string encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMyWiIsInB1YiI6IjJEQlZ0bk1aUDc5aEpWTUpwVnlIR29rRU1QWEM2cXkzOHNoeVRIaEpBekY5TlVRdlFmUWRxNGRjMyJ9";
        const string encodedShared = "STN.2bLW8dmYQr4jrLSKiTLggLU1cbVMkmK1uUChchxYzAMC9fshCG";
        var clientKey = Item.Import<Key>(encodedClient);
        var serverKey = Item.Import<Key>(encodedServer);
        var shared = clientKey.GenerateSharedSecret(serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        Assert.AreEqual(encodedShared, shared.Secret);
    }

    [TestMethod]
    public void GenerateGenerateSharedSecretTest3() 
    {
        const string encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDE1MloiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
        const string encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMxNloiLCJrZXkiOiIyREJWdDhWOWJ4R2pGS0xoa2FodEo0UUtRc3F6Y1ZjNGFqeWNxSnQ4eFZQTlZkYnBveHBLdkFZaUoiLCJwdWIiOiIyREJWdG5NWlA3OWhKVk1KcFZ5SEdva0VNUFhDNnF5MzhzaHlUSGhKQXpGOU5VUXZRZlFkcTRkYzMifQ";
        const string encodedShared = "STN.2bLW8dmYQr4jrLSKiTLggLU1cbVMkmK1uUChchxYzAMC9fshCG";
        var clientKey = Item.Import<Key>(encodedClient);
        var serverKey = Item.Import<Key>(encodedServer);
        var shared = clientKey.GenerateSharedSecret(serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        Assert.AreEqual(encodedShared, shared.Secret);
    }

    [TestMethod]
    public void EncryptTest1() 
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Encrypt}, null);
        var cipherText = Dime.Crypto.Encrypt(Encoding.UTF8.GetBytes(Commons.Payload), key);
        Assert.IsNotNull(cipherText);
        var plainText = Dime.Crypto.Decrypt(cipherText, key);
        Assert.IsNotNull(plainText);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(plainText));
    }

    [TestMethod]
    public void EncryptTest2() 
    {
        const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
        var key = Item.Import<Key>(encoded);
        var cipherText = Dime.Crypto.Encrypt(Encoding.UTF8.GetBytes(Commons.Payload), key);
        Assert.IsNotNull(cipherText);
        var plainText = Dime.Crypto.Decrypt(cipherText, key);
        Assert.IsNotNull(plainText);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(plainText));
    }

    [TestMethod]
    public void DecryptTest1() 
    {
        const string cipherText = "Haau0FPwXKpwv8IL4R0n5bhG5IIhlVFEllSwm4r6lN2Ur9LGIX7yfMr1jZeHsqbCsvcq5d3EF2pV0P5Xe7z5grwKNRIy";
        const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
        var key = Item.Import<Key>(encoded);
        var plainText = Dime.Crypto.Decrypt(Utility.FromBase64(cipherText), key);
        Assert.IsNotNull(plainText);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(plainText));
    }

    [TestMethod]
    public void GenerateHashTest1() {
        const string expected = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
        var data = Encoding.UTF8.GetBytes(Commons.Payload);
        var hash = Dime.Crypto.GenerateHash(data);
        Assert.IsNotNull(hash);
        var hex = Utility.ToHex(hash);
        Assert.AreEqual(expected, hex);
    }

    [TestMethod]
    public void CryptoPlatformExchangeTest1()
    {
        var clientKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiIzOWYxMzkzMC0yYTJhLTQzOWEtYjBkNC1lMzJkMzc4ZDgyYzciLCJwdWIiOiIyREJWdG5NWlVjb0dZdHd3dmtjYnZBSzZ0Um1zOUZwNGJ4dHBlcWdha041akRVYkxvOXdueWRCUG8iLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0LjQ0NDA0MVoiLCJrZXkiOiIyREJWdDhWOEF4UWR4UFZVRkJKOWdScFA1WDQzNnhMbVBrWW9RNzE1cTFRd2ZFVml1NFM3RExza20ifQ");
        var serverKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiJjY2U1ZDU1Yi01NDI4LTRhMDUtOTZmYi1jZmU4ZTE4YmM3NWIiLCJwdWIiOiIyREJWdG5NYTZrcjNWbWNOcXNMSmRQMW90ZGtUMXlIMTZlMjV0QlJiY3pNaDFlc3J3a2hqYTdaWlEiLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0Ljg0NjEyMVoiLCJrZXkiOiIyREJWdDhWOTV5N2lvb1A0bmRDajd6d3dqNW1MVExydVhaaGg0RTJuMUE0SHoxQkIycHB5WXY1blIifQ");
        var shared1 = Dime.Crypto.GenerateSharedSecret(clientKey, serverKey.PublicCopy(), new List<KeyCapability>() {KeyCapability.Encrypt});
        var shared2 = Dime.Crypto.GenerateSharedSecret(clientKey.PublicCopy(), serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        var hash1 = Utility.ToHex(shared1);
        var hash2 = Utility.ToHex(shared2);
        Assert.AreEqual("8c0c2c98d5839bc59a61fa0bea987aea6f058c08c214ab65d1a87e2a7913cea9", hash1);
        Assert.AreEqual(hash1, hash2);
    }

}