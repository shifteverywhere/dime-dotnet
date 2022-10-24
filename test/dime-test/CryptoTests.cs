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
using System.Text.Json;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class CryptoTests
{

    [TestMethod]
    public void HasCryptoSuiteTest1() 
    {
        Assert.IsTrue(Dime.Crypto.HasCryptoSuite("DSC"));
        Assert.IsFalse(Dime.Crypto.HasCryptoSuite("NSA"));
    }

    [TestMethod]
    public void AllCryptoSuitesTest1() 
    {
        var suiteNames = Dime.Crypto.AllCryptoSuites();
        Assert.IsNotNull(suiteNames);
        Assert.AreEqual(2, suiteNames.Count);
        Assert.IsTrue(suiteNames.Contains("DSC"));
        Assert.IsTrue(suiteNames.Contains("STN"));
    }

    [TestMethod]
    public void GenerateNameTest1() 
    {
        var key = Key.Generate(KeyCapability.Sign);
        var identifier = Dime.Crypto.GenerateKeyName(key);
        Assert.IsNotNull(identifier);
        Assert.AreEqual(16, identifier.Length);
    }

    [TestMethod]
    public void GenerateNameTest2() 
    {
        const string hex = "506f85299f6a2a4b";
        const string encoded = "Di:KEY.eyJ1aWQiOiIyYTY5ZjJkMC1kNzQ2LTQxNzYtOTg5NS01MDcyNzRlNzJiYjkiLCJwdWIiOiJTVE4uMkI4VzZCNjRRTTlBeDRvdzNjb1Y0TlJrTW95MWNXUzR4N0FYYTRzdnd5dVJlQWtQNG8iLCJpYXQiOiIyMDIyLTA2LTExVDEwOjI3OjM0Ljk5NjIzOFoiLCJ1c2UiOlsic2lnbiJdLCJrZXkiOiJTVE4uQXhwZ3Z2N0FYS2lhalNEQlBCZ0ZCbndzSkoyUXpXSGFUaWpFY29LcEx6YUo5VVlpOGVKNGg0bkJFQnVSN2NldWtVQm5waWU1NkxZQW5EdHQ3Y2V3aVczd0FGTDdFIn0";
        var key = Item.Import<Key>(encoded);
        var identifier = Dime.Crypto.GenerateKeyName(key);
        Assert.AreEqual(hex, identifier);
    }
    
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
        var sig = Utility.FromBase64("Ey5hGXAXFq1WgVS0bhzmx4qfT6VdsTQtZDF4PSRTBAcWZmO/2jhFPmV2YEy5bIA8PHDwRHXtbdU5Psi3ln7cBA");
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
        Assert.AreEqual(expected, hash);
    }

    [TestMethod]
    public void SuiteTest1() 
    {
        var dscKey = Key.Generate(KeyCapability.Sign);
        Assert.IsNotNull(dscKey);
        Assert.AreEqual("DSC", dscKey.CryptoSuiteName);
        Utility.FromBase64(dscKey.Secret[4..]);
        Utility.FromBase64(dscKey.Public[4..]);
        var exported = dscKey.Export();
        Assert.IsNotNull(exported);
        var claims = exported.Split('.')[1];
        var json = JsonSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Utility.FromBase64(claims)));
        Assert.IsNotNull(json);
        Assert.IsTrue(json.ContainsKey("key"));
        Assert.IsTrue(json.ContainsKey("pub"));
        Assert.IsTrue(json["key"].ToString()!.StartsWith("DSC."));
        Assert.IsTrue(json["pub"].ToString()!.StartsWith("DSC."));
    }

    [TestMethod]
    public void SuiteTest2() 
    {
        var stnKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, Dime.NoExpiration, null, null, "STN");
        Assert.IsNotNull(stnKey);
        Assert.AreEqual("STN", stnKey.CryptoSuiteName);
        Base58.Decode(stnKey.Secret[4..]);
        Base58.Decode(stnKey.Public[4..]);
        var exported = stnKey.Export();
        Assert.IsNotNull(exported);
        var claims = exported.Split('.')[1];
        var json = JsonSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Utility.FromBase64(claims)));
        Assert.IsNotNull(json);
        Assert.IsTrue(json.ContainsKey("key"));
        Assert.IsTrue(json.ContainsKey("pub"));
        Assert.IsTrue(json["key"].ToString()!.StartsWith("STN."));
        Assert.IsTrue(json["pub"].ToString()!.StartsWith("STN."));
    }

}