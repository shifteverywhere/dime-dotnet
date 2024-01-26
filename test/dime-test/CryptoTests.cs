//
//  CryptoTests.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;
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
        Assert.IsTrue(Dime.Crypto.HasCryptoSuite("NaCl")); // default
        Assert.IsTrue(Dime.Crypto.HasCryptoSuite("DSC"));  // legacy base64
        Assert.IsTrue(Dime.Crypto.HasCryptoSuite("STN"));  // legacy base58
        Assert.IsFalse(Dime.Crypto.HasCryptoSuite("NSA")); // non-existing
    }

    [TestMethod]
    public void AllCryptoSuitesTest1() 
    {
        var suiteNames = Dime.Crypto.AllCryptoSuites();
        Assert.IsNotNull(suiteNames);
        Assert.AreEqual(3, suiteNames.Count);
        Assert.IsTrue(suiteNames.Contains("NaCl"));
        Assert.IsTrue(suiteNames.Contains("DSC"));
        Assert.IsTrue(suiteNames.Contains("STN"));
    }

    [TestMethod]
    public void DefaultSuiteNameTest1()
    {
        Assert.IsNotNull(Dime.Crypto.DefaultSuiteName);
        Assert.AreEqual("NaCl", Dime.Crypto.DefaultSuiteName);
    }
    
    [TestMethod]
    public void DefaultSuiteNameTest2()
    {
        Dime.Crypto.DefaultSuiteName = "DSC";
        Assert.AreEqual("DSC", Dime.Crypto.DefaultSuiteName);
        Dime.Crypto.DefaultSuiteName = "NaCl";
        Assert.AreEqual("NaCl", Dime.Crypto.DefaultSuiteName);
    }
    
    [TestMethod]
    public void DefaultSuiteNameTest3()
    {
        try
        {
            Dime.Crypto.DefaultSuiteName = "NSA"; // non-existing
            Assert.IsTrue(false, "Exception not thrown.");
        }
        catch (ArgumentException) { /* All is well */ }
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
        const string name = "40950cea47a2b319";
        const string encoded = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTo1NToyNC43NzI5NDMzWiIsImtleSI6Ik5hQ2wuRXdxVWU4M1JERitkNlpGaU1ZQ2NTNHg4OFZtZTUxS3JvVTlId3U4b1l3MCIsInB1YiI6Ik5hQ2wuemxuQ1BZTTl5SFprOWpTdGhxOXZVQWtYTy9pR2dFcmhaY040bzJoWXFUYyIsInVpZCI6IjY4ZDk2NWUzLTAxNmEtNGI2Yy05NzUyLTFmYzlhNzdhNjc1MSJ9";
        var key = Item.Import<Key>(encoded);
        Assert.AreEqual(name, Dime.Crypto.GenerateKeyName(key));
    }
    
    [TestMethod]
    public void GenerateSignatureTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() { KeyCapability.Sign }, null);
        var signature = Dime.Crypto.GenerateSignature(key, key);
        Assert.IsTrue(Dime.Crypto.VerifySignature(key, signature, key));
    }

    [TestMethod]
    public void GenerateSignatureTest2()
    {
        const string encoded = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjExOjIyLjk1MzQ1NDZaIiwia2V5IjoiTmFDbC5RdS9KVmNjTk5hMlBPa0owMmoxOVNLNHlMam1mZzJyMlpDQzhrTi9LZUIxTDBYWVFDenpnRm40L1QvQjZ5d3NZVEFTNVdzQUk0b0NLdlNvZlN4Sm8rdyIsInB1YiI6Ik5hQ2wuUzlGMkVBczg0QlorUDAvd2Vzc0xHRXdFdVZyQUNPS0FpcjBxSDBzU2FQcyIsInVpZCI6ImQ0YzBmYjkwLWE1OTEtNDk2YS04OWNjLTAyNTlhYjhiMjU5NSJ9";
        var key = Item.Import<Key>(encoded);
        var signature =
            new Signature(
                Utility.FromHex("c447e712b0cfd384a2d0e80ec0006962057d76406683dd9587b0bd08b09389d24cc8ba13d0d4c3b92a315602e83c04d5a48229f2c6d428183d51193b119b9a01"),
                null);
        Assert.IsTrue(Dime.Crypto.VerifySignature(key, signature, key));
    }

    [TestMethod]
    public void GenerateSharedSecretTest1() 
    {
        var clientKey = Key.Generate(KeyCapability.Exchange);
        var serverKey = Key.Generate(KeyCapability.Exchange);
        var shared1 = clientKey.GenerateSharedSecret(serverKey.PublicCopy(), new List<KeyCapability>() {KeyCapability.Encrypt});
        var shared2 = clientKey.PublicCopy().GenerateSharedSecret(serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        Assert.IsTrue(shared1.HasCapability(KeyCapability.Encrypt));
        Assert.IsTrue(shared2.HasCapability(KeyCapability.Encrypt));
        Assert.AreEqual(shared1.Secret, shared2.Secret);
    }

    [TestMethod]
    public void GenerateSharedSecretTest2()
    {
        const string encodedClient = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTo1NToyNC43NzM2NzU3WiIsImtleSI6Ik5hQ2wueGhyVmFvVitucVhFV21uRkRTbXZTVmNDZG5LL0FQdkZzNXlKMHJsMXoxTSIsInB1YiI6Ik5hQ2wuNGh1OGxOaTlnaVhRM25ZeHQ2SWhvUndQYVlOekxKK1RHYzdjWk9VTk0wayIsInVpZCI6IjFhOTNmZDVmLWIxZjAtNDk5MC04MjJkLWExOTA1YjFiNTI0NCJ9";
        const string encodedServer = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTo1NToyNC43NzI5NDMzWiIsInB1YiI6Ik5hQ2wuemxuQ1BZTTl5SFprOWpTdGhxOXZVQWtYTy9pR2dFcmhaY040bzJoWXFUYyIsInVpZCI6IjY4ZDk2NWUzLTAxNmEtNGI2Yy05NzUyLTFmYzlhNzdhNjc1MSJ9";
        const string encodedShared = "NaCl.dMFTiVQHm1vIN+C4P5f9g7C4uIU8CAGvCvUmsXHO4IQ";
        var clientKey = Item.Import<Key>(encodedClient);
        var serverKey = Item.Import<Key>(encodedServer);
        var shared = clientKey.GenerateSharedSecret(serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        Assert.AreEqual(encodedShared, shared.Secret);
    }

    [TestMethod]
    public void GenerateSharedSecretTest3() 
    {
        const string encodedClient = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTo1NToyNC43NzM2NzU3WiIsInB1YiI6Ik5hQ2wuNGh1OGxOaTlnaVhRM25ZeHQ2SWhvUndQYVlOekxKK1RHYzdjWk9VTk0wayIsInVpZCI6IjFhOTNmZDVmLWIxZjAtNDk5MC04MjJkLWExOTA1YjFiNTI0NCJ9";
        const string encodedServer = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTo1NToyNC43NzI5NDMzWiIsImtleSI6Ik5hQ2wuRXdxVWU4M1JERitkNlpGaU1ZQ2NTNHg4OFZtZTUxS3JvVTlId3U4b1l3MCIsInB1YiI6Ik5hQ2wuemxuQ1BZTTl5SFprOWpTdGhxOXZVQWtYTy9pR2dFcmhaY040bzJoWXFUYyIsInVpZCI6IjY4ZDk2NWUzLTAxNmEtNGI2Yy05NzUyLTFmYzlhNzdhNjc1MSJ9";
        const string encodedShared = "NaCl.dMFTiVQHm1vIN+C4P5f9g7C4uIU8CAGvCvUmsXHO4IQ";
        var clientKey = Item.Import<Key>(encodedClient);
        var serverKey = Item.Import<Key>(encodedServer);
        var shared = clientKey.GenerateSharedSecret(serverKey, new List<KeyCapability>() {KeyCapability.Encrypt});
        Assert.AreEqual(encodedShared, shared.Secret);
    }

    [TestMethod]
    public void EncryptTest1() 
    {
        var key = Key.Generate(KeyCapability.Encrypt);
        var cipherText = Dime.Crypto.Encrypt(Encoding.UTF8.GetBytes(Commons.Payload), key);
        Assert.IsNotNull(cipherText);
        var plainText = Dime.Crypto.Decrypt(cipherText, key);
        Assert.IsNotNull(plainText);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(plainText));
    }

    [TestMethod]
    public void EncryptTest2() 
    {
        const string encoded = "Di:KEY.eyJjYXAiOlsiZW5jcnlwdCJdLCJpYXQiOiIyMDI0LTAxLTI2VDA4OjQ4OjA5LjM4MjU1MjNaIiwia2V5IjoiTmFDbC5xaFV5Y0RDeUF3MkJiSmxWK3lSQ1pBZXRoNWl1YVo2WU15azJrK3NOYUNFIiwidWlkIjoiNWI5YTQ1ZjgtNzQzYi00MTFmLWJhODItMzA4YTgxNjdkYmM4In0";
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
        const string cipherText = "p5UDu1/yciMaoMYE2P6yN/giWOu5zCwmvL89eBMrbgeIymscVK4pVaWdfJ3i8OZ7cMiJ+/feDfF5GG9Y539jKnwDB3Vv";
        const string encoded = "Di:KEY.eyJjYXAiOlsiZW5jcnlwdCJdLCJpYXQiOiIyMDI0LTAxLTI2VDA4OjQ4OjA5LjM4MjU1MjNaIiwia2V5IjoiTmFDbC5xaFV5Y0RDeUF3MkJiSmxWK3lSQ1pBZXRoNWl1YVo2WU15azJrK3NOYUNFIiwidWlkIjoiNWI5YTQ1ZjgtNzQzYi00MTFmLWJhODItMzA4YTgxNjdkYmM4In0";
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
        var suiteName = Dime.Crypto.DefaultSuiteName;
        var naclKey = Key.Generate(KeyCapability.Sign);
        Assert.IsNotNull(naclKey);
        Assert.AreEqual(suiteName, naclKey.CryptoSuiteName);
        Utility.FromBase64(naclKey.Secret[(suiteName.Length + 1)..]);
        Utility.FromBase64(naclKey.Public[(suiteName.Length + 1)..]);
        var exported = naclKey.Export();
        Assert.IsNotNull(exported);
        var claims = exported.Split('.')[1];
        var json = JsonSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Utility.FromBase64(claims)));
        Assert.IsNotNull(json);
        Assert.IsTrue(json.ContainsKey(Claim.Key.ToString().ToLower()));
        Assert.IsTrue(json.ContainsKey(Claim.Pub.ToString().ToLower()));
        Assert.IsTrue(json["key"].ToString()!.StartsWith($"{suiteName}."));
        Assert.IsTrue(json["pub"].ToString()!.StartsWith($"{suiteName}."));
    }

    [TestMethod]
    public void SuiteTest2()
    {
        const string suiteName = "DSC";
        var dscKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, Dime.NoExpiration, null, null, suiteName);
        Assert.IsNotNull(dscKey);
        Assert.AreEqual(suiteName, dscKey.CryptoSuiteName);
        Base58.Decode(dscKey.Secret[(suiteName.Length + 1)..]);
        Base58.Decode(dscKey.Public[(suiteName.Length + 1)..]);
        var exported = dscKey.Export();
        Assert.IsNotNull(exported);
        var claims = exported.Split('.')[1];
        var json = JsonSerializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(Utility.FromBase64(claims)));
        Assert.IsNotNull(json);
        Assert.IsTrue(json.ContainsKey(Claim.Key.ToString().ToLower()));
        Assert.IsTrue(json.ContainsKey(Claim.Pub.ToString().ToLower()));
        Assert.IsTrue(json["key"].ToString()!.StartsWith($"{suiteName}."));
        Assert.IsTrue(json["pub"].ToString()!.StartsWith($"{suiteName}."));
    }

}