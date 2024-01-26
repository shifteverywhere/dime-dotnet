//
//  MessageTests.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class DataTests
{
    
    [TestMethod]
    public void GetHeaderTest1() 
    {
        var data = new Data(Guid.NewGuid());
        Assert.AreEqual("DAT", data.Header);
        Assert.AreEqual("DAT", Data.ItemHeader);
    }

    [TestMethod]
    public void DataTest1()
    {
        var now = DateTime.UtcNow;
        var data = new Data(Guid.NewGuid(), 10L, Commons.Context);
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Commons.Context, data.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data.GetPayload()));
        Assert.IsTrue(data.GetClaim<DateTime>(Claim.Iat) >= now && data.GetClaim<DateTime>(Claim.Iat) <= (now.AddSeconds(1)));
        Assert.IsTrue(data.GetClaim<DateTime>(Claim.Exp) > (now.AddSeconds(9)) && data.GetClaim<DateTime>(Claim.Exp) < (now.AddSeconds(11)));
        Assert.IsNull(data.GetClaim<string>(Claim.Mim));
    }

    [TestMethod]
    public void DataTest2() 
    {
        var data = new Data(Guid.NewGuid(), -1, Commons.Context);
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        Assert.AreEqual(Commons.Mimetype, data.GetClaim<string>(Claim.Mim));
        var d = data.GetClaim<DateTime>(Claim.Exp);
        Assert.AreEqual(default(DateTime), data.GetClaim<DateTime>(Claim.Exp)); 
    }

    [TestMethod]
    public void DataTest3() 
    {
        var data1 = new Data(Guid.NewGuid());
        var data2 = new Data(Guid.NewGuid());
        Assert.AreNotEqual(data1.GetClaim<Guid>(Claim.Uid), data2.GetClaim<Guid>(Claim.Uid));
    }
    
    [TestMethod]
    public void ClaimTest1() 
    {
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), data.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void ClaimTest2() 
    {
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        Assert.IsNotNull(data.GetClaim<string>(Claim.Mim));
        Assert.AreEqual(Commons.Mimetype, data.GetClaim<string>(Claim.Mim));
        data.RemoveClaim(Claim.Mim);
        Assert.AreEqual(default(string), data.GetClaim<string>(Claim.Mim));
    }

    [TestMethod]
    public void ClaimTest3() 
    {
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.PutClaim(Claim.Amb, new List<string>() { "one", "two" });
        Assert.IsNotNull(data.GetClaim<List<string>>(Claim.Amb));
        data.PutClaim(Claim.Aud, Guid.NewGuid());
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Aud));
        Assert.AreNotEqual(default, data.GetClaim<Guid>(Claim.Aud));
        data.PutClaim(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(data.GetClaim<string>(Claim.Ctx));
        data.PutClaim(Claim.Exp, DateTime.UtcNow);
        Assert.IsNotNull(data.GetClaim<DateTime>(Claim.Exp));
        Assert.AreNotEqual(default, data.GetClaim<DateTime>(Claim.Exp));
        data.PutClaim(Claim.Iat, DateTime.UtcNow);
        Assert.IsNotNull(data.GetClaim<DateTime>(Claim.Iat));
        Assert.AreNotEqual(default, data.GetClaim<DateTime>(Claim.Iat));
        data.PutClaim(Claim.Iss, Guid.NewGuid());
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Iss));
        Assert.AreNotEqual(default, data.GetClaim<Guid>(Claim.Iss));
        data.PutClaim(Claim.Isu, Commons.IssuerUrl);
        Assert.IsNotNull(data.GetClaim<string>(Claim.Isu));
        data.PutClaim(Claim.Kid, Guid.NewGuid());
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Kid));
        Assert.AreNotEqual(default, data.GetClaim<Guid>(Claim.Kid));
        data.PutClaim(Claim.Mim, Commons.Mimetype);
        Assert.IsNotNull(data.GetClaim<string>(Claim.Mim));
        data.PutClaim(Claim.Mtd, new List<string>() { "abc", "def" });
        Assert.IsNotNull(data.GetClaim<List<string>>(Claim.Mtd));
        data.PutClaim(Claim.Sub, Guid.NewGuid());
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Sub));
        Assert.AreNotEqual(default, data.GetClaim<Guid>(Claim.Sub));
        data.PutClaim(Claim.Sys, Commons.SystemName);
        Assert.IsNotNull(data.GetClaim<string>(Claim.Sys));
        data.PutClaim(Claim.Uid, Guid.NewGuid());
        Assert.IsNotNull(data.GetClaim<Guid>(Claim.Uid));
        Assert.AreNotEqual(default, data.GetClaim<Guid>(Claim.Uid));
        try { data.PutClaim(Claim.Cap, new List<KeyCapability>() { KeyCapability.Encrypt }); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { data.PutClaim(Claim.Key,Commons.IssuerKey.Secret); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { data.PutClaim(Claim.Lnk, new ItemLink(Commons.IssuerKey)); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { var pri = new Dictionary<string, object>(); pri["tag"] = Commons.Payload; data.PutClaim(Claim.Pri, pri); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { data.PutClaim(Claim.Pub, Commons.IssuerKey.Public); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest4() 
    {
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.Sign(Commons.IssuerKey);
        try { data.RemoveClaim(Claim.Iss); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
        try { data.PutClaim(Claim.Exp, DateTime.UtcNow); } catch (InvalidOperationException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest5() 
    {
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.Sign(Commons.IssuerKey);
        data.Strip();
        data.RemoveClaim(Claim.Iss);
        data.PutClaim(Claim.Iat, DateTime.UtcNow);
    }

    [TestMethod]
    public void ExportTest1() 
    {
            Commons.InitializeKeyRing();
            var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute, Commons.Context);
            data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
            var encoded = data.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith(Commons.FullHeaderFor(Data.ItemHeader)));
            Assert.AreEqual(3, encoded.Split('.').Length);
            data.Sign(Commons.IssuerKey);
            encoded = data.Export();
            Assert.AreEqual(4, encoded.Split('.').Length);
    }

    [TestMethod]
    public void ExportTest2() 
    {
            var data = new Data(Guid.NewGuid());
            data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
            var encoded1 = data.Export();
            var encoded2 = data.Export();
            Assert.IsNotNull(encoded1);
            Assert.IsNotNull(encoded2);
            Assert.AreEqual(encoded1, encoded2);
    }

    [TestMethod]
    public void ImportTest1() 
    {
        const string exported = "Di:DAT.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDI0LTAxLTI2VDE1OjI3OjUxLjg0NTEyOThaIiwiaWF0IjoiMjAyNC0wMS0yNlQxNToyNjo1MS44NDUxMjk4WiIsImlzcyI6IjMwYmIxMGRiLWNkMzUtNGYzZC1iMjZhLWI3ZGYwYzU4Mjc5YyIsIm1pbSI6InRleHQvcGxhaW4iLCJ1aWQiOiIzZTVhZWQwNy0xMDg2LTQyOTYtOWRkMy0yNmRmMWEyZDQwYTgifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        var data = Item.Import<Data>(exported);
        Assert.IsNotNull(data);
        Assert.AreEqual(Guid.Parse("3e5aed07-1086-4296-9dd3-26df1a2d40a8"), data.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), data.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.Mimetype, data.GetClaim<string>(Claim.Mim));
        Assert.AreEqual(Commons.Context, data.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data.GetPayload()));
        Assert.AreEqual(DateTime.Parse("2024-01-26T15:26:51.8451298Z").ToUniversalTime(), data.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(DateTime.Parse("2024-01-26T15:27:51.8451298Z").ToUniversalTime(), data.GetClaim<DateTime>(Claim.Exp));
    }

    [TestMethod]
    public void ImportTest2() 
    {
        Commons.InitializeKeyRing();
        var data1 = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 120, Commons.Context);
        data1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        var exported = data1.Export();
        var data2 = Item.Import<Data>(exported);
        Assert.IsNotNull(data2);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), data2.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(data1.GetClaim<DateTime>(Claim.Iat), data2.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(data1.GetClaim<DateTime>(Claim.Exp), data2.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(Commons.Mimetype, data2.GetClaim<string>(Claim.Mim));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data2.GetPayload()));
    }

    [TestMethod]
    public void ImportTest3() 
    {
        Commons.InitializeKeyRing();
        const string encoded = "Di:KEY.eyJ1aWQiOiIzZjAwY2QxMy00NDc0LTRjMDQtOWI2Yi03MzgzZDQ5MGYxN2YiLCJwdWIiOiJTMjFUWlNMMXV2RjVtVFdLaW9tUUtOaG1rY1lQdzVYWjFWQmZiU1BxbXlxRzVHYU5DVUdCN1BqMTlXU2h1SnVMa2hSRUVKNGtMVGhlaHFSa2FkSkxTVEFrTDlEdHlobUx4R2ZuIiwiaWF0IjoiMjAyMS0xMS0xOFQwODo0ODoyNS4xMzc5MThaIiwia2V5IjoiUzIxVGtnb3p4aHprNXR0RmdIaGdleTZ0MTQxOVdDTVVVTTk4WmhuaVZBamZUNGluaVVrbmZVck5xZlBxZEx1YTJTdnhGZjhTWGtIUzFQVEJDcmRrWVhONnFURW03TXdhMkxSZCJ9";
        try {
            _ = Item.Import<Data>(encoded);
            Assert.IsTrue(false, "Expected exception not thrown.");
        } catch (Exception) {
            /* All is well, carry on */
        }
    }

    [TestMethod]
    public void VerifyTest1() 
    {
        Commons.InitializeKeyRing();
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.Sign(Commons.IssuerKey);
        data.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void VerifyTest2() 
    {
            Commons.InitializeKeyRing();
            var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
            data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
            data.Sign(Commons.IssuerKey);
            Assert.IsFalse(Dime.IsIntegrityStateValid(data.Verify(Commons.AudienceKey)));
    }

    [TestMethod]
    public void ContextTest1() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var data = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub),Dime.NoExpiration, context);
        Assert.AreEqual(context, data.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest2() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try
        {
            _ = new Data(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.NoExpiration, context);
        }
        catch (ArgumentException)
        {
            // All is well  
        } 
    }
    
}