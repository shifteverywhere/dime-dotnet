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
using System.Text;
using DiME;

namespace DiME_test;

[TestClass]
public class DataTests
{
    [TestMethod]
    public void GetItemIdentifierTest1() 
    {
        var data = new Data(Guid.NewGuid());
        Assert.AreEqual("DAT", data.Identifier);
        Assert.AreEqual("DAT", Data.ItemIdentifier);
    }

    [TestMethod]
    public void DataTest1()
    {
        var now = DateTime.UtcNow;
        var data = new Data(Guid.NewGuid(), 10L, Commons.Context);
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.IsNotNull(data.UniqueId);
        Assert.AreEqual(Commons.Context, data.Context);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data.GetPayload()));
        Assert.IsTrue(data.IssuedAt >= now && data.IssuedAt <= (now.AddSeconds(1)));
        Assert.IsTrue(data.ExpiresAt > (now.AddSeconds(9)) && data.ExpiresAt < (now.AddSeconds(11)));
        Assert.IsNull(data.MimeType);
    }

    [TestMethod]
    public void DataTest2() 
    {
        var data = new Data(Guid.NewGuid(), -1, Commons.Context);
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        Assert.AreEqual(Commons.Mimetype, data.MimeType);
        Assert.IsNull(data.ExpiresAt);
    }

    [TestMethod]
    public void DataTest3() 
    {
        var data1 = new Data(Guid.NewGuid());
        var data2 = new Data(Guid.NewGuid());
        Assert.AreNotEqual(data1.UniqueId, data2.UniqueId);
    }

    [TestMethod]
    public void ExportTest1() 
    {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var data = new Data(Commons.IssuerIdentity.SubjectId, 120L, Commons.Context);
            data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
            var encoded = data.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith(Commons.FullHeaderFor(Data.ItemIdentifier)));
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

    /*
     TODO: re-enable and update once Commons is re-generated.
    [TestMethod]
    public void ImportTest1() 
    {
        const string exported = "Di:DAT.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDIyLTA4LTE4VDIwOjIwOjEwLjQ0ODM0M1oiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjE4OjEwLjQ0ODM0M1oiLCJpc3MiOiJiYjdhNzQ1OC0zZjVjLTQ4ZmItYWJmOC0zN2Y3Mzc4ZmEyMTkiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiNTZmOTJjOTAtNTg2OC00YzkyLTkxYzktNWY4N2FiNDhjNjQyIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YThlNGMxZWJlYWIyMDliZi42YjRjYzUxMzExNjk2OTRiMDBmMjllNDNiNmU5N2RkZjY4MDRkYjlkMGMwZGJlZjA5MWQwOTg1ZjViNGVjOThkZTkzNTk5YzQ1NmEzNzAwMDM3MzRkM2NmYzI1NmI2NjhmMTE4ZTVlYjBjNjdiNGNhYThiYjdmNTU4NTFjYTAwMA";
        var data = Item.Import<Data>(exported);
        Assert.IsNotNull(data);
        Assert.AreEqual(Guid.Parse("56f92c90-5868-4c92-91c9-5f87ab48c642"), data.UniqueId);
        Assert.AreEqual(Commons.IssuerIdentity.SubjectId, data.IssuerId);
        Assert.AreEqual(Commons.Mimetype, data.MimeType);
        Assert.AreEqual(Commons.Context, data.Context);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data.GetPayload()));
        Assert.AreEqual(DateTime.Parse("2022-08-18T20:18:10.448343Z").ToUniversalTime(), data.IssuedAt);
        Assert.AreEqual(DateTime.Parse("2022-08-18T20:20:10.448343Z").ToUniversalTime(), data.ExpiresAt);
    }
    */

    [TestMethod]
    public void ImportTest2() 
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var data1 = new Data(Commons.IssuerIdentity.SubjectId, 120, Commons.Context);
        data1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        var exported = data1.Export();
        var data2 = Item.Import<Data>(exported);
        Assert.IsNotNull(data2);
        Assert.AreEqual(Commons.IssuerIdentity.SubjectId, data2.IssuerId);
        Assert.AreEqual(data1.IssuedAt, data2.IssuedAt);
        Assert.AreEqual(data1.ExpiresAt, data2.ExpiresAt);
        Assert.AreEqual(Commons.Mimetype, data2.MimeType);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(data2.GetPayload()));
    }

    [TestMethod]
    public void ImportTest3() 
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
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
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var data = new Data(Commons.IssuerIdentity.SubjectId);
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.Sign(Commons.IssuerKey);
        data.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void VerifyTest2() 
    {
        try {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var data = new Data(Commons.IssuerIdentity.SubjectId);
            data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
            data.Sign(Commons.IssuerKey);
            data.Verify(Commons.AudienceKey);
        } catch (IntegrityException) {
            // All is well
        }
    }

    [TestMethod]
    public void ContextTest1() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var data = new Data(Commons.IssuerIdentity.SubjectId,Dime.NoExpiration, context);
        Assert.AreEqual(context, data.Context);
    }

    [TestMethod]
    public void ContextTest2() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try
        {
            _ = new Data(Commons.IssuerIdentity.SubjectId, Dime.NoExpiration, context);
        }
        catch (ArgumentException)
        {
            // All is well  
        } 
    }
    
}