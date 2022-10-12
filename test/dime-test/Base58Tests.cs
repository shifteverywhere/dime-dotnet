//
//  Base58Tests.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using DiME;

namespace DiME_test;

[TestClass]
public class Base58Tests
{

    [TestMethod]
    public void EncodeTest1() 
    {
        const string reference = "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x";
        var bytes = new byte[] { 0x00, 0x21, 0x1b, 0x74, 0xca, 0x46, 0x86, 0xf8, 0x1e, 0xfd, 0xa5, 0x64, 0x17, 0x67, 0xfc, 0x84, 0xef, 0x16, 0xda, 0xfe, 0x0b };
        var base58 = Base58.Encode(bytes);
        Assert.AreEqual(reference, base58);
    }

    [TestMethod]
    public void EncodeTest2() 
    {
        const string str = Commons.Payload;
        var base58 = Base58.Encode(Encoding.UTF8.GetBytes(str));
        Assert.AreEqual("RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDACaR79", base58);
    }

    [TestMethod]
    public void DecodeTest1() 
    {                   
        const string base58 = "RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDACaR79";
        var bytes = Base58.Decode(base58);
        var decoded = Encoding.UTF8.GetString(bytes);
        Assert.AreEqual(Commons.Payload, decoded);
    }
    
    [TestMethod]
    public void DecodeTest2() 
    {
        var base64 = Utility.ToBase64(Encoding.UTF8.GetBytes(Commons.Payload));
        var bytes = Base58.Decode(base64);
        var decoded = Encoding.UTF8.GetString(bytes);
        Assert.IsTrue(string.IsNullOrEmpty(decoded));
    }

    [TestMethod]
    public void DecodeTest3() 
    {
        var base64 = Utility.ToHex(Utility.RandomBytes(256));
        var bytes = Base58.Decode(base64);
        var decoded = Encoding.UTF8.GetString(bytes);
        Assert.IsTrue(string.IsNullOrEmpty(decoded));
    }

}