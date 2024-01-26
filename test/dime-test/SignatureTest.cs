//
//  SignatureTest.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//

using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using DiME;
using DiME.Capability;
using DiME.KeyRing;

namespace DiME_test;

[TestClass]
public class SignatureTest
{
    
    [TestMethod]
    public void SignaturesTest1()
    {
        var key1 = Key.Generate(KeyCapability.Sign);
        var key2 = Key.Generate(KeyCapability.Sign);
        var key3 = Key.Generate(KeyCapability.Sign);
        var data = new Data();
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        Assert.IsNull(data.Signatures);
        data.Sign(key1);
        data.Sign(key2);
        Assert.IsNotNull(data.Signatures);
        Assert.AreEqual(2, data.Signatures.Count);
        Assert.IsNotNull(Signature.Find(key1.Name, data.Signatures.ToList()));
        Assert.AreEqual(IntegrityState.Complete, data.Verify(key1));
        Assert.IsNotNull(Signature.Find(key2.Name, data.Signatures.ToList()));
        Assert.AreEqual(IntegrityState.Complete, data.Verify(key2));
        Assert.IsNull(Signature.Find(key3.Name, data.Signatures.ToList()));
        Assert.AreEqual(IntegrityState.FailedKeyMismatch, data.Verify(key3));
    }
    
}