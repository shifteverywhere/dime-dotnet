//
//  EnvelopeTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class EnvelopeTests
    {

        [TestMethod]
        public void SignTest1()
        {
            var envelope = new Envelope();
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SignTest2()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SignTest3()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
        }

        [TestMethod]
        public void ContextTest1()
        {
            const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId, context);
            Assert.AreEqual(context, envelope.Context);
        }

        [TestMethod]
        public void ContextTest2()
        {
            const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            var envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId, context);
            var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            envelope1.AddItem(message);
            envelope1.Sign(Commons.IssuerKey);
            var exported = envelope1.Export();
            var envelope2 = Envelope.Import(exported);
            Assert.AreEqual(context, envelope2.Context);
        }

        [TestMethod]
        public void ContextTest3()
        {
            const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
            try
            {
                _ = new Envelope(Commons.IssuerIdentity.SubjectId, context);
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            var envelope = new Envelope();
            envelope.AddItem(Commons.IssuerKey);
            Assert.IsNotNull(envelope.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            Assert.IsNotNull(envelope.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest3()
        {
            var envelope1 = new Envelope();
            envelope1.AddItem(Commons.IssuerKey);
            var exported = envelope1.Export();
            var envelope2 = Envelope.Import(exported);
            Assert.AreEqual(envelope1.Thumbprint(), envelope2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest4()
        {
            var envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope1.AddItem(Commons.IssuerKey);
            envelope1.Sign(Commons.IssuerKey);
            var exported = envelope1.Export();
            var envelope2 = Envelope.Import(exported);
            Assert.AreEqual(envelope1.Thumbprint(), envelope2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest5()
        {
            var envelope = new Envelope();
            envelope.AddItem(Commons.IssuerKey);
            var exported = envelope.Export();
            Assert.AreEqual(envelope.Thumbprint(), Item.Thumbprint(exported));
        }

        [TestMethod]
        public void ThumbprintTest6()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            var exported = envelope.Export();
            Assert.AreEqual(envelope.Thumbprint(), Item.Thumbprint(exported));
        }

        [TestMethod]
        public void IirExportTest1()
        {
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyUse>() {KeyUse.Sign}, null));
            var envelope = new Envelope();
            envelope.AddItem(iir);
            var exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.Header));
            Assert.IsTrue(exported.Split(new[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IirImportTest1()
        {
            const string exported = "Di:IIR.eyJ1aWQiOiI0ZmIxMzgyNC1lZTUyLTQ1ZjYtYmNiZC1kNTk3MDY1NjUwMzgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjU0OjIwLjc4Mzk3OVoiLCJwdWIiOiIxaFBLUUdwYldFVzFYR0RQbjRKRlJlYkF3QVlYSEs4N1lzOFhTckg3TFY5ZkdaZkZTaVprUSIsImNhcCI6WyJnZW5lcmljIl19.AR7L9NL4v2b9Kaomy//9hgMebtukkCn/M48KdBnMQ6v0lBgKfytiMRBzJJoxIQWtTy77gAcyM0ixfXrV79Y1iAA";
            var envelope = Envelope.Import(exported);
            Assert.IsTrue(envelope.IsAnonymous);
            Assert.IsNull(envelope.IssuerId);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(IdentityIssuingRequest), envelope.Items.ElementAt(0).GetType());
        }

        [TestMethod]
        public void IdentityExportTest1()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerIdentity);
            envelope.Sign(Commons.IssuerKey);
            var exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.Header));
            Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void IdentityExportTest2()
        {
            var envelope = new Envelope();
            envelope.AddItem(Commons.IssuerIdentity);
            var exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.Header));
            Assert.IsTrue(exported.Split(new[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IdentityImportTest1()
        {
            const string exported = "Di.eyJpc3MiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjMwOjA2LjY2NjY4M1oifQ:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiIyYzZmYTYwMS1mOWIyLTQxNGQtOThhNy00YWY5MDVkY2U1NzIiLCJzdWIiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJwdWIiOiIyVERYZG9OdU1GaThqd0MzRE43WDJacW1aa0ZmNWE3cWV0elhUV0Fmbmt5aDZncnFZUHE5NE5lbm4iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.pdZhvANop6iCyBvAmWqUFnviqTZRlw/mF4fjLj4MdbVRdsJDF8eOUYQJk+HoqAXE4i9NV18uAioVkKR1LM1WDw:UwtJ8JvNVDnWTkMXEinQ34rl/QmA0nmbUSoSJpDpPLZeihv/UWCoOU5KK1bo7idmx86TPj55FayBOB1Qi8VuAA";
            var envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(DateTime.Parse("2021-12-02T22:30:06.666683Z").ToUniversalTime(), envelope.IssuedAt);
            Assert.IsNull(envelope.Context);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            const string exported = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiIyYzZmYTYwMS1mOWIyLTQxNGQtOThhNy00YWY5MDVkY2U1NzIiLCJzdWIiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJwdWIiOiIyVERYZG9OdU1GaThqd0MzRE43WDJacW1aa0ZmNWE3cWV0elhUV0Fmbmt5aDZncnFZUHE5NE5lbm4iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.pdZhvANop6iCyBvAmWqUFnviqTZRlw/mF4fjLj4MdbVRdsJDF8eOUYQJk+HoqAXE4i9NV18uAioVkKR1LM1WDw";
            var envelope = Envelope.Import(exported);
            Assert.IsTrue(envelope.IsAnonymous);
            Assert.IsNull(envelope.IssuerId);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            try {
                envelope.Verify(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void KeyExportTest1()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            var exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.Header));
            Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void KeyImportTest1()
        {
            const string exported = "Di.eyJpc3MiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI4OjQzLjA1NzE1NVoifQ:KEY.eyJ1aWQiOiI5ZDA3MDliMS1kOWZmLTQzNGUtYjQwMC01MzMyMDMwMjE0YzUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzU4MloiLCJrZXkiOiJTMjFUWlNMRWRNWTJwVjlzaXBjZTgxN0NvaHBiaFZqVnYxUWRweGI4MkZQWmEzSkxmN05SanFvU0tnb3NZekdMdzlVOEc3NDdtVmZnOHp3SHVBbUZMOUQ2U0ZyMlJtN25EaEMyIiwicHViIjoiMlREWGRvTnVNRmk4andDM0RON1gyWnFtWmtGZjVhN3FldHpYVFdBZm5reWg2Z3JxWVBxOTROZW5uIn0:x5cjGoZKzY9SDzKC33q2965i6Fksq+AwX8zMG2n6eMtYUB3Jo9OKRHwn64OkFFZ6UseK9K9h/9LIWYlqHFgTBA";
            var envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(DateTime.Parse("2021-12-02T22:28:43.057155Z").ToUniversalTime(), envelope.IssuedAt);
            Assert.IsNull(envelope.Context);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            var envelope = new Envelope(Commons.IssuerIdentity.SubjectId, "Di:ME");
            var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            envelope.AddItem(message);
            envelope.Sign(Commons.IssuerKey);
            var exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.Header));
            Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void MessageImportTest1()
        {
            const string exported = "Di.eyJpc3MiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI3OjM0Ljc2OTEyNFoiLCJjdHgiOiJEaTpNRSJ9:MSG.eyJ1aWQiOiI4Y2JiNTM0Yi1kNzYzLTQ4ZjktYmVlMS1kZmEzNzU4OGQ5MmIiLCJhdWQiOiIxODUwNjYyYi05NjQxLTQyNjYtYTI5OC0zN2FiZWRlZmI1NjciLCJpc3MiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI3OjM0Ljc3MDEyNVoiLCJleHAiOiIyMDIxLTEyLTAyVDIyOjI5OjE0Ljc3MDEyNVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.SZKVht64RjHwg5NmfuvDdny8iXa4qer54Tv9ymZnlnAxzc1YJNrM/uIuqJtmrQAqttZZpXx/w2rovRFOKW0aCw:Up57uww0beEJJHl4hTRJ4YuIZODA0lOsPnOlhQeJ5VgpnB2MbSUoGmnqeTL6GbH4ALi0IyD3pgUWPniEO0BpDw";
            var envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(DateTime.Parse("2021-12-02T22:27:34.769124Z").ToUniversalTime(), envelope.IssuedAt);
            Assert.AreEqual("Di:ME", envelope.Context);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Message), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void ExportTest1()
        {
            var envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope1.AddItem(Commons.IssuerIdentity);
            envelope1.AddItem(Commons.IssuerKey.PublicCopy());
            envelope1.Sign(Commons.IssuerKey);
            var exported = envelope1.Export();

            var envelope2 = Envelope.Import(exported);
            envelope2.Verify(Commons.IssuerKey);
            Assert.AreEqual(2, envelope2.Items.Count);

            var identity = (Identity)envelope2.Items.ElementAt(0);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, identity.SubjectId);
            var key = (Key)envelope2.Items.ElementAt(1);
            Assert.AreEqual(Commons.IssuerKey.UniqueId, key.UniqueId);
            Assert.IsNull(key.Secret);
        }

    }

}
