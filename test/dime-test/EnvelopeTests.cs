//
//  EnvelopeTests.cs
//  Dime - Data Integrity Message Envelope
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
using System.Linq;
using DiME;

namespace DiME_test;

[TestClass]
public class EnvelopeTests
{
    
    [TestMethod]
    public void GetHeaderTest1() 
    {
        var envelope = new Envelope();
        Assert.AreEqual("Di", envelope.Header);
        Assert.AreEqual("Di", Envelope.ItemHeader);
    }

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
        var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
        var envelope = new Envelope();
        envelope.AddItem(iir);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
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
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
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
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 2);
    }

    [TestMethod]
    public void IdentityImportTest1()
    {
        const string exported = "Di.eyJpYXQiOiIyMDIyLTEwLTE3VDE4OjU1OjQyLjIxMTY4MloiLCJpc3MiOiIzYjAxZDcyMi1lNjZiLTQ2ODMtYTViNi05M2RjNmU2MGUwMTcifQ:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMTdUMTg6NTM6MzUuMzk3NThaIiwiaWF0IjoiMjAyMi0xMC0xN1QxODo1MzozNS4zOTc1OFoiLCJpc3MiOiJjZWRmMmI2YS0yOWUyLTQ0ZTUtOTYxYS1jNDczZTRiNTYzNzgiLCJwdWIiOiJTVE4uQVBHV0VIU0ZlcXgzd29RVHg3M0xQQmlFN3VzNDlkcjhUamtHSnBzcnhqZ1NyaGFEMiIsInN1YiI6IjNiMDFkNzIyLWU2NmItNDY4My1hNWI2LTkzZGM2ZTYwZTAxNyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiZjhkN2RlODUtNzFiNS00ZDM4LWIwZWYtODBlYTZiOTllMGQ2In0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB4TmxReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB4TjFReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFYTnpJam9pWkRSaU5qQTRORFl0TURJNE5TMDBOak5qTFdJME5qVXRPV0kzTlRnM016TmhOREZtSWl3aWNIVmlJam9pVTFST0xtaGxabGhNYTFWVFJuWkJlVkpYZEVWQldHaDJibGxIUzJWaGRGTTRXRlZxZG1Gdk9XTmpkbEpDVWtWaWJ6SnpSa2dpTENKemRXSWlPaUpqWldSbU1tSTJZUzB5T1dVeUxUUTBaVFV0T1RZeFlTMWpORGN6WlRSaU5UWXpOemdpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJbVE0TVRNNE4yTXpMV0V6TWprdE5ETmpNQzA1TURVNUxXSmhNMkZsWmpWbE9XVmtaU0o5Lk5qRXdZbUUyTkdRME16RmlaR0kyWVM0ek5XSXlOamcwTnpKbE5XSmxNV013WTJRek1EUXdNamRoTnpOa016Z3pNbVF5TnpSaU1XWTFaR1JpWm1JMFpHTmhPR1JoTXpreU1qY3hPREJsTVRWbE9XWTRZV1V4WTJJMFpqbGxaVEpsTVdaaFlqZ3laRFE0WldFd1l6Z3dNMlkwTVRJelpUZ3lNbUkwTXpsbU56QTRZamN3TnpZeFlUTXhZMlEzTlRnd01B.NDFjNjlmZDZkYzk5NjkyOC5mZGIxMWFjMDgxNGY5YzIxMzYxY2VhZGY4YmViN2M2Mjc0ZTU3MmYyNjI4NWUwNjY3NTdlYjAwYTcxNTQ3ZmM1ODhhZWQ0ODg4MjE1YWJlMGY4Nzk2NTczMDRmZDZhZGZiZGExMDExMjlmNzFjYzlmOGFhZWYzYzgxNGNiNGEwNQ:MzFhMDYyN2JlZjk1NjNiZC4yNTBmMzA5YjBmZThiMzYzNzRlYTljMWNjZmFhNWMxNmVkNzY1NmQ4OWYzY2RlODQ1MTQxNTk2M2Q0ZjdjMWFjNDc3Y2NjOTMwODcwYTUxOTcwODU2NTA3YTEzYzU1NTljNTdlMDhjNDEwZTg2MDMyZDEzZDFhYmMwM2I3NmQwMA";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
        Assert.AreEqual(DateTime.Parse("2022-10-17T18:55:42.211682Z").ToUniversalTime(), envelope.IssuedAt);
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
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
    }

    [TestMethod]
    public void KeyImportTest1()
    {
        const string exported = "Di.eyJpYXQiOiIyMDIyLTEwLTE3VDE4OjU3OjE5Ljc2NDYwN1oiLCJpc3MiOiIzYjAxZDcyMi1lNjZiLTQ2ODMtYTViNi05M2RjNmU2MGUwMTcifQ:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjUzOjM1LjM5NzM1NVoiLCJrZXkiOiJTVE4uNm1GdmtCNUFlckc0RUZMR29hcFYxYXVZQXJuSGsxRlhpd1RkeHRVTnZIdmNxYWQ5MUVwMWE4QXpBNXRkcmdMSlVCNURucVFQdUtDMzFzdmVSWWdWYTU3dmczZ3B0IiwicHViIjoiU1ROLkFQR1dFSFNGZXF4M3dvUVR4NzNMUEJpRTd1czQ5ZHI4VGprR0pwc3J4amdTcmhhRDIiLCJ1aWQiOiJkZmU0NTllOS02MzgwLTQ4NjEtOTVhOC1hYWUyMWNiMTg1OWEifQ:MzFhMDYyN2JlZjk1NjNiZC5mZjM5ZDEyODM2MTAzMWQxMTEyODA0NDAyOGQ1YTc4OWQyZDIxOTIyMGNhNmRjNDMzMTg4Yzg5NzM4MjkxZDA2NTNjMTQxNTYxOGIzMzRlOTZmMWViY2MwOTY2Y2NlZjYxYjQ3YTY5NDZhZmNiOTQ0MzllNDgxNzk5MjAwMDMwMQ";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
        Assert.AreEqual(DateTime.Parse("2022-10-17T18:57:19.764607Z").ToUniversalTime(), envelope.IssuedAt);
        Assert.IsNull(envelope.Context);
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
        envelope.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void MessageExportTest1()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.SubjectId, Commons.Context);
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, Dime.ValidFor1Minute);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        envelope.AddItem(message);
        envelope.Sign(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
    }

    [TestMethod]
    public void MessageImportTest1()
    {
        const string exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjU4OjU5LjAzOTgyNloiLCJpc3MiOiIzYjAxZDcyMi1lNjZiLTQ2ODMtYTViNi05M2RjNmU2MGUwMTcifQ:MSG.eyJhdWQiOiI4ZmRkYzI0Mi02NzBlLTRjNzMtODRiZS04Mjc2MWEzOTI3ZWYiLCJleHAiOiIyMDIyLTEwLTE3VDE5OjAwOjM5LjA0MDQzMloiLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjU4OjU5LjA0MDQzMloiLCJpc3MiOiIzYjAxZDcyMi1lNjZiLTQ2ODMtYTViNi05M2RjNmU2MGUwMTciLCJ1aWQiOiJhMDcxNjhiMi0wNGQxLTRkZGYtOTFhNi1mNmI5ZDFjOWZiMzIifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MzFhMDYyN2JlZjk1NjNiZC5hNjllYTJjNTk2Y2RhZGUwMTFiNDk1MzZhYzg2ZjQ2NzdjMjVjMzUzNzgwMjRjOGFiOWM3Mjc3NGI1Y2NmMzkyOTYxNmNkZDFiY2Q5NmNjY2IyMzZkODdhNzllZmQ2MTUwNjI3MjA0YTJiNjlkNTA0YzAyMjE4ODJlYzAwNWQwNw:MzFhMDYyN2JlZjk1NjNiZC42NjJjNjRjZDBjMTMyMzdjNjlmNjNkOTg4ZjJlYWI3MGY0MGQ0MDA2ZGQ3ODYxMDg1ZDkzMDYzMTI0YjYxYjMyZDRhZjMzMWRiYjdhZjUyYjk4MzFkMTk1MzllNjhmYWZmYmUwMWQ3Y2ZlM2YwMjY3MGE5ZmFkNDA4OWUwMjkwNA";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
        Assert.AreEqual(DateTime.Parse("2022-10-17T18:58:59.039826Z").ToUniversalTime(), envelope.IssuedAt);
        Assert.AreEqual(Commons.Context, envelope.Context);
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