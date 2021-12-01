//
//  EnvelopeTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Linq;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class EnvelopeTests
    {

        [TestMethod]
        public void SignTest1()
        {
            Envelope envelope = new Envelope();
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SignTest2()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SignTest3()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
        }

        [TestMethod]
        public void ContextTest1()
        {
            string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId, context);
            Assert.AreEqual(context, envelope.Context);
        }

        [TestMethod]
        public void ContextTest2()
        {
            string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Envelope envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId, context);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            envelope1.AddItem(message);
            envelope1.Sign(Commons.IssuerKey);
            string exported = envelope1.Export();
            Envelope envelope2 = Envelope.Import(exported);
            Assert.AreEqual(context, envelope2.Context);
        }

        [TestMethod]
        public void ContextTest3()
        {
            string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
            try {
                Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId, context);
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            Envelope envelope = new Envelope();
            envelope.AddItem(Commons.IssuerKey);
            Assert.IsNotNull(envelope.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            Assert.IsNotNull(envelope.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest3()
        {
            Envelope envelope1 = new Envelope();
            envelope1.AddItem(Commons.IssuerKey);
            string exported = envelope1.Export();
            Envelope envelope2 = Envelope.Import(exported);
            Assert.AreEqual(envelope1.Thumbprint(), envelope2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest4()
        {
            Envelope envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope1.AddItem(Commons.IssuerKey);
            envelope1.Sign(Commons.IssuerKey);
            string exported = envelope1.Export();
            Envelope envelope2 = Envelope.Import(exported);
            Assert.AreEqual(envelope1.Thumbprint(), envelope2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest5()
        {
            Envelope envelope = new Envelope();
            envelope.AddItem(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.AreEqual(envelope.Thumbprint(), Envelope.Thumbprint(exported));
        }

        [TestMethod]
        public void ThumbprintTest6()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.AreEqual(envelope.Thumbprint(), Envelope.Thumbprint(exported));
        }

        [TestMethod]
        public void IIRExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            Envelope envelope = new Envelope();
            envelope.AddItem(iir);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IIRImportTest1()
        {
            string exported = "Di:IIR.eyJ1aWQiOiI0ZmIxMzgyNC1lZTUyLTQ1ZjYtYmNiZC1kNTk3MDY1NjUwMzgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjU0OjIwLjc4Mzk3OVoiLCJwdWIiOiIxaFBLUUdwYldFVzFYR0RQbjRKRlJlYkF3QVlYSEs4N1lzOFhTckg3TFY5ZkdaZkZTaVprUSIsImNhcCI6WyJnZW5lcmljIl19.AR7L9NL4v2b9Kaomy//9hgMebtukkCn/M48KdBnMQ6v0lBgKfytiMRBzJJoxIQWtTy77gAcyM0ixfXrV79Y1iAA";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsTrue(envelope.IsAnonymous);
            Assert.IsNull(envelope.IssuerId);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(IdentityIssuingRequest), envelope.Items.ElementAt(0).GetType());
        }

        [TestMethod]
        public void IdentityExportTest1()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerIdentity);
            envelope.Sign(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void IdentityExportTest2()
        {
            Envelope envelope = new Envelope();
            envelope.AddItem(Commons.IssuerIdentity);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IdentityImportTest1()
        {
            string exported = "Di.eyJpc3MiOiIzZjgxMzg2My1lYzJjLTQ5YTctOTMyMC00MzkzZDkxMTYzNTciLCJpYXQiOiIyMDIxLTEyLTAxVDIxOjA3OjEyLjUxOTE5MVoifQ:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiOTIwMjI0NjQtYmFkYi00ZDJiLTk0YjUtZDE2NmM5NWNmYjhlIiwic3ViIjoiM2Y4MTM4NjMtZWMyYy00OWE3LTkzMjAtNDM5M2Q5MTE2MzU3IiwiaXNzIjoiNTk4NjZjYWQtMTU1MS00NGM5LWJiNjMtMDAyNmU3ODJjMGZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMDo1ODozOC4xMjAwNloiLCJleHAiOiIyMDIyLTEyLTAxVDIwOjU4OjM4LjEyMDA2WiIsInB1YiI6IjJURFhkb052VlJ0R1ByUzloOHJhVE5NUVFTOHNNcmY1aWtQZEZNbjl4WTZwVXFRa2lnZTl3a2hKZiIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1qWTVZVFF6TURJdE1tWm1aaTAwTjJKbExXSTFabVl0TkRGa01XSTFNbU0wTlRneUlpd2ljM1ZpSWpvaU5UazROalpqWVdRdE1UVTFNUzAwTkdNNUxXSmlOak10TURBeU5tVTNPREpqTUdabUlpd2lhWE56SWpvaVlUTmtZV1poWXpZdFlqRXdPUzAwT1dReUxXRmhaR0V0Tkdaa01ERTBZalZsTlRabUlpd2lhV0YwSWpvaU1qQXlNUzB4TWkwd01WUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2laWGh3SWpvaU1qQXlOaTB4TVMwek1GUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2ljSFZpSWpvaU1sUkVXR1J2VG5aS1MxWTJTRGw1WlVjell6STNhMDQ1UVV4UWRIQTVOblZMYWxGRVNsSm5WRUp2V21kMlVWTlpZVVJ2YTFOdk5IQlhJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5Lkp1N3hwTHg1R1dlN3dIb3doK0phOWl3bDNsb0Vob1JUR0RNTUJINFNjMUhYQWp1N1FvUXk5THlSOEIxV3lSOTBFczVmajhKa2E2T0UvSzRzN25Fb0NB.hRqgv30qdDRlmT2+F+RXP4Rno7lA8s2gnoSqWVNuPwErMCFvWQHDQkHqKUZ+8DuRgUHrxutJlYuslWUhqeIdCA:BTFSHlb9C36/TYxRzTBDpOX+nL1ulEg9ToAw4BqXKMcknF+dGDnntkkeFTZ+k4t424ZmoVWVFhHteQknCH6qCw";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T21:07:12.519191Z").ToUniversalTime(), envelope.IssuedAt);
            Assert.IsNull(envelope.Context);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiOTIwMjI0NjQtYmFkYi00ZDJiLTk0YjUtZDE2NmM5NWNmYjhlIiwic3ViIjoiM2Y4MTM4NjMtZWMyYy00OWE3LTkzMjAtNDM5M2Q5MTE2MzU3IiwiaXNzIjoiNTk4NjZjYWQtMTU1MS00NGM5LWJiNjMtMDAyNmU3ODJjMGZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMDo1ODozOC4xMjAwNloiLCJleHAiOiIyMDIyLTEyLTAxVDIwOjU4OjM4LjEyMDA2WiIsInB1YiI6IjJURFhkb052VlJ0R1ByUzloOHJhVE5NUVFTOHNNcmY1aWtQZEZNbjl4WTZwVXFRa2lnZTl3a2hKZiIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1qWTVZVFF6TURJdE1tWm1aaTAwTjJKbExXSTFabVl0TkRGa01XSTFNbU0wTlRneUlpd2ljM1ZpSWpvaU5UazROalpqWVdRdE1UVTFNUzAwTkdNNUxXSmlOak10TURBeU5tVTNPREpqTUdabUlpd2lhWE56SWpvaVlUTmtZV1poWXpZdFlqRXdPUzAwT1dReUxXRmhaR0V0Tkdaa01ERTBZalZsTlRabUlpd2lhV0YwSWpvaU1qQXlNUzB4TWkwd01WUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2laWGh3SWpvaU1qQXlOaTB4TVMwek1GUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2ljSFZpSWpvaU1sUkVXR1J2VG5aS1MxWTJTRGw1WlVjell6STNhMDQ1UVV4UWRIQTVOblZMYWxGRVNsSm5WRUp2V21kMlVWTlpZVVJ2YTFOdk5IQlhJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5Lkp1N3hwTHg1R1dlN3dIb3doK0phOWl3bDNsb0Vob1JUR0RNTUJINFNjMUhYQWp1N1FvUXk5THlSOEIxV3lSOTBFczVmajhKa2E2T0UvSzRzN25Fb0NB.hRqgv30qdDRlmT2+F+RXP4Rno7lA8s2gnoSqWVNuPwErMCFvWQHDQkHqKUZ+8DuRgUHrxutJlYuslWUhqeIdCA";
            Envelope envelope = Envelope.Import(exported);
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
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void KeyImportTest1()
        {
            string exported = "Di.eyJpc3MiOiIzZjgxMzg2My1lYzJjLTQ5YTctOTMyMC00MzkzZDkxMTYzNTciLCJpYXQiOiIyMDIxLTEyLTAxVDIxOjA2OjE1LjI4MzE4WiJ9:KEY.eyJ1aWQiOiJiODhmNDQyMy0yNDdjLTQxNzItYTg0OS1jMWUxODkzN2U0ZDMiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjU4OjM4LjA4MTc1M1oiLCJrZXkiOiIyVERYZDlXVjhyTEN4b29GQVM5NFJMazNwSkw3dWlYOHdFVndkOEtIc3l5ZXZjYVE3cTVLS2l2bUoiLCJwdWIiOiIyVERYZG9OdlZSdEdQclM5aDhyYVROTVFRUzhzTXJmNWlrUGRGTW45eFk2cFVxUWtpZ2U5d2toSmYifQ:ZOuSIktzKIHSEOgcn3+WwsebOUWCM9HqbeSWi2ZnT9PtCWBS6Ye7f6dxMVoWsd5KapEm93x3jCzWSRII1hllCA";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T21:06:15.28318Z").ToUniversalTime(), envelope.IssuedAt);
            Assert.IsNull(envelope.Context);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId, "Di:ME");
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            envelope.AddItem(message);
            envelope.Sign(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void MessageImportTest1()
        {
            string exported = "Di.eyJpc3MiOiIzZjgxMzg2My1lYzJjLTQ5YTctOTMyMC00MzkzZDkxMTYzNTciLCJpYXQiOiIyMDIxLTEyLTAxVDIxOjA1OjA2LjQyMDMyNloiLCJjdHgiOiJEaTpNRSJ9:MSG.eyJ1aWQiOiI0YmNkMTJlNC01MDM5LTQ5MWYtYmM2NC00ZjY5YWJhMGVkY2IiLCJhdWQiOiIxNjBjNDVkNy01NDA1LTRkMmQtODJjOS0yMjc3MDI2ZTVmMjMiLCJpc3MiOiIzZjgxMzg2My1lYzJjLTQ5YTctOTMyMC00MzkzZDkxMTYzNTciLCJpYXQiOiIyMDIxLTEyLTAxVDIxOjA1OjA2LjQyMTMyNFoiLCJleHAiOiIyMDIxLTEyLTAxVDIxOjA2OjQ2LjQyMTMyNFoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.FlAxkSyuAMRU2+AGF7TpBt+wRvPzt04DkGJlEBqjHIrpT7muymam2tdArl524u8BRzvQvJDN3l6gfus4DTfWBw:63QuGEYPI002NtBlm57n4X9jdMefCUaHragqlXE0rQAAaUSZUAjITS2jJOKlCyy2mtRyYw4AsOMbPj5CdPVzDQ";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T21:05:06.420326Z").ToUniversalTime(), envelope.IssuedAt);
            Assert.AreEqual("Di:ME", envelope.Context);
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Message), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void ExportTest1()
        {
            Envelope envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope1.AddItem(Commons.IssuerIdentity);
            envelope1.AddItem(Commons.IssuerKey.PublicCopy());
            envelope1.Sign(Commons.IssuerKey);
            string exported = envelope1.Export();

            Envelope envelope2 = Envelope.Import(exported);
            envelope2.Verify(Commons.IssuerKey);
            Assert.AreEqual(2, envelope2.Items.Count);

            Identity identity = (Identity)envelope2.Items.ElementAt(0);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, identity.SubjectId);
            Key key = (Key)envelope2.Items.ElementAt(1);
            Assert.AreEqual(Commons.IssuerKey.UniqueId, key.UniqueId);
            Assert.IsNull(key.Secret);
        }

    }

}
