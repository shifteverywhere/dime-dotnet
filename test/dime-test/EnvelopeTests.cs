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
        public void SealTest1()
        {
            Envelope envelope = new Envelope();
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest2()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest3()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
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
            string exported = "Di.eyJpc3MiOiJlZDUzZWY1ZC0wZGM4LTRmOTYtYmY2ZS1iOTk2OTI3ODVhMTgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjUzOjE5LjUyNjE1MVoifQ:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMGJiMzFkOTctNmIxZi00NjQ4LTgwNGYtYzQ3NmQ0ZTE0N2UzIiwic3ViIjoiZWQ1M2VmNWQtMGRjOC00Zjk2LWJmNmUtYjk5NjkyNzg1YTE4IiwiaXNzIjoiNWU2OWQ5NDgtMmZlMC00Y2NmLTg2ZTUtNTFhYTNhYTY3YjZmIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzo0MDozOC44MjAwMjhaIiwiZXhwIjoiMjAyMi0wOC0xMVQwNzo0MDozOC44MjAwMjhaIiwicHViIjoiMWhQS1FBTHhuRzRGMUVKSFlBOXlQa1VaZFgzaDdyVGJtVkd4Z0xaMUpBM29aaVg4OFpBQjIiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UTmtOV1ZpTXpBdFpHSmxaUzAwWmpjNExUZzNaVEF0T0RjNVptVmhZVEl5WkRCaklpd2ljM1ZpSWpvaU5XVTJPV1E1TkRndE1tWmxNQzAwWTJObUxUZzJaVFV0TlRGaFlUTmhZVFkzWWpabUlpd2lhWE56SWpvaVl6YzNZamcxWm1ZdFpHUTNaQzAwWTJVeExUaGpZak10WTJNeVlqWm1ZbVprWW1GaElpd2lhV0YwSWpvaU1qQXlNUzB3T0MweE1WUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2laWGh3SWpvaU1qQXlOaTB3T0MweE1GUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2ljSFZpSWpvaU1XaFFTMEUyUmxSdmJ6WTRhbWhCYm5CVlFsQkZTa1IzYlhaQlVIcGxOMUYxT0UxM2FGTjJSMUJrYm5SS09YSm9VM3BVU25FaUxDSmpZWEFpT2xzaVoyVnVaWEpwWXlJc0ltbGtaVzUwYVdaNUlpd2lhWE56ZFdVaVhYMC5BWXNqbmZvVnZqaDdZSVJWTCs0MlJQTkFDQWpwZ3c5aTRMd281WmdtN3FjOEM5V2FWZFgwMnV1cXlQNm9yeEExUTdubjBsV2E5Rlc0VldPRGhWZnJVd3M.Aez/Int+YNjDvnDi7FnLCzlhOPuk4z6P3eG3rtJe8pBx8N4hvUFJZ3KdZimZxNsuMUTfyYKuZRM9V/NtyTDhBwo:AZuJ/u8peCggN98lT8Bb7mkD2qavJPiGZEJU5mw2+e6aPqo+RmcVyCFJtPKpnSqS6rmScLuzBNR1ERX73f8aOwI";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("ed53ef5d-0dc8-4f96-bf6e-b99692785a18"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-11T07:53:19.526151Z"), envelope.IssuedAt);          
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }
        
        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMGJiMzFkOTctNmIxZi00NjQ4LTgwNGYtYzQ3NmQ0ZTE0N2UzIiwic3ViIjoiZWQ1M2VmNWQtMGRjOC00Zjk2LWJmNmUtYjk5NjkyNzg1YTE4IiwiaXNzIjoiNWU2OWQ5NDgtMmZlMC00Y2NmLTg2ZTUtNTFhYTNhYTY3YjZmIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzo0MDozOC44MjAwMjhaIiwiZXhwIjoiMjAyMi0wOC0xMVQwNzo0MDozOC44MjAwMjhaIiwicHViIjoiMWhQS1FBTHhuRzRGMUVKSFlBOXlQa1VaZFgzaDdyVGJtVkd4Z0xaMUpBM29aaVg4OFpBQjIiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UTmtOV1ZpTXpBdFpHSmxaUzAwWmpjNExUZzNaVEF0T0RjNVptVmhZVEl5WkRCaklpd2ljM1ZpSWpvaU5XVTJPV1E1TkRndE1tWmxNQzAwWTJObUxUZzJaVFV0TlRGaFlUTmhZVFkzWWpabUlpd2lhWE56SWpvaVl6YzNZamcxWm1ZdFpHUTNaQzAwWTJVeExUaGpZak10WTJNeVlqWm1ZbVprWW1GaElpd2lhV0YwSWpvaU1qQXlNUzB3T0MweE1WUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2laWGh3SWpvaU1qQXlOaTB3T0MweE1GUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2ljSFZpSWpvaU1XaFFTMEUyUmxSdmJ6WTRhbWhCYm5CVlFsQkZTa1IzYlhaQlVIcGxOMUYxT0UxM2FGTjJSMUJrYm5SS09YSm9VM3BVU25FaUxDSmpZWEFpT2xzaVoyVnVaWEpwWXlJc0ltbGtaVzUwYVdaNUlpd2lhWE56ZFdVaVhYMC5BWXNqbmZvVnZqaDdZSVJWTCs0MlJQTkFDQWpwZ3c5aTRMd281WmdtN3FjOEM5V2FWZFgwMnV1cXlQNm9yeEExUTdubjBsV2E5Rlc0VldPRGhWZnJVd3M.Aez/Int+YNjDvnDi7FnLCzlhOPuk4z6P3eG3rtJe8pBx8N4hvUFJZ3KdZimZxNsuMUTfyYKuZRM9V/NtyTDhBwo";
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
            string exported = "Di.eyJpc3MiOiJlZDUzZWY1ZC0wZGM4LTRmOTYtYmY2ZS1iOTk2OTI3ODVhMTgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjUxOjE1LjgwNzE4NVoifQ:KEY.eyJ1aWQiOiIwMDRkOWUxNi01Y2E5LTQyZjAtOTM4Zi1lMGY4NWI2MDNiNDgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjQwOjM4LjczMjMwOFoiLCJrZXkiOiIxaEVqdTQ5NjExdUN3Z3ZobzZwWlFwbmZndVBDb1NxNXJnOFpwUUR3Y3ZYeFZ0dFNSaDhHYiIsInB1YiI6IjFoUEtRQUx4bkc0RjFFSkhZQTl5UGtVWmRYM2g3clRibVZHeGdMWjFKQTNvWmlYODhaQUIyIn0:AToa+3X3bjHAgI/bJlYB2Z1/td4QpeUxKP0w33tPzEDBwwebPpbGe1NBUka8L1ZIhjOLpQkDgD3N9p0s2NAElgY";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("ed53ef5d-0dc8-4f96-bf6e-b99692785a18"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-11T07:51:15.807185Z"), envelope.IssuedAt);              
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
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
            string exported = "Di.eyJpc3MiOiJlZDUzZWY1ZC0wZGM4LTRmOTYtYmY2ZS1iOTk2OTI3ODVhMTgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjUwOjA1LjU5NDA0NFoifQ:MSG.eyJ1aWQiOiI5ZmUxZWU4Zi05MzcyLTQzZjYtODI1NC1mNGI0MzMzNjI4MjMiLCJhdWQiOiJhZmU0MjMxMi1kOGMyLTRmOGUtOWU5Yy1jMDY2NTljMGNmZGYiLCJpc3MiOiJlZDUzZWY1ZC0wZGM4LTRmOTYtYmY2ZS1iOTk2OTI3ODVhMTgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjUwOjA1LjU5ODIwOFoiLCJleHAiOiIyMDIxLTA4LTExVDA3OjUxOjQ1LjU5ODIwOFoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.Ae1b2zzyfUdWEem1dUXp/ugcoVvnSNGHK/V2YPRPbuqsbJQ3z1HDVpqK9nCfDTqjdCzrTEje9YuEBsRYYAJ0dwY:AfmonwMEr+KkFjwrz8pa54Io+m6W+JVVPfnGiWVPXc5mB4fyAEjkDKCSZZxG5GnIrz2Qvi6xirTp/V6bg+DGVQ4";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("ed53ef5d-0dc8-4f96-bf6e-b99692785a18"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-11T07:50:05.594044Z"), envelope.IssuedAt);              
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
            Key keybox = (Key)envelope2.Items.ElementAt(1);
            Assert.AreEqual(Commons.IssuerKey.UniqueId, keybox.UniqueId);
            Assert.IsNull(keybox.Secret);
        }

    }

}
