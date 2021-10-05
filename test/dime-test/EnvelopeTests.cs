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
            string exported = "Di.eyJpc3MiOiJkNGVlN2YyOS02OTNiLTQyY2MtODNmMy1kZGMyNDc5ZDU0NzUiLCJpYXQiOiIyMDIxLTA5LTIyVDE4OjI3OjI4Ljc5MjAyOVoifQ:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiNjQwNDRiNzctYzQxMC00MmY2LWFhZjktZmZhZWVhMDVkZjA0Iiwic3ViIjoiZDRlZTdmMjktNjkzYi00MmNjLTgzZjMtZGRjMjQ3OWQ1NDc1IiwiaXNzIjoiOTEyZWQ5YmEtYTcxYi00MDRjLWFhYjgtOTViNzI5ZTgxZjRjIiwiaWF0IjoiMjAyMS0wOS0wNlQwODowNzoyNi42ODg3MDlaIiwiZXhwIjoiMjAyMi0wOS0wNlQwODowNzoyNi42ODg3MDlaIiwicHViIjoiMWhQS2R0Q0FxNGJ2ZllZYkVXNWJxTWpGY0tHc3c3R3Jxb252cXJrVjRZRmM2Um1vMmR0a0EiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UWXhZelEzWkdJdE1UYzJPQzAwTkdJMExUaGhPVEF0WkdSaE9XRmlaVGRpWW1Oaklpd2ljM1ZpSWpvaU9URXlaV1E1WW1FdFlUY3hZaTAwTURSakxXRmhZamd0T1RWaU56STVaVGd4WmpSaklpd2lhWE56SWpvaVlXVTJNbVJtTnpJdE16UTVNUzAwTTJFd0xXRmhPVEF0TVRrelpUUmhNVFF3TTJRNElpd2lhV0YwSWpvaU1qQXlNUzB3T1Mwd05sUXdPRG93TmpvME5TNDNOakUyTTFvaUxDSmxlSEFpT2lJeU1ESTJMVEE1TFRBMVZEQTRPakEyT2pRMUxqYzJNVFl6V2lJc0luQjFZaUk2SWpGb1VFdFpTbVI2Tm5ReE5VNTNOemt6ZDBoT1pGUnBXV2hGZFdzelZtbFVlV1ZxZEVWNlZrdHhVVEYwWjFkcllWSk1iemw0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BYW4vdWJwY1gzL2pMK3d1QmpTWi9IT2VSSDlLVFpNZ0VNTWZmVGpSZUMwRzEwRXhyaVVmazZjRUZPOUhsM0hlQ1NaQ1NuWWR5Y0ErU09qNlpRK2hud1E.Aducef6L7vnEEG4+DI9ZR5REWZ53gfgTyXuCr+UJw/Pad3Hqm45wqkk2iGL/NzBHOtJ16grwc5m0yiWZLoJAtwM:AX+QXj7bRAq+k8144VjWuiCwyBaSdwSbJQqY2WeXD4RbAwd5NOBXqOvAO0EexrSrF+rxBozdqDgsFuEX6+g2wws";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-09-22T18:27:28.792029Z").ToUniversalTime(), envelope.IssuedAt);   
            Assert.IsNull(envelope.Context);       
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
            string exported = "Di.eyJpc3MiOiJkNGVlN2YyOS02OTNiLTQyY2MtODNmMy1kZGMyNDc5ZDU0NzUiLCJpYXQiOiIyMDIxLTA5LTIyVDE4OjI0OjU3LjE5MjMxNFoifQ:KEY.eyJ1aWQiOiIyMjMxNjE5MS0yNTZkLTQ5MjYtOTQ3MS0zYTljYjAwZGJlZjYiLCJpYXQiOiIyMDIxLTA5LTA2VDA4OjA3OjI2LjY1MjM2WiIsImtleSI6IjFoRWpnenFVTTZocXBNZW1wQlFqY1pDd0h2c0s4eTU3Y1hVSEF6dmNtbjRiekxRYllXUVpMIiwicHViIjoiMWhQS2R0Q0FxNGJ2ZllZYkVXNWJxTWpGY0tHc3c3R3Jxb252cXJrVjRZRmM2Um1vMmR0a0EifQ:AYWzHueo+EgVStH3KiiC0c57oWrC+/Y+6LiQHw/UBC03G/74PK+q+vVmKTkdzfFYGTS7L260AbEJHJXjwoWZMwE";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-09-22T18:24:57.192314Z").ToUniversalTime(), envelope.IssuedAt);    
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
            string exported = "Di.eyJpc3MiOiJkNGVlN2YyOS02OTNiLTQyY2MtODNmMy1kZGMyNDc5ZDU0NzUiLCJpYXQiOiIyMDIxLTA5LTIyVDE4OjIyOjExLjU0OTI3WiIsImN0eCI6IkRpOk1FIn0:MSG.eyJ1aWQiOiIxZjEyZGUyZC04ZjEyLTQ3MzctYTgzNi1jYjY3MzdiMmI1ZGEiLCJhdWQiOiIyMjYzYTAxNy1lZTVhLTRkMmEtYTNmZS1lNjlmOTI2MmE2MDEiLCJpc3MiOiJkNGVlN2YyOS02OTNiLTQyY2MtODNmMy1kZGMyNDc5ZDU0NzUiLCJpYXQiOiIyMDIxLTA5LTIyVDE4OjIyOjExLjU1MDM5MloiLCJleHAiOiIyMDIxLTA5LTIyVDE4OjIzOjUxLjU1MDM5MloifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.AQY7ubB/05EWX4w/Ro9P6qdFr3yNxKPZludTzyBJyOFepzYVyZ8MdCGBtowHDUuj6owCb1lrZKmbtAP5n1URAQk:AR93hClhyqq96i2DBYWFhI5KQ/6gIRAz+w3O/W3VcREEaFKinrFaVUv9fGruReMcTVf51f+irmijNJzb46OYwAg";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-09-22T18:22:11.54927Z").ToUniversalTime(), envelope.IssuedAt);
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
            Key keybox = (Key)envelope2.Items.ElementAt(1);
            Assert.AreEqual(Commons.IssuerKey.UniqueId, keybox.UniqueId);
            Assert.IsNull(keybox.Secret);
        }

    }

}
