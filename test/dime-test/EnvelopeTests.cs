//
//  EnvelopeTests.cs
//  DiME - Digital Identity Message Envelope
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
            Envelope dime = new Envelope();
            try {
                dime.Seal(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest2()
        {
            Envelope dime = new Envelope(Commons.SenderIdentity.SubjectId);
            try {
                dime.Seal(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest3()
        {
            Envelope dime = new Envelope(Commons.SenderIdentity.SubjectId);
            dime.AddItem(Commons.SenderKeybox);
            dime.Seal(Commons.SenderKeybox);
        }

        [TestMethod]
        public void IIRExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            Envelope dime = new Envelope();
            dime.AddItem(iir);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IIRImportTest1()
        {
            string exported = "DiME:aWly.eyJpc3MiOm51bGwsInVpZCI6IjRiNTQwZDA2LWY0MjAtNGJkMi1iMjcxLTEzNzkyYjAwOTEwZCIsImlhdCI6MTYyNjIwNzUwMiwicHViIjoiQ1lIdDdjdTNYcUVna2h5dkxhYVpoZktGUlNHYmRVZXVIRTl2c0tKUjhVU3FHTG1ORks3eXpOIiwiY2FwIjpbImdlbmVyaWMiXX0.JZHrlQ3jQNJzoPzMLAhYPlKu0LWQXNwK7ATYhmyZDMuQxIQs0w5tC59NAMgUWatb7J/cLtGAp9VPQq1rJM0LDw";
            Envelope dime = Envelope.Import(exported);
            Assert.IsTrue(dime.IsAnonymous);
            Assert.IsNull(dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(IdentityIssuingRequest), dime.Items.ElementAt(0).GetType());
        }

        [TestMethod]
        public void IdentityExportTest1()
        {
            Envelope dime = new Envelope(Commons.SenderIdentity.SubjectId);
            dime.AddItem(Commons.SenderIdentity);
            dime.Seal(Commons.SenderKeybox);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void IdentityExportTest2()
        {
            Envelope dime = new Envelope();
            dime.AddItem(Commons.SenderIdentity);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IdentityImportTest1()
        {
            string exported = "DiME.eyJpc3MiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpYXQiOjE2MjYyMTQxMjZ9:aWQ.eyJ1aWQiOiI0ZGU3MDNlYS0zZjM2LTQzMTctYTVhYi05OWRkZTVlMTllYTgiLCJzdWIiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpc3MiOiIwMzdkOTEzNS1mNmVhLTQ1ZTEtOWFhNi1hNmQ0NzE3NmUwMGQiLCJpYXQiOjE2MjYyMTM4NDUsImV4cCI6MTY1Nzc0OTg0NSwicHViIjoiQ1lIdDd0U1RxNTlGeXB0SlVOS01UOG5QdGVyeFp0bjgzZ3JSU3JkZ3I2TnNUazdxaDNBR1BjIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKbU5ERTFaR00wTUMxak1UYzJMVFJqWTJZdE9EaGhOeTFoTW1NeE5USTJOemhsTkRBaUxDSnpkV0lpT2lJd016ZGtPVEV6TlMxbU5tVmhMVFExWlRFdE9XRmhOaTFoTm1RME56RTNObVV3TUdRaUxDSnBjM01pT2lJM05USTVabUkwWlMxalpqTTRMVFJoTnpBdFlqY3dNUzAwT1dVNVltTTVaVGc1TWpFaUxDSnBZWFFpT2pFMk1qWXlNVE0zTnpRc0ltVjRjQ0k2TVRjNE16ZzVNemMzTkN3aWNIVmlJam9pUTFsSWREY3pOazVvZFVSV2VYZEtZemRXVG5KNVRrSk9iak5ZZG01V09UWnpWRXBuYUhGR1ZsaGtZa3RZYVZGcWJYbHdWMWg0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BY1N2T3hXTHVvekp4c1FqRzFEQzNTSzhGNnFnR2VOQWVwa1lDRnlUaitxQWZ5RzFiaVFJSit4RkVEUEl3cnlndHZOVDFXRnduUVlPQ3dkMEdjdElpUXc.AZrIMEZAvKFz6u699TfpQwpnJnyI594i9MmTPHH9YV6A0W2wFO/fwff9yoIO9t7eSycnTVe2AaVpo7jCG2XtMgE:AZojjnpa0Cv3x9gzBHLQQmZxEMfec9pmhMt2oIQuPfvHWwWfxrOl+jxC+39rGHI2AtazhXNWuVPH2tUQdFgNoQ8";
            Envelope dime = Envelope.Import(exported);
            Assert.IsFalse(dime.IsAnonymous);
            Assert.AreEqual(new Guid("0021e220-da4a-4023-af1d-6efb05fcfeef"), dime.IssuerId);  
            Assert.AreEqual(1626214126, dime.IssuedAt);          
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Identity), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "DiME:aWQ.eyJ1aWQiOiI0ZGU3MDNlYS0zZjM2LTQzMTctYTVhYi05OWRkZTVlMTllYTgiLCJzdWIiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpc3MiOiIwMzdkOTEzNS1mNmVhLTQ1ZTEtOWFhNi1hNmQ0NzE3NmUwMGQiLCJpYXQiOjE2MjYyMTM4NDUsImV4cCI6MTY1Nzc0OTg0NSwicHViIjoiQ1lIdDd0U1RxNTlGeXB0SlVOS01UOG5QdGVyeFp0bjgzZ3JSU3JkZ3I2TnNUazdxaDNBR1BjIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKbU5ERTFaR00wTUMxak1UYzJMVFJqWTJZdE9EaGhOeTFoTW1NeE5USTJOemhsTkRBaUxDSnpkV0lpT2lJd016ZGtPVEV6TlMxbU5tVmhMVFExWlRFdE9XRmhOaTFoTm1RME56RTNObVV3TUdRaUxDSnBjM01pT2lJM05USTVabUkwWlMxalpqTTRMVFJoTnpBdFlqY3dNUzAwT1dVNVltTTVaVGc1TWpFaUxDSnBZWFFpT2pFMk1qWXlNVE0zTnpRc0ltVjRjQ0k2TVRjNE16ZzVNemMzTkN3aWNIVmlJam9pUTFsSWREY3pOazVvZFVSV2VYZEtZemRXVG5KNVRrSk9iak5ZZG01V09UWnpWRXBuYUhGR1ZsaGtZa3RZYVZGcWJYbHdWMWg0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BY1N2T3hXTHVvekp4c1FqRzFEQzNTSzhGNnFnR2VOQWVwa1lDRnlUaitxQWZ5RzFiaVFJSit4RkVEUEl3cnlndHZOVDFXRnduUVlPQ3dkMEdjdElpUXc.AZrIMEZAvKFz6u699TfpQwpnJnyI594i9MmTPHH9YV6A0W2wFO/fwff9yoIO9t7eSycnTVe2AaVpo7jCG2XtMgE";
            Envelope dime = Envelope.Import(exported);
            Assert.IsTrue(dime.IsAnonymous);
            Assert.IsNull(dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Identity), dime.Items.ElementAt(0).GetType());
            try {
                dime.Verify(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void KeyBoxExportTest1()
        {
            Envelope dime = new Envelope(Commons.SenderIdentity.SubjectId);
            dime.AddItem(Commons.SenderKeybox);
            dime.Seal(Commons.SenderKeybox);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void KeyBoxImportTest1()
        {
            string exported = "DiME.eyJpc3MiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpYXQiOjE2MjYyMTQwMzl9:a2V5.eyJraWQiOiIyZDQ2YzYzMC1mNTQ4LTRmNzUtODYwZC01ZTE3NzNkODU0OWQiLCJpYXQiOjE2MjYyMTM4NDUsImtleSI6IkNZSGpYazU1aUNWek00MWdDUjlOcmhLcXhkalNQcDJHMUUxU0xjOGNBbk5EY0I0UnZQWDlzWCIsInB1YiI6IkNZSHQ3dFNUcTU5RnlwdEpVTktNVDhuUHRlcnhadG44M2dyUlNyZGdyNk5zVGs3cWgzQUdQYyJ9:AXEDtpVRWAfg+te2EfI3RxGOq1xIwl5o1nmz7ICkKmbq+CYuxf90h9NzB511qtiSlV+ve8bve+RNMB1z5X6ezwE";
            Envelope dime = Envelope.Import(exported);
            Assert.IsFalse(dime.IsAnonymous);
            Assert.AreEqual(new Guid("0021e220-da4a-4023-af1d-6efb05fcfeef"), dime.IssuerId);  
            Assert.AreEqual(1626214039, dime.IssuedAt);              
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(KeyBox), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            Envelope dime = new Envelope(Commons.SenderIdentity.SubjectId);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            dime.AddItem(message);
            dime.Seal(Commons.SenderKeybox);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void MessageImportTest1()
        {
            string exported = "DiME.eyJpc3MiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpYXQiOjE2MjYyMTM5NjV9:bXNn.eyJ1aWQiOiJmODI4ZTA1Ni0yNTc1LTRkZDktOGMzZC04YWMxMjFkOTM2YTAiLCJhdWQiOiJmMTRmNzNhZi02N2Y1LTRiYjgtODMxMi1lNDg4OGU4ZjllYzciLCJpc3MiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpYXQiOjE2MjYyMTM5NjUsImV4cCI6MTYyNjIxNDA2NX0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.Abx4KooAQ7WUK0xLWYouofsldmLKAuBc9ACQxO4IZmZkgH06QlfTDv6wTx5Wlow+0UApilj4+ZJYnJT+B+s+6Ak:ARJC4fif3Yvz58KrmxXrZ50RaNUQKnvzTSmLV2RSxByoFoZjujFKRS1gCgoejoSV253BtictghCZzBVQqQtlfgo";
            Envelope dime = Envelope.Import(exported);
            Assert.IsFalse(dime.IsAnonymous);
            Assert.AreEqual(new Guid("0021e220-da4a-4023-af1d-6efb05fcfeef"), dime.IssuerId);  
            Assert.AreEqual(1626213965, dime.IssuedAt);              
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Message), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void ExportTest1()
        {
            Envelope dime1 = new Envelope(Commons.SenderIdentity.SubjectId);
            dime1.AddItem(Commons.SenderIdentity);
            dime1.AddItem(Commons.SenderKeybox.PublicOnly());
            dime1.Seal(Commons.SenderKeybox);
            string exported = dime1.Export();

            Envelope dime2 = Envelope.Import(exported);
            dime2.Verify(Commons.SenderKeybox);
            Assert.AreEqual(2, dime2.Items.Count);

            Identity identity = (Identity)dime2.Items.ElementAt(0);
            Assert.AreEqual(Commons.SenderIdentity.SubjectId, identity.SubjectId);
            KeyBox keybox = (KeyBox)dime2.Items.ElementAt(1);
            Assert.AreEqual(Commons.SenderKeybox.UID, keybox.UID);
            Assert.IsNull(keybox.Key);
        }

    }

}
