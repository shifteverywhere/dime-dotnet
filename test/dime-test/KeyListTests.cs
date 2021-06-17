//
//  KeyListTests.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class KeyListTests
    {
        [TestMethod]
        public void KeyListTest1()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            KeyList keylist = new KeyList(Commons.SenderIdentity, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            Assert.IsNotNull(keylist.Id);
            Assert.AreEqual(Commons.SenderIdentity.SubjectId, keylist.Issuer.SubjectId);
            Assert.AreEqual(Commons.ReceiverIdentity.SubjectId, keylist.AudienceId);
            Assert.IsTrue(keylist.IssuedAt >= now);
            Assert.IsNotNull(keylist.ExpiresAt);
            Assert.IsTrue(keylist.ExpiresAt >= now + 120);
            Assert.IsNotNull(keylist.Keys);
            Assert.AreEqual(1, keylist.Keys.Count);
        }

        [TestMethod]
        public void ExportTest1()
        {
            KeyList keylist = new KeyList(Commons.SenderIdentity, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            try {
                string encoded = keylist.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ExportTest2()
        {
            KeyList keylist = new KeyList(Commons.SenderIdentity, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            keylist.Seal(Commons.SenderKeypair.Key, false);
            string encoded = keylist.Export();
            Assert.IsTrue(encoded.StartsWith(Dime.HEADER));
            Assert.AreEqual(3, encoded.Split(':').Length);
        }

        [TestMethod]
        public void ExportTest3()
        {
            KeyList keylist1 = new KeyList(Commons.SenderIdentity, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            keylist1.Seal(Commons.SenderKeypair.Key, true);
            string encoded = keylist1.Export();
            KeyList keylist2 = Dime.Import<KeyList>(encoded);
            Assert.IsNotNull(keylist2.Keys[0].Key);
        }

        [TestMethod]
        public void ExportTest4()
        {
            KeyList keylist1 = new KeyList(Commons.SenderIdentity, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            keylist1.Seal(Commons.SenderKeypair.Key, false);
            string encoded = keylist1.Export();
            KeyList keylist2 = Dime.Import<KeyList>(encoded);
            Assert.IsNull(keylist2.Keys[0].Key);
        }

        [TestMethod]
        public void ImportTest2()
        {
            string encoded = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6Ijg0NjE0YjU0LWE2NGUtNGU2Zi04ODhmLTUwMzliOWZhNjRmYyIsInN1YiI6ImFkZDIwZmY0LTMyMmItNGQ1NC1iYzc0LWJjYjVjN2VhMDhkNiIsImlzcyI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlhdCI6MTYyMzI3NjI4OSwiZXhwIjoxNjU0ODEyMjg5LCJpa3kiOiJNQ293QlFZREsyVndBeUVBcDgyMFx1MDAyQnhlUWhZZFFlM3pMSjRObFNNR3hKOFhLOS9OOHVaZDJnOHZBSlZnIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoyWlhJaU9qRXNJblZwWkNJNklqQTVNelExTVdSaUxUSTJaakl0TkRCak5TMDRabVE1TFRZM00yVTFaalV3WVRZNU5DSXNJbk4xWWlJNkltTm1PV1JsTWpNeExUZGtZbVF0TkRBME9TMDRNREZoTFRCaVpEVXpNakUwWlRNek5TSXNJbWx6Y3lJNklqRTNaVFppTnpnM0xXUTJaV1l0TkRFMU9DMWhZak01TFRoaU5XWmpNamczTlRjelpTSXNJbWxoZENJNk1UWXlNekkzTkRRNE55d2laWGh3SWpveE56Z3dPVFUwTkRnM0xDSnBhM2tpT2lKTlEyOTNRbEZaUkVzeVZuZEJlVVZCUlZsd2JXbGxiRTUzYmtSNlpHTkphbWxMYlVaUFZURjFabWRuVEhGWk9XZFZORk4zYUU1NWN6TXhTU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAuc0pJZXZZYjcybWppRTdXOHZPS3Ywbmk5MGUzSVhhd1lsOGZuWVhsMzRJbzRlUU1tZ05DYkdUN1N2MXFIclBhcjIxZ1FkZGVVQUdZaFVzM1hwbFIyQWc.revzfv1JwJG3/m/IKY3bVm5VFxMB/epmfe/0gqxhXD0rbUdvj+j22QLhuyhKqRe1XScOypk+TiwZ2RW0BKEUAA:aW8uZGltZWZvcm1hdC5reWw.eyJ1aWQiOiI0N2NjZWRiNi05NDliLTQ5MmMtYTMyNC1iMDc1MzYwZjI0MDkiLCJhdWQiOiIyZjRjYmY2Ni05ZWRiLTRkZTEtYjdhOC0yNDRmNmUwYzdmMmYiLCJpc3MiOiJhZGQyMGZmNC0zMjJiLTRkNTQtYmM3NC1iY2I1YzdlYTA4ZDYiLCJpYXQiOjE2MjM5NTUzMjUsImV4cCI6MTYyMzk1NTQ0NX0.YVc4dVpHbHRaV1p2Y20xaGRDNXJlV0kuZXlKMlpYSWlPakVzSW10cFpDSTZJalpqTTJGbFpqTmpMV1ptWVRJdE5EUmtNQzFpTnpreUxXTTRZakV3WWpRME1qWTFNU0lzSW10MGVTSTZNaXdpY0hWaUlqb2lUVU52ZDBKUldVUkxNbFoxUVhsRlFUVmlabEk1TkVKSWRISkdORXBsUTFaVU9UaHdSa3B3WWtGV05qUndVMWR6TDJ0RFRFaFJURFp3YlZraWZR.mx06PyfJdxjV4qepHIfIt+9cMBYRlbnqkEnpCFDDFJVtETDl7jcn3LaUlsb/wjYFdEQ3ttnWy3RC9KHk2GktBw";
            KeyList keylist = Dime.Import<KeyList>(encoded);
            Assert.AreEqual(new Guid("47ccedb6-949b-492c-a324-b075360f2409"), keylist.Id);
            Assert.AreEqual(new Guid("2f4cbf66-9edb-4de1-b7a8-244f6e0c7f2f"), keylist.AudienceId);
            Assert.AreEqual(new Guid("add20ff4-322b-4d54-bc74-bcb5c7ea08d6"), keylist.Issuer.SubjectId);
            Assert.AreEqual(1623955325, keylist.IssuedAt);
            Assert.AreEqual(1623955445, keylist.ExpiresAt);
            Assert.AreEqual(1, keylist.Keys.Count);
            Assert.AreEqual(ProfileVersion.One, keylist.Keys[0].Profile);
            Assert.AreEqual(new Guid("6c3aef3c-ffa2-44d0-b792-c8b10b442651"), keylist.Keys[0].Id);
            Assert.AreEqual(KeyType.Exchange, keylist.Keys[0].Type);
            Assert.AreEqual("MCowBQYDK2VuAyEA5bfR94BHtrF4JeCVT98pFJpbAV64pSWs/kCLHQL6pmY", keylist.Keys[0].PublicKey);
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            KeyList keylist1 = new KeyList(Commons.SenderIdentity, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            keylist1.Seal(Commons.SenderKeypair.Key, false);
            string encoded = keylist1.Export();
            KeyList keylist2 = Dime.Import<KeyList>(encoded);
            keylist2.Verify();
        }

        [TestMethod]
        public void VerifyTest2()
        {
            List<Capability> caps = new List<Capability> { Capability.Identify };
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            Identity untrustedSender = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 120, caps,  keypair,  null);
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            KeyList keylist = new KeyList(untrustedSender, new List<KeyBox>() { KeyBox.Generate(KeyType.Exchange) }, Commons.ReceiverIdentity.SubjectId, 120);
            keylist.Seal(keypair.Key, false);
            try {
                keylist.Verify();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void VerifyTest3()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6Ijg0NjE0YjU0LWE2NGUtNGU2Zi04ODhmLTUwMzliOWZhNjRmYyIsInN1YiI6ImFkZDIwZmY0LTMyMmItNGQ1NC1iYzc0LWJjYjVjN2VhMDhkNiIsImlzcyI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlhdCI6MTYyMzI3NjI4OSwiZXhwIjoxNjU0ODEyMjg5LCJpa3kiOiJNQ293QlFZREsyVndBeUVBcDgyMFx1MDAyQnhlUWhZZFFlM3pMSjRObFNNR3hKOFhLOS9OOHVaZDJnOHZBSlZnIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoyWlhJaU9qRXNJblZwWkNJNklqQTVNelExTVdSaUxUSTJaakl0TkRCak5TMDRabVE1TFRZM00yVTFaalV3WVRZNU5DSXNJbk4xWWlJNkltTm1PV1JsTWpNeExUZGtZbVF0TkRBME9TMDRNREZoTFRCaVpEVXpNakUwWlRNek5TSXNJbWx6Y3lJNklqRTNaVFppTnpnM0xXUTJaV1l0TkRFMU9DMWhZak01TFRoaU5XWmpNamczTlRjelpTSXNJbWxoZENJNk1UWXlNekkzTkRRNE55d2laWGh3SWpveE56Z3dPVFUwTkRnM0xDSnBhM2tpT2lKTlEyOTNRbEZaUkVzeVZuZEJlVVZCUlZsd2JXbGxiRTUzYmtSNlpHTkphbWxMYlVaUFZURjFabWRuVEhGWk9XZFZORk4zYUU1NWN6TXhTU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAuc0pJZXZZYjcybWppRTdXOHZPS3Ywbmk5MGUzSVhhd1lsOGZuWVhsMzRJbzRlUU1tZ05DYkdUN1N2MXFIclBhcjIxZ1FkZGVVQUdZaFVzM1hwbFIyQWc.revzfv1JwJG3/m/IKY3bVm5VFxMB/epmfe/0gqxhXD0rbUdvj+j22QLhuyhKqRe1XScOypk+TiwZ2RW0BKEUAA:aW8uZGltZWZvcm1hdC5reWw.eyJ1aWQiOiI0N2NjZWRiNi05NDliLTQ5MmMtYTMyNC1iMDc1MzYwZjI0MDkiLCJhdWQiOiIyZjRjYmY2Ni05ZWRiLTRkZTEtYjdhOC0yNDRmNmUwYzdmMmYiLCJpc3MiOiJhZGQyMGZmNC0zMjJiLTRkNTQtYmM3NC1iY2I1YzdlYTA4ZDYiLCJpYXQiOjE2MjM5NTUzMjUsImV4cCI6MTYyMzk1NTQ0NX0.YVc4dVpHbHRaV1p2Y20xaGRDNXJlV0kuZXlKMlpYSWlPakVzSW10cFpDSTZJalpqTTJGbFpqTmpMV1ptWVRJdE5EUmtNQzFpTnpreUxXTTRZakV3WWpRME1qWTFNU0lzSW10MGVTSTZNaXdpY0hWaUlqb2lUVU52ZDBKUldVUkxNbFoxUVhsRlFUVmlabEk1TkVKSWRISkdORXBsUTFaVU9UaHdSa3B3WWtGV05qUndVMWR6TDJ0RFRFaFJURFp3YlZraWZR.mx06PyfJdxjV4qepHIfIt+9cMBYRlbnqkEnpCFDDFJVtETDl7jcn3LaUlsb/wjYFdEQ3ttnWy3RC9KHk2GktBw";
            KeyList keylist = Dime.Import<KeyList>(encoded);
            try {
                keylist.Verify();
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

    }

}