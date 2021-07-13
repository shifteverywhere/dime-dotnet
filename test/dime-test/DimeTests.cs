//
//  DimeTest.cs
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
    public class DimeTests
    {

        [TestMethod]
        public void SealTest1()
        {
            Dime dime = new Dime();
            try {
                dime.Seal(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest2()
        {
            Dime dime = new Dime(Commons.SenderIdentity.SubjectId);
            try {
                dime.Seal(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest3()
        {
            Dime dime = new Dime(Commons.SenderIdentity.SubjectId);
            dime.AddItem(Commons.SenderKeybox);
            dime.Seal(Commons.SenderKeybox);
        }

        [TestMethod]
        public void IIRExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            Dime dime = new Dime();
            dime.AddItem(iir);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IIRImportTest1()
        {
            string exported = "DiME:aWly.eyJpc3MiOm51bGwsInVpZCI6IjRiNTQwZDA2LWY0MjAtNGJkMi1iMjcxLTEzNzkyYjAwOTEwZCIsImlhdCI6MTYyNjIwNzUwMiwicHViIjoiQ1lIdDdjdTNYcUVna2h5dkxhYVpoZktGUlNHYmRVZXVIRTl2c0tKUjhVU3FHTG1ORks3eXpOIiwiY2FwIjpbImdlbmVyaWMiXX0.JZHrlQ3jQNJzoPzMLAhYPlKu0LWQXNwK7ATYhmyZDMuQxIQs0w5tC59NAMgUWatb7J/cLtGAp9VPQq1rJM0LDw";
            Dime dime = Dime.Import(exported);
            Assert.IsNull(dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(IdentityIssuingRequest), dime.Items.ElementAt(0).GetType());
        }

        [TestMethod]
        public void IdentityExportTest1()
        {
            Dime dime = new Dime(Commons.SenderIdentity.SubjectId);
            dime.AddItem(Commons.SenderIdentity);
            dime.Seal(Commons.SenderKeybox);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void IdentityExportTest2()
        {
            Dime dime = new Dime();
            dime.AddItem(Commons.SenderIdentity);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IdentityImportTest1()
        {
            string exported = "DiME.NzA1MDI4MzMtNTIxNS00YmUzLWI3NWUtM2UzZjA3ZDI1NjI0:aWQ.eyJ1aWQiOiJkYjkxZWU5OS1hMDVlLTRlODgtODI0NC1jZjVhNTU5NDYyOWYiLCJzdWIiOiI3MDUwMjgzMy01MjE1LTRiZTMtYjc1ZS0zZTNmMDdkMjU2MjQiLCJpc3MiOiI3NTkwNTQ1MC1iZmE1LTQwMmMtYWZiZS0xZGY2YjBiY2YzNTMiLCJpYXQiOjE2MjYyMDczODksImV4cCI6MTY1Nzc0MzM4OSwiaWt5IjoiQ1lIdDZRRkw0eEpockw5MnZuOU51SHJYZGhOZTdMNm5tYnNWQW9FbnRQZVpmeWlweVk3Z1RtIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKaFl6UmtOemxsWWkwNU5ESmtMVFEzWkdZdFltTXlNaTFtWlRNMk1tUmpNR0ZqWkRNaUxDSnpkV0lpT2lJM05Ua3dOVFExTUMxaVptRTFMVFF3TW1NdFlXWmlaUzB4WkdZMllqQmlZMll6TlRNaUxDSnBjM01pT2lKak56aGpNRGcyWkMxaE0yUmtMVFE0WlRRdE9HWXhPQzFoTlRFek5qazBOMlk1TWpBaUxDSnBZWFFpT2pFMk1qWXlNRGN6TURZc0ltVjRjQ0k2TVRjNE16ZzROek13Tml3aWFXdDVJam9pUTFsSWREYzFSMUZxWlZkVFl6WkxhbWcwVEdNeFVVWjJkelZVZFZOV1YxSmlTblpvVUZoSFp6aFVRbmt5Y1RsaE5YTjVOVWR6SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5zUUxWSEJNcmtkTFpFWEpKQS8zaHd2aXV1a3hkT3FHcDZtRHpDemhCYnRQaGtYWkxVNTdvSHFDQ2NvVmloNy80VGw2d0dLODZjNVphb3ZRQkc1WHZBZw.fWZ+pdwoYpbmvzytYwi+iwM+CYSmyfX6VX44ocGsUKZ3JKMFDNnRdHJivt0Bwv1GFBnRRCfq9+GJvPYYbGPqCA:IZGiVtsMGK8ySFoK9I01AZDRWN9X81tt5GO9sDgOlmZ9niKlmqhB6Jn7+qqaM4bLvEZdzY9bH4Q56MsFe2r1AA";
            Dime dime = Dime.Import(exported);
            Assert.AreEqual(new Guid("70502833-5215-4be3-b75e-3e3f07d25624"), dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Identity), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "DiME:aWQ.eyJ1aWQiOiJkYjkxZWU5OS1hMDVlLTRlODgtODI0NC1jZjVhNTU5NDYyOWYiLCJzdWIiOiI3MDUwMjgzMy01MjE1LTRiZTMtYjc1ZS0zZTNmMDdkMjU2MjQiLCJpc3MiOiI3NTkwNTQ1MC1iZmE1LTQwMmMtYWZiZS0xZGY2YjBiY2YzNTMiLCJpYXQiOjE2MjYyMDczODksImV4cCI6MTY1Nzc0MzM4OSwiaWt5IjoiQ1lIdDZRRkw0eEpockw5MnZuOU51SHJYZGhOZTdMNm5tYnNWQW9FbnRQZVpmeWlweVk3Z1RtIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKaFl6UmtOemxsWWkwNU5ESmtMVFEzWkdZdFltTXlNaTFtWlRNMk1tUmpNR0ZqWkRNaUxDSnpkV0lpT2lJM05Ua3dOVFExTUMxaVptRTFMVFF3TW1NdFlXWmlaUzB4WkdZMllqQmlZMll6TlRNaUxDSnBjM01pT2lKak56aGpNRGcyWkMxaE0yUmtMVFE0WlRRdE9HWXhPQzFoTlRFek5qazBOMlk1TWpBaUxDSnBZWFFpT2pFMk1qWXlNRGN6TURZc0ltVjRjQ0k2TVRjNE16ZzROek13Tml3aWFXdDVJam9pUTFsSWREYzFSMUZxWlZkVFl6WkxhbWcwVEdNeFVVWjJkelZVZFZOV1YxSmlTblpvVUZoSFp6aFVRbmt5Y1RsaE5YTjVOVWR6SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5zUUxWSEJNcmtkTFpFWEpKQS8zaHd2aXV1a3hkT3FHcDZtRHpDemhCYnRQaGtYWkxVNTdvSHFDQ2NvVmloNy80VGw2d0dLODZjNVphb3ZRQkc1WHZBZw.fWZ+pdwoYpbmvzytYwi+iwM+CYSmyfX6VX44ocGsUKZ3JKMFDNnRdHJivt0Bwv1GFBnRRCfq9+GJvPYYbGPqCA";
            Dime dime = Dime.Import(exported);
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
            Dime dime = new Dime(Commons.SenderIdentity.SubjectId);
            dime.AddItem(Commons.SenderKeybox);
            dime.Seal(Commons.SenderKeybox);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void KeyBoxImportTest1()
        {
            string exported = "DiME.NzA1MDI4MzMtNTIxNS00YmUzLWI3NWUtM2UzZjA3ZDI1NjI0:a2V5.eyJraWQiOiI5ODVkN2QyNS1jZTc4LTRmMzMtYWVhZi0yMDlkYTgwNzAzNzgiLCJpYXQiOjE2MjYyMDczODksImtleSI6IkNZSGpYS2lqcXpYVnV0U3drcVY0RkhIaUY2WjN2TVhzRVVQaTROZDVHdjVMUDdSd2JYcGlrNyIsInB1YiI6IkNZSHQ2UUZMNHhKaHJMOTJ2bjlOdUhyWGRoTmU3TDZubWJzVkFvRW50UGVaZnlpcHlZN2dUbSJ9:/4vsvXoSw/RzBdm89bUNdfaDew4h9FQ/itiMqg/vJ4sfbBEYgtLvFBLkLRqD61SAJfe+o4Qb2Y/HnAa7dXUlCA";
            Dime dime = Dime.Import(exported);
            Assert.AreEqual(new Guid("70502833-5215-4be3-b75e-3e3f07d25624"), dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(KeyBox), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            Dime dime = new Dime(Commons.SenderIdentity.SubjectId);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            dime.AddItem(message);
            dime.Seal(Commons.SenderKeybox);
            string exported = dime.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void MessageImportTest1()
        {
            string exported = "DiME.NzA1MDI4MzMtNTIxNS00YmUzLWI3NWUtM2UzZjA3ZDI1NjI0:bXNn.eyJ1aWQiOiI2MGRkZjNlOS1hMzUzLTRiNmQtOWEwZi05MWRjZDVkNTE3MDciLCJhdWQiOiJhZjM4NGQwMC05YmM1LTQwMTctODc3YS01Mzc5ZjY1M2U1ZTUiLCJpc3MiOiI3MDUwMjgzMy01MjE1LTRiZTMtYjc1ZS0zZTNmMDdkMjU2MjQiLCJpYXQiOjE2MjYyMDc3NzQsImV4cCI6MTYyNjIwNzg3NH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.PRJOERIaqWY1YU8fHSTZkwFDHRVIUiFK2RH7GIYqDlb2MbkAK4qCrC5xS5cVsobOblsHD4O3jDclRlNGWUgIBA:wqaMXXU0jPERfiZgl31skwAzdwE/mofeYlGt+duD7PS553yy/gxNFF1bAeKBv0CVqsmacV6QTJnIov4yIxPzBA";
            Dime dime = Dime.Import(exported);
            Assert.AreEqual(new Guid("70502833-5215-4be3-b75e-3e3f07d25624"), dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Message), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

    }

}
