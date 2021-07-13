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
            string exported = "Di:aW8uZGltZWZvcm1hdC5paXI.eyJpc3MiOm51bGwsInVpZCI6IjNmNTA2ODM5LTAzYjctNDM0OS1hODJiLWJhYzBiY2EzYzlhMiIsImlhdCI6MTYyNjEyMDMzOCwicHViIjoiQ1lIdDdacFVKRGpEcTFWY3BpRnJKMXhvMW1GNmdYMU1lQXVjNktuSG9UYXU1bVpDbzUyV0ZCIiwiY2FwIjpbImdlbmVyaWMiXX0.2qfbsglMaTOu6Hc0NtYftgGFfx76f3OmpJrpEJiuvOL1Ul+xcdFs2l4eCu6K1M9HAH0cFWAoRMjyqQvQ2mUYCw";
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
            string exported = "Di.NTM2OWExMDUtYzY5MS00NGNmLTk3M2UtMWFlNTI0MTY5ZDE4:aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiI0YTNlMGI2Yi1iZmZiLTRmZWItYWI1NS00M2VlMzMzOGIzYmYiLCJzdWIiOiI1MzY5YTEwNS1jNjkxLTQ0Y2YtOTczZS0xYWU1MjQxNjlkMTgiLCJpc3MiOiI0NWEzOGE2Mi1lODg4LTQ2Y2ItYmRiYy1hOWE2YWJhNmFjY2YiLCJpYXQiOjE2MjU4NjI0NjMsImV4cCI6MTY1NzM5ODQ2MywiaWt5IjoiQ1lIdDZiRjZmMURuY2k2eFRFYXVpanlQQnM4RFY3aGhqUTc4SDkzQkFqRU5qZ3ZGaGg3SEJuIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoxYVdRaU9pSmpaRFkyTjJFMk9TMDBOR0l4TFRReU5HWXRZalF3T0MwMU1HWXlOemc0TUdOak9HSWlMQ0p6ZFdJaU9pSTBOV0V6T0dFMk1pMWxPRGc0TFRRMlkySXRZbVJpWXkxaE9XRTJZV0poTm1GalkyWWlMQ0pwYzNNaU9pSTNZekkxT0dWalpDMHpPRE5sTFRRMU5EVXRPR015WmkxbFkyRm1ObUU0Wm1ZeVlUQWlMQ0pwWVhRaU9qRTJNalU0TmpJek5EUXNJbVY0Y0NJNk1UYzRNelUwTWpNME5Dd2lhV3Q1SWpvaVExbElkRGN6UW1OV1RuTnlUbkpJVlVoRFMzcFljM00xTVZkamQzbDRPVzFoUnpOSWVqUnhWVGRhVW1KelduWktjMUpDY0VOaUlpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBaR1Z1ZEdsbWVTSXNJbWx6YzNWbElsMTkuK0JYaWkvM3RYOFJ2TTBoVWVGVHlxS2c4Q0NGSlZLU1J6ZC8yamJhSkptMEhCVWlIZ3pmVzZIQnpvQkVWbmRsOGdFSHV3a2JUL0cxUEo2WU0vKzB5Q1E.mYvXRzAzZw1Lnh1taFtf1MWMidlMN8Tm56niwIZhdbsz6vEpU1szS8YVnXd/AuwokkJKmxr4UMbDBAoZVj+NDg:19aBJhWEF51sqtI8hJSQTlUw58ja8wv2woGVAB00nl15UQ/N2sO6mLTmpej5ImJxadKq5Apqy9GpE2GZMVB6Bw";
            Dime dime = Dime.Import(exported);
            Assert.AreEqual(new Guid("5369a105-c691-44cf-973e-1ae524169d18"), dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Identity), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "Di:aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiI0YTNlMGI2Yi1iZmZiLTRmZWItYWI1NS00M2VlMzMzOGIzYmYiLCJzdWIiOiI1MzY5YTEwNS1jNjkxLTQ0Y2YtOTczZS0xYWU1MjQxNjlkMTgiLCJpc3MiOiI0NWEzOGE2Mi1lODg4LTQ2Y2ItYmRiYy1hOWE2YWJhNmFjY2YiLCJpYXQiOjE2MjU4NjI0NjMsImV4cCI6MTY1NzM5ODQ2MywiaWt5IjoiQ1lIdDZiRjZmMURuY2k2eFRFYXVpanlQQnM4RFY3aGhqUTc4SDkzQkFqRU5qZ3ZGaGg3SEJuIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoxYVdRaU9pSmpaRFkyTjJFMk9TMDBOR0l4TFRReU5HWXRZalF3T0MwMU1HWXlOemc0TUdOak9HSWlMQ0p6ZFdJaU9pSTBOV0V6T0dFMk1pMWxPRGc0TFRRMlkySXRZbVJpWXkxaE9XRTJZV0poTm1GalkyWWlMQ0pwYzNNaU9pSTNZekkxT0dWalpDMHpPRE5sTFRRMU5EVXRPR015WmkxbFkyRm1ObUU0Wm1ZeVlUQWlMQ0pwWVhRaU9qRTJNalU0TmpJek5EUXNJbVY0Y0NJNk1UYzRNelUwTWpNME5Dd2lhV3Q1SWpvaVExbElkRGN6UW1OV1RuTnlUbkpJVlVoRFMzcFljM00xTVZkamQzbDRPVzFoUnpOSWVqUnhWVGRhVW1KelduWktjMUpDY0VOaUlpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBaR1Z1ZEdsbWVTSXNJbWx6YzNWbElsMTkuK0JYaWkvM3RYOFJ2TTBoVWVGVHlxS2c4Q0NGSlZLU1J6ZC8yamJhSkptMEhCVWlIZ3pmVzZIQnpvQkVWbmRsOGdFSHV3a2JUL0cxUEo2WU0vKzB5Q1E.mYvXRzAzZw1Lnh1taFtf1MWMidlMN8Tm56niwIZhdbsz6vEpU1szS8YVnXd/AuwokkJKmxr4UMbDBAoZVj+NDg";
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
            string exported = "Di.NTM2OWExMDUtYzY5MS00NGNmLTk3M2UtMWFlNTI0MTY5ZDE4:aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiJmMzRhYWQ1MC1iM2IyLTRmYzAtYTRkMC0zOTI3MGVjYjgxNjMiLCJpYXQiOjE2MjU4NjI0NTQsImtleSI6IkNZSGpYTkM5UkZYSjFabzdFZWZBR0JRYTdYbXF0QmNFWWM0RHhTR1BWQlExY3o1bnZKRkg4UiIsInB1YiI6IkNZSHQ2YkY2ZjFEbmNpNnhURWF1aWp5UEJzOERWN2hoalE3OEg5M0JBakVOamd2RmhoN0hCbiJ9:miIbSCCjAKfRjIuxUP9X70HyxORw3WtyU39PDFMhahYkdVGF8aVlfh0SAV+xqdxnhMwXW7+qFpvZuTaGg3WUAA";
            Dime dime = Dime.Import(exported);
            Assert.AreEqual(new Guid("5369a105-c691-44cf-973e-1ae524169d18"), dime.IssuerId);            
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
            string exported = "Di.NTM2OWExMDUtYzY5MS00NGNmLTk3M2UtMWFlNTI0MTY5ZDE4:aW8uZGltZWZvcm1hdC5tc2c.eyJ1aWQiOiIyOGUzNTc1Yy1lYmM1LTRjZGItOTZlMS04NmJmOGRjMTJlZGYiLCJhdWQiOiJkNDY5NDU5YS1jMjdkLTQ3MzYtOWIwYS1lZDkzMTczZDliZWEiLCJpc3MiOiI1MzY5YTEwNS1jNjkxLTQ0Y2YtOTczZS0xYWU1MjQxNjlkMTgiLCJpYXQiOjE2MjYxMjUxNDIsImV4cCI6MTYyNjEyNTI0Mn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.W4hK+T/vgST6qmtWfGpsOly0lInrjDQs9dCY+k339dL6e1UaA720mwGds97mnWdiBQx6IymsjTQp0v+SPAB6Bw:3p2rkxoXeZ6ftrgr4S4X/vUmzA6DAkX4pHL7mZRwkIZ7i1OpyOUSujJcjTlhdXQaTj/MRM3Qk6JmN678Si8TAw";
            Dime dime = Dime.Import(exported);
            Assert.AreEqual(new Guid("5369a105-c691-44cf-973e-1ae524169d18"), dime.IssuerId);            
            Assert.AreEqual(1, dime.Items.Count);
            Assert.AreEqual(typeof(Message), dime.Items.ElementAt(0).GetType());
            dime.Verify(Commons.SenderKeybox);
        }

    }

}
