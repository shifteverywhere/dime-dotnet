//
//  Commons.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    public class Commons
    {
        #region -- PUBLIC --
        public static Key TrustedKey { get { if (Commons._trustedKey == null) { Commons._trustedKey = Item.Import<Key>(Commons._encodedTrustedKey); } return Commons._trustedKey; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Item.Import<Identity>(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static Key IntermediateKey { get { if (Commons._intermediateKey == null) { Commons._intermediateKey = Item.Import<Key>(Commons._encodedIntermediateKey); } return Commons._intermediateKey; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Item.Import<Identity>(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static Key IssuerKey { get { if (Commons._issuerKey == null) { Commons._issuerKey = Item.Import<Key>(Commons._encodedIssuerKey); } return Commons._issuerKey; } }
        public static Identity IssuerIdentity { get { if (Commons._issuerIdentity == null) { Commons._issuerIdentity = Item.Import<Identity>(Commons._encodedIssuerIdentity); } return Commons._issuerIdentity; } }
        public static Key AudienceKey { get { if (Commons._audienceKey == null) { Commons._audienceKey = Item.Import<Key>(Commons._encodedAudienceKey); } return Commons._audienceKey; } }
        public static Identity AudienceIdentity { get { if (Commons._audienceIdentity == null) { Commons._audienceIdentity = Item.Import<Identity>(Commons._encodedAudienceIdentity); } return Commons._audienceIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiJkNjQ0M2ZkMC1lNzJlLTRmMjItYTAzZS02YmJiMTI5YmM1MzQiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUxOjI2LjI3MzY4MloiLCJrZXkiOiIxaEVrNFAxMkQ3Vm1NSHhBa2kyUW5ubjVTbVZka3U5QlJ4ZnpQVmtWWGJHaXNIam5GQmtRUyIsInB1YiI6IjFoUEtOTVpSV3lqUkdDNFdhRmlrQWk0NEdQenZxWU5ieXBmY3IyekdXcjYzZVB1cG5MQ2YxIn0";
        private const string _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiIxOTg3MTY0MS1mMGZlLTRlMjUtOTcxZi1mYmJkNmI0MmE3NjciLCJzdWIiOiJjY2U5Mzk0MC1hZmNiLTRhYTEtOTA2My1mMGYwYTYzYTVlZDAiLCJpc3MiOiJjY2U5Mzk0MC1hZmNiLTRhYTEtOTA2My1mMGYwYTYzYTVlZDAiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUxOjI2LjM4NDM1OFoiLCJleHAiOiIyMDMxLTA4LTA3VDEwOjUxOjI2LjM4NDM1OFoiLCJwdWIiOiIxaFBLTk1aUld5alJHQzRXYUZpa0FpNDRHUHp2cVlOYnlwZmNyMnpHV3I2M2VQdXBuTENmMSIsImNhcCI6WyJnZW5lcmljIiwiaXNzdWUiLCJzZWxmIl19.ARIizM4wG8iyaCvVA4Bb0V8RgT9iG3nNG2YRvc0x5WMrM3bhN1b+0NjWKT5MYU8bGzHEM3o2WkCmw0Ka1QQNBAc";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiI1OGNkMjEyZS0zZjNkLTQ3YTgtOTBhZS05YjAwMjVlMDFkZjIiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUyOjMyLjkxNDM3M1oiLCJrZXkiOiIxaEVpeUJ5Z0VtazJtN1lxYW9pR2hjMXBzTXhBc2ZQSDNWa1hVQ1NpTjNBZU5vNVEzcGI2NiIsInB1YiI6IjFoUEpIWTdrY1lVdG14dWJCY0FYZkpYb3lLY3FYTDNGc0RVRG5Wa2JHSmhQeXlLaFZuUmlVIn0";
        private const string _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiIyOTBkMWRmYi0wMWI0LTQzOTUtYmE1Yi1iNmI0MDFkYWUyMTQiLCJzdWIiOiJmNjhkMTVhYy04MjJkLTRmZGMtODFjYy04ZTUwYjQ3ODc3MmUiLCJpc3MiOiJjY2U5Mzk0MC1hZmNiLTRhYTEtOTA2My1mMGYwYTYzYTVlZDAiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUyOjMzLjAwNzIzOFoiLCJleHAiOiIyMDI2LTA4LTA4VDEwOjUyOjMzLjAwNzIzOFoiLCJwdWIiOiIxaFBKSFk3a2NZVXRteHViQmNBWGZKWG95S2NxWEwzRnNEVURuVmtiR0poUHl5S2hWblJpVSIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiLCJpc3N1ZSJdfQ.AVW4XxuW2Mf+uWxto3bfilfaV/EAdLYXg/uziniLXJ8VPP4/xSRNeQaT+r2JBf6Xqd+BINgClcBNhQx3qeOqDAo";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- ISSUER IDENTITY (SENDER) --
        private const string _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiJhZDBmZmQwMi0yMjE1LTQ4NTktOGYwZC0xMTcxNzU0Njg3MjIiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUzOjIyLjQyMzExNFoiLCJrZXkiOiIxaEVqMWRpc01yTUNFVURZM05SVnZMc2FaVWpaZlFUWmNCZ0FDRXV0UExDWXF2eGVCUTVTeiIsInB1YiI6IjFoUEp1ZEdSd2s2RTZrV0pZclhCOUE5cmhRY1RiZ0ZoWjY1UlNZdkxOS0dQZ1BRblluNGM4In0";
        private const string _encodedIssuerIdentity = "Di:ID.eyJ1aWQiOiJlY2EzOWFiYS00YzY5LTQ4YjItYTliZS0wYzQxNmZlMDgwZDciLCJzdWIiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpc3MiOiJmNjhkMTVhYy04MjJkLTRmZGMtODFjYy04ZTUwYjQ3ODc3MmUiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUzOjIyLjUxNTM0MloiLCJleHAiOiIyMDIyLTA4LTA5VDEwOjUzOjIyLjUxNTM0MloiLCJwdWIiOiIxaFBKdWRHUndrNkU2a1dKWXJYQjlBOXJoUWNUYmdGaFo2NVJTWXZMTktHUGdQUW5ZbjRjOCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUl5T1RCa01XUm1ZaTB3TVdJMExUUXpPVFV0WW1FMVlpMWlObUkwTURGa1lXVXlNVFFpTENKemRXSWlPaUptTmpoa01UVmhZeTA0TWpKa0xUUm1aR010T0RGall5MDRaVFV3WWpRM09EYzNNbVVpTENKcGMzTWlPaUpqWTJVNU16azBNQzFoWm1OaUxUUmhZVEV0T1RBMk15MW1NR1l3WVRZellUVmxaREFpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKd2RXSWlPaUl4YUZCS1NGazNhMk5aVlhSdGVIVmlRbU5CV0daS1dHOTVTMk54V0V3elJuTkVWVVJ1Vm10aVIwcG9VSGw1UzJoV2JsSnBWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVZXNFh4dVcyTWYrdVd4dG8zYmZpbGZhVi9FQWRMWVhnL3V6aW5pTFhKOFZQUDQveFNSTmVRYVQrcjJKQmY2WHFkK0JJTmdDbGNCTmhReDNxZU9xREFv.AUIHWWvs5nuQuXsJ396vh8HbtvVElJqXQO+GixI2ZStdzO+Wgw7/mIURS0c/t3hBvUNgb8hnrG8fC3iFIY/sFgM";
        private static Key _issuerKey;
        private static Identity _issuerIdentity;
        #endregion

        #region -- AUDIENCE IDENTITY (RECEIVER) --
        private const string _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiI2MDE5MzY4My0wNTM1LTQ4NzgtYTU0OS1lM2E4ZTIwZDZlZTYiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjU0OjAzLjcyNzM3NVoiLCJrZXkiOiIxaEVqQXNUVUtnVzQ4Rk1KRW1LZjZGQ0hRU1Y2d2NCcXNFVjN1dktXWFlvZ2ZIN2dZc0o5UiIsInB1YiI6IjFoUEpGWG9lanlRdTRSV1dydkpKTW5TbW1zeHBTY1FNaEF4Z2tlTVFQMjNRcUF1NzlGc3FiIn0";
        private const string _encodedAudienceIdentity = "Di:ID.eyJ1aWQiOiJkOGYxMGRiMi1mOWEzLTQxOWMtYThkZS0yYjIxOTA4ZWFiZjMiLCJzdWIiOiI0ZDAzMTM1Zi0wZTBkLTQ4YjYtYTQ0Ny01ZDM1YmU3ODE5ZjkiLCJpc3MiOiJmNjhkMTVhYy04MjJkLTRmZGMtODFjYy04ZTUwYjQ3ODc3MmUiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjU0OjAzLjgyMDgxWiIsImV4cCI6IjIwMjItMDgtMDlUMTA6NTQ6MDMuODIwODFaIiwicHViIjoiMWhQSkZYb2VqeVF1NFJXV3J2SkpNblNtbXN4cFNjUU1oQXhna2VNUVAyM1FxQXU3OUZzcWIiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKMWFXUWlPaUl5T1RCa01XUm1ZaTB3TVdJMExUUXpPVFV0WW1FMVlpMWlObUkwTURGa1lXVXlNVFFpTENKemRXSWlPaUptTmpoa01UVmhZeTA0TWpKa0xUUm1aR010T0RGall5MDRaVFV3WWpRM09EYzNNbVVpTENKcGMzTWlPaUpqWTJVNU16azBNQzFoWm1OaUxUUmhZVEV0T1RBMk15MW1NR1l3WVRZellUVmxaREFpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKd2RXSWlPaUl4YUZCS1NGazNhMk5aVlhSdGVIVmlRbU5CV0daS1dHOTVTMk54V0V3elJuTkVWVVJ1Vm10aVIwcG9VSGw1UzJoV2JsSnBWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVZXNFh4dVcyTWYrdVd4dG8zYmZpbGZhVi9FQWRMWVhnL3V6aW5pTFhKOFZQUDQveFNSTmVRYVQrcjJKQmY2WHFkK0JJTmdDbGNCTmhReDNxZU9xREFv.AQUin5SwUGOBjWZchDRyDSg9qgF+z5CxyGPiYGbxgbRepGHSdtPErGstODFF3LX4QIs/Wv/QB+C+kOgaAhY/Hws";
        private static Key _audienceKey;
        private static Identity _audienceIdentity;
        #endregion
    }

}
