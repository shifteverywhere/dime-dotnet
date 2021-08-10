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
        private const string _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiIyZmFlZDdhZC0wOWI5LTQxNzQtYTE0Ni1hNWE1ZmMyZTAzOGQiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjE3OjMzLjkzNTE3MloiLCJrZXkiOiIxaEVqU2puWGVNVkRQRnZKeUc1N1Nwd0p1ZXlyUmVjcnRDSmhEcTFjY3lpa0E0WGp1MTRYNiIsInB1YiI6IjFoUEpwV3E1S3NleGo0VWJhak1NQXA2SHEyb2ZlNVduZjJONXNBNnBMVm50YWkzcFo3RGZMIn0";
        private const string _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiI2NjZkYTYyNS05YTI5LTQzN2YtYWM0Mi0xM2JmMWE1Y2RlY2MiLCJzdWIiOiIwMGFhMjZlNy0zNGIyLTRmYTItYmRmNi0xN2ZlYzA4NDA3NjkiLCJpc3MiOiIwMGFhMjZlNy0zNGIyLTRmYTItYmRmNi0xN2ZlYzA4NDA3NjkiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjE3OjM0LjA1MTgzNloiLCJleHAiOiIyMDMxLTA4LTA4VDA2OjE3OjM0LjA1MTgzNloiLCJwdWIiOiIxaFBKcFdxNUtzZXhqNFViYWpNTUFwNkhxMm9mZTVXbmYyTjVzQTZwTFZudGFpM3BaN0RmTCIsImNhcCI6WyJnZW5lcmljIiwiaXNzdWUiLCJzZWxmIl19.AZ9wMJfnHv3n49h0VJXnm3RMT0hV/2TlC49yTvzyFDhIO1S0zPyWDIWNE1Y9ow2gegnBJw7VxIW4z4bdFWn+4gQ";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiIwOGYwOGFhMy1iOWEyLTQ2NDgtODRlOC0wNTI1NzYxMzE0M2QiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjE5OjUzLjY4OTY5N1oiLCJrZXkiOiIxaEVqS3dQc3JqZ0Vtb0E3NmF2SmRKanZaeFAxMlp1QlRvZnZHMlFCeXNwQ2VMejFuaVRyYiIsInB1YiI6IjFoUEt1RUU4ckxuNHA2Tkh1ejNOakZRVGY2NFU2SFE3Sno4ZHE4Um1ZTkJMNndOVjNOQXJDIn0";
        private const string _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiI0NWU1MjAxNy0wZWIyLTQ5NjctODUxYS1mNTgyZTI2ZjRmZjMiLCJzdWIiOiJkZDNjZmQ2ZS1hMzY2LTRiMGMtYTRlMy1hZTExZjdjZGY5NjciLCJpc3MiOiIwMGFhMjZlNy0zNGIyLTRmYTItYmRmNi0xN2ZlYzA4NDA3NjkiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjE5OjUzLjgwMjU1MVoiLCJleHAiOiIyMDI2LTA4LTA5VDA2OjE5OjUzLjgwMjU1MVoiLCJwdWIiOiIxaFBLdUVFOHJMbjRwNk5IdXozTmpGUVRmNjRVNkhRN0p6OGRxOFJtWU5CTDZ3TlYzTkFyQyIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiLCJpc3N1ZSJdfQ.AZf3WFSof6DXNHmwFbaAVGjvsOqpXagRRZxVWKeam7Sx+i8ct13FkFmWQ2N/lfnTzYM44u3OsdNEUFwxPngOHw4";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- ISSUER IDENTITY (SENDER) --
        private const string _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiJjMWNkNjRmNi0wNDk4LTQxOWYtYmY2OS05MWJkYWU4NDYxYmMiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIyOjQwLjc5NTk5MloiLCJrZXkiOiIxaEVpZ3l5N3Fva0R2ZzRWNFk1N0FKdjdkN1J3TmNGMTRMNVUzOFdWMUh1NkIxVnV2YmlSbyIsInB1YiI6IjFoUEtabW9GcmQxWEFTa0hzcVRBYjMycWt2UzFOU1phTW1jN3NxZHZLNEhBNkJ1dERiTkY0In0";
        private const string _encodedIssuerIdentity = "Di:ID.eyJ1aWQiOiI3NDlkNTA4Ni0xNmFhLTRhM2YtYjc1Mi0zMDYyNzBiMDg1YzUiLCJzdWIiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpc3MiOiJkZDNjZmQ2ZS1hMzY2LTRiMGMtYTRlMy1hZTExZjdjZGY5NjciLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIyOjQwLjg5MDYwMVoiLCJleHAiOiIyMDIyLTA4LTEwVDA2OjIyOjQwLjg5MDYwMVoiLCJwdWIiOiIxaFBLWm1vRnJkMVhBU2tIc3FUQWIzMnFrdlMxTlNaYU1tYzdzcWR2SzRIQTZCdXREYk5GNCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUkwTldVMU1qQXhOeTB3WldJeUxUUTVOamN0T0RVeFlTMW1OVGd5WlRJMlpqUm1aak1pTENKemRXSWlPaUprWkROalptUTJaUzFoTXpZMkxUUmlNR010WVRSbE15MWhaVEV4WmpkalpHWTVOamNpTENKcGMzTWlPaUl3TUdGaE1qWmxOeTB6TkdJeUxUUm1ZVEl0WW1SbU5pMHhOMlpsWXpBNE5EQTNOamtpTENKcFlYUWlPaUl5TURJeExUQTRMVEV3VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE1VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKd2RXSWlPaUl4YUZCTGRVVkZPSEpNYmpSd05rNUlkWG96VG1wR1VWUm1OalJWTmtoUk4wcDZPR1J4T0ZKdFdVNUNURFozVGxZelRrRnlReUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVpmM1dGU29mNkRYTkhtd0ZiYUFWR2p2c09xcFhhZ1JSWnhWV0tlYW03U3graThjdDEzRmtGbVdRMk4vbGZuVHpZTTQ0dTNPc2RORVVGd3hQbmdPSHc0.AawlZOyXVbC53NP0kP33PIav0TTfyVLpVzF+7H1Bzb95iTdV8hOyLc6q2el8ZYFyvRUqXu5BNk2ibQbkc2K8igQ";
        private static Key _issuerKey;
        private static Identity _issuerIdentity;
        #endregion

        #region -- AUDIENCE IDENTITY (RECEIVER) --
        private const string _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiIyODJmYWFkOS0xNWMwLTRhMzItYjFkZC03Njg0NTY0MDFkYzYiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIzOjI3LjE3NDU0WiIsImtleSI6IjFoRWliUjkzOVF4MndnR1J1NjlDUXRoUktWdzJ2QnFEdDdxTmoyMXg2ZEJZV0t2QjRmTTFGIiwicHViIjoiMWhQSzJhRXY3aFNBS1pyOWlvOUNIWTF0dHVZbU5XNFROUktUcFFWRUhHNXRNV1NReUR2RTcifQ";
        private const string _encodedAudienceIdentity = "Di:ID.eyJ1aWQiOiJhNWJmMDgwNy00NWNkLTRkOGYtYmY1My04N2QxZDY4MzJmZWMiLCJzdWIiOiJmYzFjYzhjOC0yOWUyLTQ1Y2UtYjFjMi0xNzJhOTNlNzcxZTUiLCJpc3MiOiJkZDNjZmQ2ZS1hMzY2LTRiMGMtYTRlMy1hZTExZjdjZGY5NjciLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIzOjI3LjI2NzU1NVoiLCJleHAiOiIyMDIyLTA4LTEwVDA2OjIzOjI3LjI2NzU1NVoiLCJwdWIiOiIxaFBLMmFFdjdoU0FLWnI5aW85Q0hZMXR0dVltTlc0VE5SS1RwUVZFSEc1dE1XU1F5RHZFNyIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUkwTldVMU1qQXhOeTB3WldJeUxUUTVOamN0T0RVeFlTMW1OVGd5WlRJMlpqUm1aak1pTENKemRXSWlPaUprWkROalptUTJaUzFoTXpZMkxUUmlNR010WVRSbE15MWhaVEV4WmpkalpHWTVOamNpTENKcGMzTWlPaUl3TUdGaE1qWmxOeTB6TkdJeUxUUm1ZVEl0WW1SbU5pMHhOMlpsWXpBNE5EQTNOamtpTENKcFlYUWlPaUl5TURJeExUQTRMVEV3VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE1VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKd2RXSWlPaUl4YUZCTGRVVkZPSEpNYmpSd05rNUlkWG96VG1wR1VWUm1OalJWTmtoUk4wcDZPR1J4T0ZKdFdVNUNURFozVGxZelRrRnlReUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVpmM1dGU29mNkRYTkhtd0ZiYUFWR2p2c09xcFhhZ1JSWnhWV0tlYW03U3graThjdDEzRmtGbVdRMk4vbGZuVHpZTTQ0dTNPc2RORVVGd3hQbmdPSHc0.AeMn6iMBWVR90YDYUINacKJFrrHMHzlwwoy/IC9nyQcBPNDJli/t2N8Uun+NMZQrjvUpu5aWCSZTrwEvjhgr/w0";
        private static Key _audienceKey;
        private static Identity _audienceIdentity;
        #endregion
    }

}
