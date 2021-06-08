//
//  Commons.cs
//  DiME - Digital Identity Message Envelope
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
        public static KeyBox TrustedKeypair { get { if (Commons._trustedKeypair == null) { Commons._trustedKeypair = Dime.Import<KeyBox>(Commons._encodedTrustedKeypair); } return Commons._trustedKeypair; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Dime.Import<Identity>(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static KeyBox IntermediateKeypair { get { if (Commons._intermediateKeypair == null) { Commons._intermediateKeypair = Dime.Import<KeyBox>(Commons._encodedIntermediateKeypair); } return Commons._intermediateKeypair; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Dime.Import<Identity>(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static KeyBox SenderKeypair { get { if (Commons._senderKeypair == null) { Commons._senderKeypair = Dime.Import<KeyBox>(Commons._encodedSenderKeypair); } return Commons._senderKeypair; } }
        public static Identity SenderIdentity { get { if (Commons._senderIdentity == null) { Commons._senderIdentity = Dime.Import<Identity>(Commons._encodedSenderIdentity); } return Commons._senderIdentity; } }
        public static KeyBox ReceiverKeypair { get { if (Commons._receiverKeypair == null) { Commons._receiverKeypair = Dime.Import<KeyBox>(Commons._encodedReceiverKeypair); } return Commons._receiverKeypair; } }
        public static Identity ReceiverIdentity { get { if (Commons._receiverIdentity == null) { Commons._receiverIdentity = Dime.Import<Identity>(Commons._encodedReceiverIdentity); } return Commons._receiverIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKeypair = "DI1.aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiJkMzJjMWE4MC00MGM0LTQ2NjgtOGY5My0zYjU5OWQyMzNlMTMiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSU9NZWZRempmdVEwRFlhZjNad013UVEzZ3NYT05BNHBHU0ltSXhYaTZ5dkgiLCJwdWIiOiJNQ293QlFZREsyVndBeUVBRkdGNlYva1x1MDAyQk9vbTFcdTAwMkJhZlVPS2V5NjNMMGtzSnBpV3E4XHUwMDJCdFx1MDAyQnliZEJMMFgwIn0";
        private const string _encodedTrustedIdentity = "DI1.aW8uZGltZWZvcm1hdC5pZA.eyJzdWIiOiI3NTA0NjA3Mi01MjY4LTQ1ZTgtYmVhNS02ZDQxOWE5NmIyNjEiLCJpc3MiOiI3NTA0NjA3Mi01MjY4LTQ1ZTgtYmVhNS02ZDQxOWE5NmIyNjEiLCJpYXQiOjE2MjMxODA0MjcsImV4cCI6MTkzODU0MDQyNywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQUZHRjZWL2tcdTAwMkJPb20xXHUwMDJCYWZVT0tleTYzTDBrc0pwaVdxOFx1MDAyQnRcdTAwMkJ5YmRCTDBYMCIsImNhcCI6WyJnZW5lcmljIiwiaXNzdWUiLCJzZWxmIl19.Oej6V8N0X+LPCYW0a0acqBRhAnNoVk9QBSb7o6r0QUxK8zmF0ENHumr2OsLWc7NjKffhPXmp+mEfQQ8EXqcWBA";
        private static KeyBox _trustedKeypair;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "DI1.aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiI5MDgxYzA2OC03MzZiLTQyODktYTUyMy02ZDhkNzc3YmRhZmQiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSU55aHJZXHUwMDJCYkhvRlx1MDAyQjVRXHUwMDJCbU81SnpaVDdHSFhPVEpHT0c2azI0RUZEUUNTcUoiLCJwdWIiOiJNQ293QlFZREsyVndBeUVBa21mVVZGeDZlMFluSWk5VVpvVDJRUkQ0ZkNDMjRVYlFkeXVsc3htd1x1MDAyQkpVIn0";
        private const string _encodedIntermediateIdentity = "DI1.aW8uZGltZWZvcm1hdC5pZA.eyJzdWIiOiI5YWU4NDVmZi04NzQ3LTQyYWItYmRhYi1lYmMxNWM4OGE3N2QiLCJpc3MiOiI3NTA0NjA3Mi01MjY4LTQ1ZTgtYmVhNS02ZDQxOWE5NmIyNjEiLCJpYXQiOjE2MjMxODA4MTcsImV4cCI6MTc4MDg2MDgxNywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWttZlVWRng2ZTBZbklpOVVab1QyUVJENGZDQzI0VWJRZHl1bHN4bXdcdTAwMkJKVSIsImNhcCI6WyJnZW5lcmljIiwiaXNzdWUiXX0.w+K0L60BnguBblz3vdqgI+gg0oCYquxqU60PM5dKTSGScoPbl572QsKrmU1owFjWKw7tPU5ppeQe+0oarSJJDg";
        private static KeyBox _intermediateKeypair;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeypair = "DI1.aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiI5NjczNmMwYi0zYTIxLTQxNjItODc4YS05MjFkN2RkNzIyMzQiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSU9ibUZtVEFQR0JKTTRoSGFIYmYzbjk5L3FTVlpaczd1V1FsNE9nTVpoY0wiLCJwdWIiOiJNQ293QlFZREsyVndBeUVBOXNhVUNCc1x1MDAyQk00c1JqNW5pRnVGVlcvczViTkVQbHJWUzdLSUxWZnNQUmpvIn0";
        private const string _encodedSenderIdentity = "DI1.aW8uZGltZWZvcm1hdC5pZA.eyJzdWIiOiI0MTQ0ZTkwMi0wYzFkLTQ4NDgtOTBmYy1lZDBkOTMzOGI2MzMiLCJpc3MiOiI5YWU4NDVmZi04NzQ3LTQyYWItYmRhYi1lYmMxNWM4OGE3N2QiLCJpYXQiOjE2MjMxODExMzcsImV4cCI6MTY1NDcxNzEzNywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQTlzYVVDQnNcdTAwMkJNNHNSajVuaUZ1RlZXL3M1Yk5FUGxyVlM3S0lMVmZzUFJqbyIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.REkxLmFXOHVaR2x0WldadmNtMWhkQzVwWkEuZXlKemRXSWlPaUk1WVdVNE5EVm1aaTA0TnpRM0xUUXlZV0l0WW1SaFlpMWxZbU14TldNNE9HRTNOMlFpTENKcGMzTWlPaUkzTlRBME5qQTNNaTAxTWpZNExUUTFaVGd0WW1WaE5TMDJaRFF4T1dFNU5tSXlOakVpTENKcFlYUWlPakUyTWpNeE9EQTRNVGNzSW1WNGNDSTZNVGM0TURnMk1EZ3hOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXdHRabFZXUm5nMlpUQlpia2xwT1ZWYWIxUXlVVkpFTkdaRFF6STBWV0pSWkhsMWJITjRiWGRjZFRBd01rSktWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAudytLMEw2MEJuZ3VCYmx6M3ZkcWdJK2dnMG9DWXF1eHFVNjBQTTVkS1RTR1Njb1BibDU3MlFzS3JtVTFvd0ZqV0t3N3RQVTVwcGVRZSswb2FyU0pKRGc.MJu/9sKX+uF5kgDSbHHwrNtFOKJ96uph47BFdLX/RTKaSpAQNVFQc103vHpY4KiUPqDRwL7x+pPdqO9Kp9zdBQ";
        private static KeyBox _senderKeypair;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeypair = "DI1.aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiJiMDE5ZTk2OC00NDBkLTRmZDctOGI0Mi1mOGUxNGUyZGIzN2EiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSUhKM0lUd3d0RkFkRXBtZi8zRDFrOWQwYUVkejdvUWxCVndiaXFzc2NmZWoiLCJwdWIiOiJNQ293QlFZREsyVndBeUVBcHFSdEgvTnVxeEpKa2Z6bVFEUVx1MDAyQmFiNXQ0dk9lQ01WSjFzM3FiN3RyUmgwIn0";
        private const string _encodedReceiverIdentity = "DI1.aW8uZGltZWZvcm1hdC5pZA.eyJzdWIiOiI1N2YxODEzYi0xZTNkLTQ2OGQtOTA0Mi0zNzg5ZTUzNDdlN2MiLCJpc3MiOiI5YWU4NDVmZi04NzQ3LTQyYWItYmRhYi1lYmMxNWM4OGE3N2QiLCJpYXQiOjE2MjMxODExODcsImV4cCI6MTY1NDcxNzE4NywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQXBxUnRIL051cXhKSmtmem1RRFFcdTAwMkJhYjV0NHZPZUNNVkoxczNxYjd0clJoMCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.REkxLmFXOHVaR2x0WldadmNtMWhkQzVwWkEuZXlKemRXSWlPaUk1WVdVNE5EVm1aaTA0TnpRM0xUUXlZV0l0WW1SaFlpMWxZbU14TldNNE9HRTNOMlFpTENKcGMzTWlPaUkzTlRBME5qQTNNaTAxTWpZNExUUTFaVGd0WW1WaE5TMDJaRFF4T1dFNU5tSXlOakVpTENKcFlYUWlPakUyTWpNeE9EQTRNVGNzSW1WNGNDSTZNVGM0TURnMk1EZ3hOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXdHRabFZXUm5nMlpUQlpia2xwT1ZWYWIxUXlVVkpFTkdaRFF6STBWV0pSWkhsMWJITjRiWGRjZFRBd01rSktWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAudytLMEw2MEJuZ3VCYmx6M3ZkcWdJK2dnMG9DWXF1eHFVNjBQTTVkS1RTR1Njb1BibDU3MlFzS3JtVTFvd0ZqV0t3N3RQVTVwcGVRZSswb2FyU0pKRGc.hnWfWuQMjkyRNdnEyM+7OffJUjL6t7AwDA8qWipnAzbZUIDIoQafF2W1gDTxSD0DRy9q7saBDfQgAdY7aXbDDg";
        private static KeyBox _receiverKeypair;
        private static Identity _receiverIdentity;
        #endregion
    }

}
