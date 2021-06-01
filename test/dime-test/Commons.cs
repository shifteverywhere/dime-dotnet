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
        private const string _encodedTrustedKeypair = "k1.eyJraWQiOiI0MzE0YjA2NS0yMzMxLTQwZmYtYWE3OS1hYzA5ZDA2ODk2MGMiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSUQycElacEtZRjNFZlphRHNUT2xPTE5lTjdxdEp6OUVlbEVpdU8vZ0QvaHciLCJwdWIiOiJNQ293QlFZREsyVndBeUVBMHFsXHUwMDJCejFXTldcdTAwMkI3SnF3ekhaZXdLWlVhQmNTZGV6Q0pxWTB5MWlOSFR3N3cifQ";
        private const string _encodedTrustedIdentity = "I1.eyJzdWIiOiI4OGFmZjBlMi1kYTM4LTQyYWQtOGVkZC02Yzg2ZDg5YzdmMjgiLCJpc3MiOiI4OGFmZjBlMi1kYTM4LTQyYWQtOGVkZC02Yzg2ZDg5YzdmMjgiLCJpYXQiOjE2MjI0OTA2NTQsImV4cCI6MTkzNzg1MDY1NCwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQTBxbFx1MDAyQnoxV05XXHUwMDJCN0pxd3pIWmV3S1pVYUJjU2RlekNKcVkweTFpTkhUdzd3IiwiY2FwIjpbImlzc3VlIiwiZ2VuZXJpYyIsInNlbGYiXX0.x3E712bQkgmAdbemd/XaYxpU1Xq5o/y7urC1WiFWz1vUAUyqpKjFZHmFLBD7v3ssoInZ0SSnUmd62tAxD5pFAA";
        private static KeyBox _trustedKeypair;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "k1.eyJraWQiOiJhNzE1OTg0Yy0yMzJhLTQxY2ItOTk0Ni1kOWQ5NGY3NDUyNTAiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSUJOakVDY3psY0V0OFIzSzhLUnhYMTRhWHVyWFFmNFFvSE9qZDBUWjU2QVAiLCJwdWIiOiJNQ293QlFZREsyVndBeUVBQ1dvb3gyelpZdFpJYUs3Q0E5bW1vQURhZEJ1Q3hkQ1IzaUpPTG9mT3V1SSJ9";
        private const string _encodedIntermediateIdentity = "I1.eyJzdWIiOiI4NDM3MDNiMC03ODFjLTRlNTYtYjMwNi0wYTVlYjU3YzVmYzkiLCJpc3MiOiI4OGFmZjBlMi1kYTM4LTQyYWQtOGVkZC02Yzg2ZDg5YzdmMjgiLCJpYXQiOjE2MjI0OTA3MjAsImV4cCI6MTkzNzg1MDcyMCwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQUNXb294MnpaWXRaSWFLN0NBOW1tb0FEYWRCdUN4ZENSM2lKT0xvZk91dUkiLCJjYXAiOlsiaXNzdWUiLCJnZW5lcmljIl19.rL89vWh1nhGxU3jve/sNMXm3eeONDdpnETtLOBnLVHFkgYIMIZH18lMyjLC44XlZDtRJUE9hq4E4rDCABEjhAA";
        private static KeyBox _intermediateKeypair;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeypair = "k1.eyJraWQiOiI3M2M5M2U5Yi03MjdhLTQxM2MtYWNhNC1hMTc5YTVhNDBiNjUiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSUhPQ1I2VnE3TkpXdFNtRnhXem9mMXNwL09nb2J4NFF2eTN4bm9Jem9tMW4iLCJwdWIiOiJNQ293QlFZREsyVndBeUVBaVBRdXdXREhkbUxhd2tYM1poQnJkVklsRG91OGxtLzdIYmFLT3IvVEdCayJ9";
        private const string _encodedSenderIdentity = "I1.eyJzdWIiOiIxNGIxMjMwMy0zZjUwLTQyOGUtOGViYS05YWM1NmY1Yzc0ZDQiLCJpc3MiOiI4NDM3MDNiMC03ODFjLTRlNTYtYjMwNi0wYTVlYjU3YzVmYzkiLCJpYXQiOjE2MjI0OTA4MDEsImV4cCI6MTY1NDAyNjgwMSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWlQUXV3V0RIZG1MYXdrWDNaaEJyZFZJbERvdThsbS83SGJhS09yL1RHQmsiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.STEuZXlKemRXSWlPaUk0TkRNM01ETmlNQzAzT0RGakxUUmxOVFl0WWpNd05pMHdZVFZsWWpVM1l6Vm1ZemtpTENKcGMzTWlPaUk0T0dGbVpqQmxNaTFrWVRNNExUUXlZV1F0T0dWa1pDMDJZemcyWkRnNVl6ZG1NamdpTENKcFlYUWlPakUyTWpJME9UQTNNakFzSW1WNGNDSTZNVGt6TnpnMU1EY3lNQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFVTlhiMjk0TW5wYVdYUmFTV0ZMTjBOQk9XMXRiMEZFWVdSQ2RVTjRaRU5TTTJsS1QweHZaazkxZFVraUxDSmpZWEFpT2xzaWFYTnpkV1VpTENKblpXNWxjbWxqSWwxOS5yTDg5dldoMW5oR3hVM2p2ZS9zTk1YbTNlZU9ORGRwbkVUdExPQm5MVkhGa2dZSU1JWkgxOGxNeWpMQzQ0WGxaRHRSSlVFOWhxNEU0ckRDQUJFamhBQQ.BDyBxIn1vrVF7zfs9owmxHQpnxMnK5Mt5f3t/lpq7ckm0KcXO5rh9ykr4nyqMcqDxUu248HDpmBSJ3IhrSrVDQ";
        private static KeyBox _senderKeypair;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeypair = "k1.eyJraWQiOiI4MThiNDBlMC03YzM2LTRlZTQtYTExMC0zMzMxNmFlOGI1MjkiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSUY2T0pcdTAwMkJvOE5mcDF4NzRxZXhyRWIyYy96Z2p0eXdOM2FKUDhVblNhQi8vNCIsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUE0dEU1eUlTYjNlZjFaNUxRWTBRWjdRZ0JmUkFcdTAwMkJyNkFJSEVtd1pYWDcwZkkifQ";
        private const string _encodedReceiverIdentity = "I1.eyJzdWIiOiI5M2YyOTZkZC00NGNjLTQ1NDEtYWIzNi1jMmUyZDVjMDZkMjIiLCJpc3MiOiI4NDM3MDNiMC03ODFjLTRlNTYtYjMwNi0wYTVlYjU3YzVmYzkiLCJpYXQiOjE2MjI0OTA4MzksImV4cCI6MTY1NDAyNjgzOSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQTR0RTV5SVNiM2VmMVo1TFFZMFFaN1FnQmZSQVx1MDAyQnI2QUlIRW13WlhYNzBmSSIsImNhcCI6WyJnZW5lcmljIl19.STEuZXlKemRXSWlPaUk0TkRNM01ETmlNQzAzT0RGakxUUmxOVFl0WWpNd05pMHdZVFZsWWpVM1l6Vm1ZemtpTENKcGMzTWlPaUk0T0dGbVpqQmxNaTFrWVRNNExUUXlZV1F0T0dWa1pDMDJZemcyWkRnNVl6ZG1NamdpTENKcFlYUWlPakUyTWpJME9UQTNNakFzSW1WNGNDSTZNVGt6TnpnMU1EY3lNQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFVTlhiMjk0TW5wYVdYUmFTV0ZMTjBOQk9XMXRiMEZFWVdSQ2RVTjRaRU5TTTJsS1QweHZaazkxZFVraUxDSmpZWEFpT2xzaWFYTnpkV1VpTENKblpXNWxjbWxqSWwxOS5yTDg5dldoMW5oR3hVM2p2ZS9zTk1YbTNlZU9ORGRwbkVUdExPQm5MVkhGa2dZSU1JWkgxOGxNeWpMQzQ0WGxaRHRSSlVFOWhxNEU0ckRDQUJFamhBQQ.J0lRRe+NFmYPrpSPjL4TjNoyuC0rrWrXrB3hl6H4ae8Z3Lf3lWZ9aiqmL/f8L3iKZemlz+8lYJCy6KCfoLN8Ag";
        private static KeyBox _receiverKeypair;
        private static Identity _receiverIdentity;
        #endregion
    }

}
