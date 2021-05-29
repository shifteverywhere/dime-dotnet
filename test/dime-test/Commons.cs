using System;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    public class Commons
    {
        #region -- PUBLIC --
        public static Keypair TrustedKeypair { get { if (!Commons._trustedKeypair.HasValue) { Commons._trustedKeypair = Keypair.Import(Commons._encodedTrustedKeypair); } return Commons._trustedKeypair.Value; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Identity.Import(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static Keypair IntermediateKeypair { get { if (!Commons._intermediateKeypair.HasValue) { Commons._intermediateKeypair = Keypair.Import(Commons._encodedIntermediateKeypair); } return Commons._intermediateKeypair.Value; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Identity.Import(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static Keypair SenderKeypair { get { if (!Commons._senderKeypair.HasValue) { Commons._senderKeypair = Keypair.Import(Commons._encodedSenderKeypair); } return Commons._senderKeypair.Value; } }
        public static Identity SenderIdentity { get { if (Commons._senderIdentity == null) { Commons._senderIdentity = Identity.Import(Commons._encodedSenderIdentity); } return Commons._senderIdentity; } }
        public static Keypair ReceiverKeypair { get { if (!Commons._receiverKeypair.HasValue) { Commons._receiverKeypair = Keypair.Import(Commons._encodedReceiverKeypair); } return Commons._receiverKeypair.Value; } }
        public static Identity ReceiverIdentity { get { if (Commons._receiverIdentity == null) { Commons._receiverIdentity = Identity.Import(Commons._encodedReceiverIdentity); } return Commons._receiverIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKeypair = "k1.eyJraWQiOiJkNDY4MDJjNC00MmUxLTRjNGYtOGFkNC0xOGZiOWZjMzcwMWUiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUE5Mmk5UHRUOFZGdHFLdkpISHFVTWx1eW5mbmxIQW1zZFluNkpFbXRGSVpVIiwicHJ2IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJTUp3cjQzTzJIMFdZNkdsbzJ2amU2VnVFZzdmdFc3R3lUMy80RXh0Q0ZRZCJ9";
        private const string _encodedTrustedIdentity = "I1.eyJzdWIiOiI3NmE3ZDg0OS03Y2RjLTQ4ZjctYTdiNi04M2M5ZjUzNTI1YWUiLCJpc3MiOiI3NmE3ZDg0OS03Y2RjLTQ4ZjctYTdiNi04M2M5ZjUzNTI1YWUiLCJpYXQiOjE2MjIzMjQzMTIsImV4cCI6MTkzNzY4NDMxMiwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQTkyaTlQdFQ4VkZ0cUt2SkhIcVVNbHV5bmZubEhBbXNkWW42SkVtdEZJWlUiLCJjYXAiOlsiaXNzdWUiLCJnZW5lcmljIiwic2VsZiJdfQ.l4hwZePabLG0ufbCen3iZ4dBa1Po2jx/lt4M8nsItPmx5J699H3Y7PY+NJUvcuHMJcJttoX2zNgCFVaxwEnsAA";
        private static Keypair? _trustedKeypair;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "k1.eyJraWQiOiI4NzFiOTkwNy01YjIzLTRjMGMtYjU5ZS1kZTdmMWU3ZWIzYjgiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFSQjBWcmJ6L2JIOVYxQUxKUGY1Slx1MDAyQnpFUDFuODFjTTU2XHUwMDJCL3Y3VzhlMTBVYyIsInBydiI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSVA0cGdcdTAwMkI1dWJvQnpJZ3czQUR2M1dKQm4xUldPSmZyb3ZteG9Yb2p2YWkwMCJ9";
        private const string _encodedIntermediateIdentity = "I1.eyJzdWIiOiIwODVmNTc4Yy0zMjRjLTQwOTctODRmOS1kN2E1ZmJlMTJkZTMiLCJpc3MiOiI3NmE3ZDg0OS03Y2RjLTQ4ZjctYTdiNi04M2M5ZjUzNTI1YWUiLCJpYXQiOjE2MjIzMjQ3MzUsImV4cCI6MTc4MDAwNDczNSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQVJCMFZyYnovYkg5VjFBTEpQZjVKXHUwMDJCekVQMW44MWNNNTZcdTAwMkIvdjdXOGUxMFVjIiwiY2FwIjpbImdlbmVyaWMiLCJpc3N1ZSJdfQ.pU7dcY2OC9om/z6cBAIeJ3mxOF6sqv+fkT+xeA8Xs3On/M05r42BprbuL2etFgkWvUMARU26XOExCAnqILhBBA";
        private static Keypair? _intermediateKeypair;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeypair = "k1.eyJraWQiOiJkYjc0YmQyOC0yYTk4LTQ2NGMtYjIxMS1mZGU1MTRmZTVjZTIiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFkSmFiZEVCTmFvN3IyWEFnSFx1MDAyQmNRbFBYemRzMS85UnVZRkJ6RXpzQURwQnMiLCJwcnYiOiJNQzRDQVFBd0JRWURLMlZ3QkNJRUlEY2tIZllJRkk0VXZZWjF4QVI4QWpvNDVJbWxiNWpTSjBPdkxNUzU1dThQIn0";
        private const string _encodedSenderIdentity = "I1.eyJzdWIiOiI4NTI0NWVlNS0wM2U1LTQ1ZGEtOGRhYi03YTA5MmRkYWMwNjIiLCJpc3MiOiIwODVmNTc4Yy0zMjRjLTQwOTctODRmOS1kN2E1ZmJlMTJkZTMiLCJpYXQiOjE2MjIzMjQ5NTksImV4cCI6MTY1Mzg2MDk1OSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWRKYWJkRUJOYW83cjJYQWdIXHUwMDJCY1FsUFh6ZHMxLzlSdVlGQnpFenNBRHBCcyIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.STEuZXlKemRXSWlPaUl3T0RWbU5UYzRZeTB6TWpSakxUUXdPVGN0T0RSbU9TMWtOMkUxWm1KbE1USmtaVE1pTENKcGMzTWlPaUkzTm1FM1pEZzBPUzAzWTJSakxUUTRaamN0WVRkaU5pMDRNMk01WmpVek5USTFZV1VpTENKcFlYUWlPakUyTWpJek1qUTNNelVzSW1WNGNDSTZNVGM0TURBd05EY3pOU3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFWSkNNRlp5WW5vdllrZzVWakZCVEVwUVpqVktYSFV3TURKQ2VrVlFNVzQ0TVdOTk5UWmNkVEF3TWtJdmRqZFhPR1V4TUZWaklpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBjM04xWlNKZGZRLnBVN2RjWTJPQzlvbS96NmNCQUllSjNteE9GNnNxditma1QreGVBOFhzM09uL00wNXI0MkJwcmJ1TDJldEZna1d2VU1BUlUyNlhPRXhDQW5xSUxoQkJB.tWRr2v6O6Je7vMhoBOUb6outlIO18DHc81ncN4hplc74OlWjRUZmtFbVRdNiPrgx5Gg+E+1Sb2LskNRIOMhADA";
        private static Keypair? _senderKeypair;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeypair = "k1.eyJraWQiOiI0ZjAwZGI0ZS1mMTM3LTRmYmMtYmQyYS01NGVhODQwNzdlNWYiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFYMEhweTNYeFlmYUg2bnl3eHpKUFRYa1Y3OGlLaVNnZzV5TXhtZVx1MDAyQnR1RzgiLCJwcnYiOiJNQzRDQVFBd0JRWURLMlZ3QkNJRUlDVzA2enNOLzRnVVRrOE1EYTRFalJpV096WjZxOVFxclZMTUJnU2ZXOVhiIn0";
        private const string _encodedReceiverIdentity = "I1.eyJzdWIiOiJmNjBjNmJkNS05OWRmLTRjMDAtYmE0Yy1jZDQ4NWM4ZjVlOWMiLCJpc3MiOiIwODVmNTc4Yy0zMjRjLTQwOTctODRmOS1kN2E1ZmJlMTJkZTMiLCJpYXQiOjE2MjIzMjQ5OTcsImV4cCI6MTY1Mzg2MDk5NywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQVgwSHB5M1h4WWZhSDZueXd4ekpQVFhrVjc4aUtpU2dnNXlNeG1lXHUwMDJCdHVHOCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.STEuZXlKemRXSWlPaUl3T0RWbU5UYzRZeTB6TWpSakxUUXdPVGN0T0RSbU9TMWtOMkUxWm1KbE1USmtaVE1pTENKcGMzTWlPaUkzTm1FM1pEZzBPUzAzWTJSakxUUTRaamN0WVRkaU5pMDRNMk01WmpVek5USTFZV1VpTENKcFlYUWlPakUyTWpJek1qUTNNelVzSW1WNGNDSTZNVGM0TURBd05EY3pOU3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFWSkNNRlp5WW5vdllrZzVWakZCVEVwUVpqVktYSFV3TURKQ2VrVlFNVzQ0TVdOTk5UWmNkVEF3TWtJdmRqZFhPR1V4TUZWaklpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBjM04xWlNKZGZRLnBVN2RjWTJPQzlvbS96NmNCQUllSjNteE9GNnNxditma1QreGVBOFhzM09uL00wNXI0MkJwcmJ1TDJldEZna1d2VU1BUlUyNlhPRXhDQW5xSUxoQkJB.bTkrGXxkhQ2riPoDmjnaPnrvqqmZ3XM3gYftvZ3SCPSTav6UWpnPP94awZgAgWGKMppeoDh/qRLYbRXuVGeRBA";
        private static Keypair? _receiverKeypair;
        private static Identity _receiverIdentity;
        #endregion
    }

}