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
        public static Key TrustedKey { get { if (Commons._trustedKey == null) { Commons._trustedKey = Item.Import<Key>(Commons._encodedTrustedKey); } return Commons._trustedKey; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Item.Import<Identity>(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static Key IntermediateKey { get { if (Commons._intermediateKey == null) { Commons._intermediateKey = Item.Import<Key>(Commons._encodedIntermediateKey); } return Commons._intermediateKey; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Item.Import<Identity>(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static Key SenderKey { get { if (Commons._senderKey == null) { Commons._senderKey = Item.Import<Key>(Commons._encodedSenderKey); } return Commons._senderKey; } }
        public static Identity SenderIdentity { get { if (Commons._senderIdentity == null) { Commons._senderIdentity = Item.Import<Identity>(Commons._encodedSenderIdentity); } return Commons._senderIdentity; } }
        public static Key ReceiverKey { get { if (Commons._receiverKey == null) { Commons._receiverKey = Item.Import<Key>(Commons._encodedReceiverKey); } return Commons._receiverKey; } }
        public static Identity ReceiverIdentity { get { if (Commons._receiverIdentity == null) { Commons._receiverIdentity = Item.Import<Identity>(Commons._encodedReceiverIdentity); } return Commons._receiverIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKey = "Di:KEY.eyJraWQiOiI4YTE4MTk5NC0zMzY4LTRjNTUtYTVkZC02MThhZDkyNzU0MzYiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjQ3OjIzLjc4MjIwNFoiLCJrZXkiOiJDWUhqWURFa1FKQnpYV1ZUaE53ekdlajJZVnlzSHdpc1h0cHZzZkNWNmNLamd4U1dNYkFTeGEiLCJwdWIiOiJDWUh0NmprbnVUZHVndEF2bkFzQk1NblM4b2l2UmZRd1F6bkNIRVhhdUJFVEZpeVdSVExiM1kifQ";
        private const string _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiI2NzY1ZTJjMC0zNDQxLTRkNzUtYjAxOS0yNjEzMzA5YzNkM2QiLCJzdWIiOiJhYzY0YWNmZi1kMzBmLTQwMTAtYjk2NS0zNTFhMTdlMTE0N2YiLCJpc3MiOiJhYzY0YWNmZi1kMzBmLTQwMTAtYjk2NS0zNTFhMTdlMTE0N2YiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjQ3OjMzLjA5MjM3NFoiLCJleHAiOiIyMDMxLTA4LTA3VDA5OjQ3OjMzLjA5MjM3NFoiLCJwdWIiOiJDWUh0NmprbnVUZHVndEF2bkFzQk1NblM4b2l2UmZRd1F6bkNIRVhhdUJFVEZpeVdSVExiM1kiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdfQ.AbbvXK2d9xrMU/YS7mBxqk5jghEX/UcyaysIeHSE7P6nDS9LHKRbN5fG+h+wUawyNc7bmRUtO94UE1NbqE+7cwU";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKey = "Di:KEY.eyJraWQiOiI5ZjA0ZjllNi1iN2E3LTQwOWUtYTJkYi00Y2VhNjMxNWQxNTQiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUxOjI0LjY3NTE2M1oiLCJrZXkiOiJDWUhqWU5yN2JvQ2F0VU5vOFo1SGlNSnE4UVdUN25HU2FmNVlvQmRBb0RocHJhbWJHOG42bTEiLCJwdWIiOiJDWUh0N3JNQWt6MU1SQkJ2QnE0TXNMRVJvQUViN2R2VzI2WkNrN1ZTVlZVaFdpY1NrckJSaUQifQ";
        private const string _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiI2ZjUzN2QyYS0wMjJiLTRhMGQtYjU4Yy0yMDVjOWQwMWEzNzQiLCJzdWIiOiI0OTdkMTU2Ny1kMTBhLTRiNWYtOGIwOS00YmQ5NDc3ZTQyOTUiLCJpc3MiOiJhYzY0YWNmZi1kMzBmLTQwMTAtYjk2NS0zNTFhMTdlMTE0N2YiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUxOjI0Ljc3Mzk2OVoiLCJleHAiOiIyMDI2LTA4LTA4VDA5OjUxOjI0Ljc3Mzk2OVoiLCJwdWIiOiJDWUh0N3JNQWt6MU1SQkJ2QnE0TXNMRVJvQUViN2R2VzI2WkNrN1ZTVlZVaFdpY1NrckJSaUQiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXX0.AQtQniFv3/f1yhwZtf6qp+heUiiolvUgaJwO1LZ2+q2rtmmXkP4/qzztVk9kVNdMJc4EtUcMYZ913YrrtJnvzgY";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKey = "Di:KEY.eyJraWQiOiJkMWJkNTUwMS02NGU5LTQwYjUtYTYwOC1hNGJiM2Q4MmViZTQiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUyOjUyLjU0ODYyWiIsImtleSI6IkNZSGpZRTNUaEczeGJGQzVONkhkcHN5Mzdza0dkS1RIcHlWRzRWSnlYanVOeUJ4VEIzUHJnRyIsInB1YiI6IkNZSHQ4MjMxWXhWVHRDdk1rZXBYNGRLWXFyZTZiWU12N3JjdUpaQVJQYmN1Y1I0OTl0RWhtSiJ9";
        private const string _encodedSenderIdentity = "Di:ID.eyJ1aWQiOiIxNDg5NmMxZi1lZWYzLTRhM2MtOTdkNS1kZjEyZGRjNDA4NTgiLCJzdWIiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpc3MiOiI0OTdkMTU2Ny1kMTBhLTRiNWYtOGIwOS00YmQ5NDc3ZTQyOTUiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUyOjUyLjY0NDUzOFoiLCJleHAiOiIyMDIyLTA4LTA5VDA5OjUyOjUyLjY0NDUzOFoiLCJwdWIiOiJDWUh0ODIzMVl4VlR0Q3ZNa2VwWDRkS1lxcmU2YllNdjdyY3VKWkFSUGJjdWNSNDk5dEVobUoiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKMWFXUWlPaUkyWmpVek4yUXlZUzB3TWpKaUxUUmhNR1F0WWpVNFl5MHlNRFZqT1dRd01XRXpOelFpTENKemRXSWlPaUkwT1Rka01UVTJOeTFrTVRCaExUUmlOV1l0T0dJd09TMDBZbVE1TkRjM1pUUXlPVFVpTENKcGMzTWlPaUpoWXpZMFlXTm1aaTFrTXpCbUxUUXdNVEF0WWprMk5TMHpOVEZoTVRkbE1URTBOMllpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKd2RXSWlPaUpEV1VoME4zSk5RV3Q2TVUxU1FrSjJRbkUwVFhOTVJWSnZRVVZpTjJSMlZ6STJXa05yTjFaVFZsWlZhRmRwWTFOcmNrSlNhVVFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLkFRdFFuaUZ2My9mMXlod1p0ZjZxcCtoZVVpaW9sdlVnYUp3TzFMWjIrcTJydG1tWGtQNC9xenp0Vms5a1ZOZE1KYzRFdFVjTVlaOTEzWXJydEpudnpnWQ.AVlVdQY94UsYqpLwkeOgkbQi2vT+c/9XJF/rxl++epxDjiOwNkI3nom/9wZTq7U6297rQxWabM6udgwetHGG5As";
        private static Key _senderKey;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKey = "Di:KEY.eyJraWQiOiIzM2ViNzA1Ny1kZjI2LTQ3NzMtYTkyMi1lZGE2NzM3ZTZhM2UiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjU0OjE4LjMyNzQ1MVoiLCJrZXkiOiJDWUhqWEdSWk5wcEZXTEJIU2s1WXRQRzI5OFloTnlKdzhYdHpTUXo1dlJpd0JSc0NSZFpUZm8iLCJwdWIiOiJDWUh0NlJFaEZlTFhXRzYyZXFyUGU5ZjJldmtHZldvYnlMU1NDYm5qR2ZqU1BVRzM2S1FhZ3QifQ";
        private const string _encodedReceiverIdentity = "Di:ID.eyJ1aWQiOiI2M2E5MjQ1Mi1hMDcxLTQzODAtYmU0Ny1lM2UzYzZhNjc3MTMiLCJzdWIiOiIyZDIyNGZlYy0zNjZmLTQyODQtYTgyMi0wYTVmZjA0ZTcxMWQiLCJpc3MiOiI0OTdkMTU2Ny1kMTBhLTRiNWYtOGIwOS00YmQ5NDc3ZTQyOTUiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjU0OjE4LjQxNzEyOFoiLCJleHAiOiIyMDIyLTA4LTA5VDA5OjU0OjE4LjQxNzEyOFoiLCJwdWIiOiJDWUh0NlJFaEZlTFhXRzYyZXFyUGU5ZjJldmtHZldvYnlMU1NDYm5qR2ZqU1BVRzM2S1FhZ3QiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKMWFXUWlPaUkyWmpVek4yUXlZUzB3TWpKaUxUUmhNR1F0WWpVNFl5MHlNRFZqT1dRd01XRXpOelFpTENKemRXSWlPaUkwT1Rka01UVTJOeTFrTVRCaExUUmlOV1l0T0dJd09TMDBZbVE1TkRjM1pUUXlPVFVpTENKcGMzTWlPaUpoWXpZMFlXTm1aaTFrTXpCbUxUUXdNVEF0WWprMk5TMHpOVEZoTVRkbE1URTBOMllpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKd2RXSWlPaUpEV1VoME4zSk5RV3Q2TVUxU1FrSjJRbkUwVFhOTVJWSnZRVVZpTjJSMlZ6STJXa05yTjFaVFZsWlZhRmRwWTFOcmNrSlNhVVFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLkFRdFFuaUZ2My9mMXlod1p0ZjZxcCtoZVVpaW9sdlVnYUp3TzFMWjIrcTJydG1tWGtQNC9xenp0Vms5a1ZOZE1KYzRFdFVjTVlaOTEzWXJydEpudnpnWQ.Ab6FWDHoNeSDdDHijALA7qiM4gQ0iybMcQhEWGRzXGh9oW+Kq3tVroFnPo4fsEek0g45q1KzcIWYMj1sULLnQgk";
        private static Key _receiverKey;
        private static Identity _receiverIdentity;
        #endregion
    }

}
