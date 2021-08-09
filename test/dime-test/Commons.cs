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
        private const string _encodedTrustedKey = "Di:KEY.eyJraWQiOiI4YWRhNmU0OS1kMDEyLTQyODctOTI2OS1hZDY1MjI4ZjRiNDIiLCJpYXQiOjE2MjYzNzgyNTcsImtleSI6IkNZSGpZQ2ppaWNlUEJTb1V5cHhZUXpxSjVOOGk1OHNUR1JxTmk5N3V0Y2hxSHJVRmNNRTRkNiIsInB1YiI6IkNZSHQ3c3hwVTExUWYzeEs3Z2dTY2ZvR0s4RDVtN2ZIWFgzR1FCSHdFR3FyUXZ6ODZneW5HdCJ9";
        private const string _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiJkNzE4ZDk5Ny1mYmRkLTQ2MzgtYTgyMy1kZTgzYTM1NGYzYTEiLCJzdWIiOiJjYTNhMGY1Yy02MGUxLTRkYzgtYTRhOS03YTgwODkzNjM5ZWYiLCJpc3MiOiJjYTNhMGY1Yy02MGUxLTRkYzgtYTRhOS03YTgwODkzNjM5ZWYiLCJpYXQiOjE2MjYzNzgyNTcsImV4cCI6MTk0MTczODI1NywicHViIjoiQ1lIdDdzeHBVMTFRZjN4SzdnZ1NjZm9HSzhENW03ZkhYWDNHUUJId0VHcXJRdno4Nmd5bkd0IiwiY2FwIjpbImdlbmVyaWMiLCJpc3N1ZSIsInNlbGYiXX0.ATSDr0H8nKGPn5PYivJZGfxNI8Rnf3cW0yeyLBGmThAer4wxLRo3LtvjYVid7SWEl1Diiz70MRyVEWcIiIraNgk";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKey = "Di:KEY.eyJraWQiOiI3NzZhOTY0MC0wNDAwLTQ1ZWMtOTVmMS1mZTg0Y2NlYzBmZDIiLCJpYXQiOjE2MjYzNzgzMDUsImtleSI6IkNZSGpYeXVmU0F3ZmRjZFlSekZucjhXVm1RR3JZcUY2bUw1MU1rNlRjUEZhNmUzM3NMQUQ0cyIsInB1YiI6IkNZSHQ2bUFiVjM5aU53TEJBQVRObWNmd29ENFZteVBrZHBGVkpLZkgxTUZyc1BXM2d3djFKciJ9";
        private const string _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiJkMjc1ZDJjMy03ZDFmLTQ0YTEtODcwZS0zODQ2OWViMDRhNDUiLCJzdWIiOiI2NDc1ODliZi03ZjdlLTRkNGMtODE3NC1lM2ViMzY2ZDVhOTEiLCJpc3MiOiJjYTNhMGY1Yy02MGUxLTRkYzgtYTRhOS03YTgwODkzNjM5ZWYiLCJpYXQiOjE2MjYzNzgzMDUsImV4cCI6MTc4NDA1ODMwNSwicHViIjoiQ1lIdDZtQWJWMzlpTndMQkFBVE5tY2Z3b0Q0Vm15UGtkcEZWSktmSDFNRnJzUFczZ3d2MUpyIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSIsImlzc3VlIl19.AavfKg1W135rwGjj31Vh4NC2C97N8A14d1VoTu0egXIf+K97IXuloaracO3GQToN8HpvV3LyQOWB68sgPu5OvQs";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKey = "Di:KEY.eyJraWQiOiI3MTc1NzFhMC0wNmY0LTQzZDUtYWUwMi00ZDMzMjQwMDExNDYiLCJpYXQiOjE2MjYzNzg0OTYsImtleSI6IkNZSGpYOWtOZUttdU1tb3Jwb1JhcDVCQUpjTDNOZTZEelZXaU56cjJBVHh4NlF5Y2pvZ3duVyIsInB1YiI6IkNZSHQ3Z1lXanpOeDV1enljZk4xOFlSMVIyTFBFZjU1aEFrdU5BQndLd0F4QU5BYmtaczlkdyJ9";
        private const string _encodedSenderIdentity = "Di:ID.eyJ1aWQiOiJjNDhlNGI2OC05MWFjLTRjOTMtYmE5Ni0xYzM1YzUwNzYxZDQiLCJzdWIiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpc3MiOiI2NDc1ODliZi03ZjdlLTRkNGMtODE3NC1lM2ViMzY2ZDVhOTEiLCJpYXQiOjE2MjYzNzg0OTYsImV4cCI6MTY1NzkxNDQ5NiwicHViIjoiQ1lIdDdnWVdqek54NXV6eWNmTjE4WVIxUjJMUEVmNTVoQWt1TkFCd0t3QXhBTkFia1pzOWR3IiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKMWFXUWlPaUprTWpjMVpESmpNeTAzWkRGbUxUUTBZVEV0T0Rjd1pTMHpPRFEyT1dWaU1EUmhORFVpTENKemRXSWlPaUkyTkRjMU9EbGlaaTAzWmpkbExUUmtOR010T0RFM05DMWxNMlZpTXpZMlpEVmhPVEVpTENKcGMzTWlPaUpqWVROaE1HWTFZeTAyTUdVeExUUmtZemd0WVRSaE9TMDNZVGd3T0Rrek5qTTVaV1lpTENKcFlYUWlPakUyTWpZek56Z3pNRFVzSW1WNGNDSTZNVGM0TkRBMU9ETXdOU3dpY0hWaUlqb2lRMWxJZERadFFXSldNemxwVG5kTVFrRkJWRTV0WTJaM2IwUTBWbTE1VUd0a2NFWldTa3RtU0RGTlJuSnpVRmN6WjNkMk1VcHlJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5LkFhdmZLZzFXMTM1cndHamozMVZoNE5DMkM5N044QTE0ZDFWb1R1MGVnWElmK0s5N0lYdWxvYXJhY08zR1FUb044SHB2VjNMeVFPV0I2OHNnUHU1T3ZRcw.AavQrK+J3jQ+sEJKoFbh12aA0vhx4z7n3FijXsF9AOOLFNkmZSelEbdPxJ3A2VFrfHEaT5/GzB5LYcJ0jUbihgQ";
        private static Key _senderKey;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKey = "Di:KEY.eyJraWQiOiI0YTBiMjlmYy01MWZlLTRkNTktYTFiZi0yMDQ5Yjk2NzhmYzYiLCJpYXQiOjE2MjYzNzg1MzgsImtleSI6IkNZSGpYVFFmck1aVmJVYlNUWFd5RldrM3BCdXZmOTV1MXF2MmI1eVc4enhBR1IxdnlOVEplZiIsInB1YiI6IkNZSHQ3VGZOYTRnUHc1M2hrZkdFS1BQUWtGTkRnd0tqMTZ0ajZRUzVpR0tFOEpnQTVMZXpqTCJ9";
        private const string _encodedReceiverIdentity = "Di:ID.eyJ1aWQiOiIzOWJhNGZiYy05MzliLTRlMjQtYTBjMS02NzExMWNhYjZhMDMiLCJzdWIiOiIwZTMyZGY2Zi0xNjg3LTQwNTktODIyOS0yM2E2NzlhODExYzkiLCJpc3MiOiI2NDc1ODliZi03ZjdlLTRkNGMtODE3NC1lM2ViMzY2ZDVhOTEiLCJpYXQiOjE2MjYzNzg1MzgsImV4cCI6MTY1NzkxNDUzOCwicHViIjoiQ1lIdDdUZk5hNGdQdzUzaGtmR0VLUFBRa0ZORGd3S2oxNnRqNlFTNWlHS0U4SmdBNUxlempMIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKMWFXUWlPaUprTWpjMVpESmpNeTAzWkRGbUxUUTBZVEV0T0Rjd1pTMHpPRFEyT1dWaU1EUmhORFVpTENKemRXSWlPaUkyTkRjMU9EbGlaaTAzWmpkbExUUmtOR010T0RFM05DMWxNMlZpTXpZMlpEVmhPVEVpTENKcGMzTWlPaUpqWVROaE1HWTFZeTAyTUdVeExUUmtZemd0WVRSaE9TMDNZVGd3T0Rrek5qTTVaV1lpTENKcFlYUWlPakUyTWpZek56Z3pNRFVzSW1WNGNDSTZNVGM0TkRBMU9ETXdOU3dpY0hWaUlqb2lRMWxJZERadFFXSldNemxwVG5kTVFrRkJWRTV0WTJaM2IwUTBWbTE1VUd0a2NFWldTa3RtU0RGTlJuSnpVRmN6WjNkMk1VcHlJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5LkFhdmZLZzFXMTM1cndHamozMVZoNE5DMkM5N044QTE0ZDFWb1R1MGVnWElmK0s5N0lYdWxvYXJhY08zR1FUb044SHB2VjNMeVFPV0I2OHNnUHU1T3ZRcw.AdowJ/n0uJdYNvU5HsSvS+GPatFfN9E2RV7sgP6JCyQiOB9H0mqkaV7v5RMLm42d07BshAb1BVUtOUQ41+tGwQ4";
        private static Key _receiverKey;
        private static Identity _receiverIdentity;
        #endregion
    }

}
