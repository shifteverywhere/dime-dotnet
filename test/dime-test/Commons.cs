using System;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    public class Commons
    {
        #region -- PUBLIC --
        public static Keypair TrustedKeypair { get { if (!Commons._trustedKeypair.HasValue) { Commons._trustedKeypair = Keypair.Import(Commons._encodedTrustedKeypair); } return Commons._trustedKeypair.Value; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Identity.Import(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static Keypair SenderKeypair { get { if (!Commons._senderKeypair.HasValue) { Commons._senderKeypair = Keypair.Import(Commons._encodedSenderKeypair); } return Commons._senderKeypair.Value; } }
        public static Identity SenderIdentity { get { if (Commons._senderIdentity == null) { Commons._senderIdentity = Identity.Import(Commons._encodedSenderIdentity); } return Commons._senderIdentity; } }
        public static Keypair ReceiverKeypair { get { if (!Commons._receiverKeypair.HasValue) { Commons._receiverKeypair = Keypair.Import(Commons._encodedReceiverKeypair); } return Commons._receiverKeypair.Value; } }
        public static Identity ReceiverIdentity { get { if (Commons._receiverIdentity == null) { Commons._receiverIdentity = Identity.Import(Commons._encodedReceiverIdentity); } return Commons._receiverIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKeypair = "k1.eyJraWQiOiI3NzBiNTE2YS0wY2U5LTQxMTAtYTVhNS0yYTFiZGU2OTY2YjAiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFCRmlBY3g3dGRJN2tvL3NmRnVcdTAwMkJsQXVJZXVDaEpQRDZJV3lOeU4xL29zOUUiLCJwcnYiOiJNQzRDQVFBd0JRWURLMlZ3QkNJRUlLQVx1MDAyQnBXVVI1bnFuOEo0OHJXTk1SS1dcdTAwMkIyOHpYRG9cdTAwMkJ6ZUtLUHRodEdiOXFrIn0";
        private const string _encodedTrustedIdentity = "I1.eyJzdWIiOiI3MWUyYmU1Yy03MWVkLTQyYjQtYmY5Mi04ZmJiZmU2MjA3N2MiLCJpc3MiOiI3MWUyYmU1Yy03MWVkLTQyYjQtYmY5Mi04ZmJiZmU2MjA3N2MiLCJpYXQiOjE2MjE5Njg5NjIsImV4cCI6MTkzNzMyODk2MiwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQUJGaUFjeDd0ZEk3a28vc2ZGdVx1MDAyQmxBdUlldUNoSlBENklXeU55TjEvb3M5RSIsImNhcCI6WyJpc3N1ZSJdfQ.GJGMslLqgT+S4ATRKkJUIJCI4vmAICnlg04843s38tOL1U+44REiTeb5jGgOmGQP4zujLqrxXbyu+W55xHGqCg";
        private static Keypair? _trustedKeypair;
        private static Identity _trustedIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeypair = "k1.eyJraWQiOiI1YjY5MWQwOS1mM2Y1LTRjYTktOTU0MS1mNzNkYTE1NzM1MzEiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFpU3RkdUp6cHVLanNLSjVcdTAwMkJuTzlEdEdDTktaYnBQRk01TzRUREczNUtFSGciLCJwcnYiOiJNQzRDQVFBd0JRWURLMlZ3QkNJRUlNc3hlUy9oUnhUeHF5OGRKeVZ0dEpqaXFlQnh3dmZTS2tabHJjZUozWVlSIn0";
        private const string _encodedSenderIdentity = "I1.eyJzdWIiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpc3MiOiI3MWUyYmU1Yy03MWVkLTQyYjQtYmY5Mi04ZmJiZmU2MjA3N2MiLCJpYXQiOjE2MjE5NzIwMjQsImV4cCI6MTY1MzUwODAyNCwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWlTdGR1SnpwdUtqc0tKNVx1MDAyQm5POUR0R0NOS1picFBGTTVPNFRERzM1S0VIZyIsImNhcCI6WyJhdXRob3JpemUiXX0.wCWm1Oq10qU+xOaVUM2pGWGRd1jH1saVatF1G6g/wPU2Hv9taRXhH4kVUg46qcqM2M4JwBUfo1mc6uMtgRNJBQ";
        private static Keypair? _senderKeypair;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeypair = "k1.eyJraWQiOiIzZTFlMjgyYi1jNGNkLTRkYzQtOGZiMC1jZDFmM2MzNTRkZjgiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFmXHUwMDJCeDZaekFzR1UyVVdkOUtUbDNsMUFiNU1udFczZWMwTlBXNUg1Vkh2N3MiLCJwcnYiOiJNQzRDQVFBd0JRWURLMlZ3QkNJRUlFRzF0MWVuXHUwMDJCaE83am9MSWhvZE9OWHJicGRlcTV4c25OcWRDcGNNR3ZTclEifQ";
        private const string _encodedReceiverIdentity = "I1.eyJzdWIiOiJmNDIyOTUzMi1hMzUyLTQ3NjgtOWI4Yi1hNTY0YzdjYjJjZDYiLCJpc3MiOiI3MWUyYmU1Yy03MWVkLTQyYjQtYmY5Mi04ZmJiZmU2MjA3N2MiLCJpYXQiOjE2MjE5NzIxODksImV4cCI6MTY1MzUwODE4OSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWZcdTAwMkJ4Nlp6QXNHVTJVV2Q5S1RsM2wxQWI1TW50VzNlYzBOUFc1SDVWSHY3cyIsImNhcCI6WyJhdXRob3JpemUiXX0.KVs5syD6g83V2/YgEEJxdWTKfOSZjr2dMyntPR269md5yJqXb9avtWrsIoNumj1F3XqVGXUU3VzjwiSaiQdeCg";
        private static Keypair? _receiverKeypair;
        private static Identity _receiverIdentity;
        #endregion
    }

}