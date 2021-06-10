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
        private const string _encodedTrustedKeypair = "DiME:aW8uZGltZWZvcm1hdC5reWI.eyJ2ZXIiOjEsImtpZCI6IjZmMTdjYTY5LTEyNzUtNDNhMC1iYTkzLWQxOTVmYzQzYTYwYSIsImt0eSI6MSwia2V5IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJSkJnc1hsRUVYcHVSY3dEXHUwMDJCN1pmakNkUHJHZlBYczNxaGZ2cXBWcFZOcG9XIiwicHViIjoiTUNvd0JRWURLMlZ3QXlFQXc0eHZjbUhVMUpOZUk5b3R3V1ZNekVJSjI5MGl5Y29RN1J4SXYxVElDRDAifQ";
        private const string _encodedTrustedIdentity = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6ImIxOTIyNjFiLWE4MTMtNDAwOC05YjRjLTVlNjk4MzNiZTU3MCIsInN1YiI6IjE3ZTZiNzg3LWQ2ZWYtNDE1OC1hYjM5LThiNWZjMjg3NTczZSIsImlzcyI6IjE3ZTZiNzg3LWQ2ZWYtNDE1OC1hYjM5LThiNWZjMjg3NTczZSIsImlhdCI6MTYyMzI3NDI1OCwiZXhwIjoxOTM4NjM0MjU4LCJpa3kiOiJNQ293QlFZREsyVndBeUVBdzR4dmNtSFUxSk5lSTlvdHdXVk16RUlKMjkwaXljb1E3UnhJdjFUSUNEMCIsImNhcCI6WyJnZW5lcmljIiwiaXNzdWUiLCJzZWxmIl19.pD7MVB4cGkOs3/ebKPPQcYa2mrpzriA3txI9w4F/XGZY9fBt0AaXQdRrkgpJQNL864REdEpXQkdbi1OSd1Q1Dw";
        private static KeyBox _trustedKeypair;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "DiME:aW8uZGltZWZvcm1hdC5reWI.eyJ2ZXIiOjEsImtpZCI6IjZjYzIyMjFhLTViOGYtNDc3Mi05YjI5LTI2ZjI1ZWE3YjI5YiIsImt0eSI6MSwia2V5IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJTnMwOEFZQndQQTRlN3JFWmNTZUNCd0t1SlhqR3Ftd1MvbkN5OFJnUmh5YiIsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFFWXBtaWVsTnduRHpkY0lqaUttRk9VMXVmZ2dMcVk5Z1U0U3doTnlzMzFJIn0";
        private const string _encodedIntermediateIdentity = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6IjA5MzQ1MWRiLTI2ZjItNDBjNS04ZmQ5LTY3M2U1ZjUwYTY5NCIsInN1YiI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlzcyI6IjE3ZTZiNzg3LWQ2ZWYtNDE1OC1hYjM5LThiNWZjMjg3NTczZSIsImlhdCI6MTYyMzI3NDQ4NywiZXhwIjoxNzgwOTU0NDg3LCJpa3kiOiJNQ293QlFZREsyVndBeUVBRVlwbWllbE53bkR6ZGNJamlLbUZPVTF1ZmdnTHFZOWdVNFN3aE55czMxSSIsImNhcCI6WyJnZW5lcmljIiwiaXNzdWUiXX0.sJIevYb72mjiE7W8vOKv0ni90e3IXawYl8fnYXl34Io4eQMmgNCbGT7Sv1qHrPar21gQddeUAGYhUs3XplR2Ag";
        private static KeyBox _intermediateKeypair;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeypair = "DiME:aW8uZGltZWZvcm1hdC5reWI.eyJ2ZXIiOjEsImtpZCI6IjQyMjEwMjlhLTc2ZjUtNGVmZC1iZTI3LWFmZWRlOTkxMjI4MSIsImt0eSI6MSwia2V5IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJRklaQ2FFRFZ2ckZ3azNMbHhldDV6QXNpRVhpSmNocjhiclA0WnJvRFRYOCIsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFwODIwXHUwMDJCeGVRaFlkUWUzekxKNE5sU01HeEo4WEs5L044dVpkMmc4dkFKVmcifQ";
        private const string _encodedSenderIdentity = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6Ijg0NjE0YjU0LWE2NGUtNGU2Zi04ODhmLTUwMzliOWZhNjRmYyIsInN1YiI6ImFkZDIwZmY0LTMyMmItNGQ1NC1iYzc0LWJjYjVjN2VhMDhkNiIsImlzcyI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlhdCI6MTYyMzI3NjI4OSwiZXhwIjoxNjU0ODEyMjg5LCJpa3kiOiJNQ293QlFZREsyVndBeUVBcDgyMFx1MDAyQnhlUWhZZFFlM3pMSjRObFNNR3hKOFhLOS9OOHVaZDJnOHZBSlZnIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoyWlhJaU9qRXNJblZwWkNJNklqQTVNelExTVdSaUxUSTJaakl0TkRCak5TMDRabVE1TFRZM00yVTFaalV3WVRZNU5DSXNJbk4xWWlJNkltTm1PV1JsTWpNeExUZGtZbVF0TkRBME9TMDRNREZoTFRCaVpEVXpNakUwWlRNek5TSXNJbWx6Y3lJNklqRTNaVFppTnpnM0xXUTJaV1l0TkRFMU9DMWhZak01TFRoaU5XWmpNamczTlRjelpTSXNJbWxoZENJNk1UWXlNekkzTkRRNE55d2laWGh3SWpveE56Z3dPVFUwTkRnM0xDSnBhM2tpT2lKTlEyOTNRbEZaUkVzeVZuZEJlVVZCUlZsd2JXbGxiRTUzYmtSNlpHTkphbWxMYlVaUFZURjFabWRuVEhGWk9XZFZORk4zYUU1NWN6TXhTU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAuc0pJZXZZYjcybWppRTdXOHZPS3Ywbmk5MGUzSVhhd1lsOGZuWVhsMzRJbzRlUU1tZ05DYkdUN1N2MXFIclBhcjIxZ1FkZGVVQUdZaFVzM1hwbFIyQWc.revzfv1JwJG3/m/IKY3bVm5VFxMB/epmfe/0gqxhXD0rbUdvj+j22QLhuyhKqRe1XScOypk+TiwZ2RW0BKEUAA";
        private static KeyBox _senderKeypair;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeypair = "aW8uZGltZWZvcm1hdC5reWI.eyJ2ZXIiOjEsImtpZCI6IjNjMjg2ZGM2LWQ2MWEtNDg4NC05MTgxLTkwMmQ2M2QzYjk3NCIsImt0eSI6MSwia2V5IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJSTcvWUJ0eFd6RlFUM2I2RUFpTUF5dWhJanJLaWZRWkJ3RnNadEg2aTVhcyIsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFONWZ3aGxEOXFtbmEySVlma0RHc0M2WUJDTEpxMzRcdTAwMkJVQ2F6Y1x1MDAyQmlMTEVaQSJ9";
        private const string _encodedReceiverIdentity = "aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6IjMxZmFhNzc5LTM1OTQtNDVmYi1hYTdhLTVhMWE1ZjBhODY1MSIsInN1YiI6IjJmNGNiZjY2LTllZGItNGRlMS1iN2E4LTI0NGY2ZTBjN2YyZiIsImlzcyI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlhdCI6MTYyMzI3NjM1MCwiZXhwIjoxNjU0ODEyMzUwLCJpa3kiOiJNQ293QlFZREsyVndBeUVBTjVmd2hsRDlxbW5hMklZZmtER3NDNllCQ0xKcTM0XHUwMDJCVUNhemNcdTAwMkJpTExFWkEiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoyWlhJaU9qRXNJblZwWkNJNklqQTVNelExTVdSaUxUSTJaakl0TkRCak5TMDRabVE1TFRZM00yVTFaalV3WVRZNU5DSXNJbk4xWWlJNkltTm1PV1JsTWpNeExUZGtZbVF0TkRBME9TMDRNREZoTFRCaVpEVXpNakUwWlRNek5TSXNJbWx6Y3lJNklqRTNaVFppTnpnM0xXUTJaV1l0TkRFMU9DMWhZak01TFRoaU5XWmpNamczTlRjelpTSXNJbWxoZENJNk1UWXlNekkzTkRRNE55d2laWGh3SWpveE56Z3dPVFUwTkRnM0xDSnBhM2tpT2lKTlEyOTNRbEZaUkVzeVZuZEJlVVZCUlZsd2JXbGxiRTUzYmtSNlpHTkphbWxMYlVaUFZURjFabWRuVEhGWk9XZFZORk4zYUU1NWN6TXhTU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAuc0pJZXZZYjcybWppRTdXOHZPS3Ywbmk5MGUzSVhhd1lsOGZuWVhsMzRJbzRlUU1tZ05DYkdUN1N2MXFIclBhcjIxZ1FkZGVVQUdZaFVzM1hwbFIyQWc.L8fJcAQr4Y8Bssj1Y0dM74vO6BrPZ7wd6reJtQsC14qYST8N6dJoT+D8oi8He1rYiXGeLtRuJxskCwiAJcwZAw";
        private static KeyBox _receiverKeypair;
        private static Identity _receiverIdentity;
        #endregion
    }

}
