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
        public static KeyBox TrustedKeybox { get { if (Commons._trustedKeybox == null) { Commons._trustedKeybox = Item.Import<KeyBox>(Commons._encodedTrustedKeybox); } return Commons._trustedKeybox; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Item.Import<Identity>(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static KeyBox IntermediateKeybox { get { if (Commons._intermediateKeybox == null) { Commons._intermediateKeybox = Item.Import<KeyBox>(Commons._encodedIntermediateKeypair); } return Commons._intermediateKeybox; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Item.Import<Identity>(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static KeyBox SenderKeybox { get { if (Commons._senderKeybox == null) { Commons._senderKeybox = Item.Import<KeyBox>(Commons._encodedSenderKeybox); } return Commons._senderKeybox; } }
        public static Identity SenderIdentity { get { if (Commons._senderIdentity == null) { Commons._senderIdentity = Item.Import<Identity>(Commons._encodedSenderIdentity); } return Commons._senderIdentity; } }
        public static KeyBox ReceiverKeybox { get { if (Commons._receiverKeybox == null) { Commons._receiverKeybox = Item.Import<KeyBox>(Commons._encodedReceiverKeybox); } return Commons._receiverKeybox; } }
        public static Identity ReceiverIdentity { get { if (Commons._receiverIdentity == null) { Commons._receiverIdentity = Item.Import<Identity>(Commons._encodedReceiverIdentity); } return Commons._receiverIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKeybox = "Di:a2V5.eyJraWQiOiI3ZDA2ZjFhOC03YjdmLTRlNGItYjg3Yy0xMjE5NjQxNTE2ZTUiLCJpYXQiOjE2MjYyMTM2OTUsImtleSI6IkNZSGpZUGVTV2g4U3lmY0hveXVxZnR4TndzeEdUcTNSQVVQWHZhamRYMkJNRDF1UDhkOUxvUiIsInB1YiI6IkNZSHQ2UDZmNTZoSGRxaE1GUW1UMlYzYTlOS3hKUkxhOEFWS2hEc0hRZFhYeTNGVEtwUzdYTSJ9";
        private const string _encodedTrustedIdentity = "Di:aWQ.eyJ1aWQiOiI2YThlMWFiYy0wYjQzLTQ1MTUtOGFlMi00YTM1ZTlhMTdiZjgiLCJzdWIiOiI3NTI5ZmI0ZS1jZjM4LTRhNzAtYjcwMS00OWU5YmM5ZTg5MjEiLCJpc3MiOiI3NTI5ZmI0ZS1jZjM4LTRhNzAtYjcwMS00OWU5YmM5ZTg5MjEiLCJpYXQiOjE2MjYyMTM2OTUsImV4cCI6MTk0MTU3MzY5NSwicHViIjoiQ1lIdDZQNmY1NmhIZHFoTUZRbVQyVjNhOU5LeEpSTGE4QVZLaERzSFFkWFh5M0ZUS3BTN1hNIiwiY2FwIjpbImdlbmVyaWMiLCJpc3N1ZSIsInNlbGYiXX0.ARxE0YAIkTm7cyeZgJx4P0Orc6xLfUpt2k175pPdUhe9XZHMWB/8U/H347+83MH2NR0JIxxrwHxJ2F5HTiUioA8";
        private static KeyBox _trustedKeybox;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "Di:a2V5.eyJraWQiOiJhYThkNzE3YS1iYWUyLTRmZDgtODI1My1iM2I0NDJkMGFlZWUiLCJpYXQiOjE2MjYyMTM3NzQsImtleSI6IkNZSGpYMkRBanFFaWtudHFuaFdNcXJySHRaS0ZEOVROcFZISDE1cFF6Vm51R3RwcEpjUWY5UyIsInB1YiI6IkNZSHQ3MzZOaHVEVnl3SmM3Vk5yeU5CTm4zWHZuVjk2c1RKZ2hxRlZYZGJLWGlRam15cFdYeCJ9";
        private const string _encodedIntermediateIdentity = "Di:aWQ.eyJ1aWQiOiJmNDE1ZGM0MC1jMTc2LTRjY2YtODhhNy1hMmMxNTI2NzhlNDAiLCJzdWIiOiIwMzdkOTEzNS1mNmVhLTQ1ZTEtOWFhNi1hNmQ0NzE3NmUwMGQiLCJpc3MiOiI3NTI5ZmI0ZS1jZjM4LTRhNzAtYjcwMS00OWU5YmM5ZTg5MjEiLCJpYXQiOjE2MjYyMTM3NzQsImV4cCI6MTc4Mzg5Mzc3NCwicHViIjoiQ1lIdDczNk5odURWeXdKYzdWTnJ5TkJObjNYdm5WOTZzVEpnaHFGVlhkYktYaVFqbXlwV1h4IiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSIsImlzc3VlIl19.AcSvOxWLuozJxsQjG1DC3SK8F6qgGeNAepkYCFyTj+qAfyG1biQIJ+xFEDPIwrygtvNT1WFwnQYOCwd0GctIiQw";
        private static KeyBox _intermediateKeybox;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeybox = "Di:a2V5.eyJraWQiOiIyZDQ2YzYzMC1mNTQ4LTRmNzUtODYwZC01ZTE3NzNkODU0OWQiLCJpYXQiOjE2MjYyMTM4NDUsImtleSI6IkNZSGpYazU1aUNWek00MWdDUjlOcmhLcXhkalNQcDJHMUUxU0xjOGNBbk5EY0I0UnZQWDlzWCIsInB1YiI6IkNZSHQ3dFNUcTU5RnlwdEpVTktNVDhuUHRlcnhadG44M2dyUlNyZGdyNk5zVGs3cWgzQUdQYyJ9";
        private const string _encodedSenderIdentity = "Di:aWQ.eyJ1aWQiOiI0ZGU3MDNlYS0zZjM2LTQzMTctYTVhYi05OWRkZTVlMTllYTgiLCJzdWIiOiIwMDIxZTIyMC1kYTRhLTQwMjMtYWYxZC02ZWZiMDVmY2ZlZWYiLCJpc3MiOiIwMzdkOTEzNS1mNmVhLTQ1ZTEtOWFhNi1hNmQ0NzE3NmUwMGQiLCJpYXQiOjE2MjYyMTM4NDUsImV4cCI6MTY1Nzc0OTg0NSwicHViIjoiQ1lIdDd0U1RxNTlGeXB0SlVOS01UOG5QdGVyeFp0bjgzZ3JSU3JkZ3I2TnNUazdxaDNBR1BjIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKbU5ERTFaR00wTUMxak1UYzJMVFJqWTJZdE9EaGhOeTFoTW1NeE5USTJOemhsTkRBaUxDSnpkV0lpT2lJd016ZGtPVEV6TlMxbU5tVmhMVFExWlRFdE9XRmhOaTFoTm1RME56RTNObVV3TUdRaUxDSnBjM01pT2lJM05USTVabUkwWlMxalpqTTRMVFJoTnpBdFlqY3dNUzAwT1dVNVltTTVaVGc1TWpFaUxDSnBZWFFpT2pFMk1qWXlNVE0zTnpRc0ltVjRjQ0k2TVRjNE16ZzVNemMzTkN3aWNIVmlJam9pUTFsSWREY3pOazVvZFVSV2VYZEtZemRXVG5KNVRrSk9iak5ZZG01V09UWnpWRXBuYUhGR1ZsaGtZa3RZYVZGcWJYbHdWMWg0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BY1N2T3hXTHVvekp4c1FqRzFEQzNTSzhGNnFnR2VOQWVwa1lDRnlUaitxQWZ5RzFiaVFJSit4RkVEUEl3cnlndHZOVDFXRnduUVlPQ3dkMEdjdElpUXc.AZrIMEZAvKFz6u699TfpQwpnJnyI594i9MmTPHH9YV6A0W2wFO/fwff9yoIO9t7eSycnTVe2AaVpo7jCG2XtMgE";
        private static KeyBox _senderKeybox;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeybox = "Di:a2V5.eyJraWQiOiI5N2I5YmYxZC02ZTZhLTRkNGYtYWZkOC05MDg2N2MwNGVhMDkiLCJpYXQiOjE2MjYyMTM4NzgsImtleSI6IkNZSGpXeFBObnhobXVRd2ZOVEJVZTNHWTNSV0VMRFBEdFJaNHVYQWlGekNmNmgxc29BTlk5ZiIsInB1YiI6IkNZSHQ4Nm5iZXU0ZnZveDdyd3pkTldjZmpibk1KN3M1c3dLa0pOQUgzckxVZ2I3MXZ3bktoaSJ9";
        private const string _encodedReceiverIdentity = "Di:aWQ.eyJ1aWQiOiI0Yzc4NGMwNy03NmE0LTQxNDEtOGY3Zi00MzlkNjhkNDgzNmQiLCJzdWIiOiJmMTRmNzNhZi02N2Y1LTRiYjgtODMxMi1lNDg4OGU4ZjllYzciLCJpc3MiOiIwMzdkOTEzNS1mNmVhLTQ1ZTEtOWFhNi1hNmQ0NzE3NmUwMGQiLCJpYXQiOjE2MjYyMTM4NzgsImV4cCI6MTY1Nzc0OTg3OCwicHViIjoiQ1lIdDg2bmJldTRmdm94N3J3emROV2NmamJuTUo3czVzd0trSk5BSDNyTFVnYjcxdnduS2hpIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKbU5ERTFaR00wTUMxak1UYzJMVFJqWTJZdE9EaGhOeTFoTW1NeE5USTJOemhsTkRBaUxDSnpkV0lpT2lJd016ZGtPVEV6TlMxbU5tVmhMVFExWlRFdE9XRmhOaTFoTm1RME56RTNObVV3TUdRaUxDSnBjM01pT2lJM05USTVabUkwWlMxalpqTTRMVFJoTnpBdFlqY3dNUzAwT1dVNVltTTVaVGc1TWpFaUxDSnBZWFFpT2pFMk1qWXlNVE0zTnpRc0ltVjRjQ0k2TVRjNE16ZzVNemMzTkN3aWNIVmlJam9pUTFsSWREY3pOazVvZFVSV2VYZEtZemRXVG5KNVRrSk9iak5ZZG01V09UWnpWRXBuYUhGR1ZsaGtZa3RZYVZGcWJYbHdWMWg0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BY1N2T3hXTHVvekp4c1FqRzFEQzNTSzhGNnFnR2VOQWVwa1lDRnlUaitxQWZ5RzFiaVFJSit4RkVEUEl3cnlndHZOVDFXRnduUVlPQ3dkMEdjdElpUXc.AZXzc94/LuBBqqwMSZ/WUR26z0MRbBCcW/akiCc7o6mpXjLdK4bEwXMqEHk9Sctb3x0e4sQTUW/4H+3fuP1NNgs";
        private static KeyBox _receiverKeybox;
        private static Identity _receiverIdentity;
        #endregion
    }

}
