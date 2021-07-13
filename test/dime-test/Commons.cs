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
        public static KeyBox TrustedKeybox { get { if (Commons._trustedKeybox == null) { Commons._trustedKeybox = KeyBox.FromString(Commons._encodedTrustedKeybox); } return Commons._trustedKeybox; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Identity.FromString(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static KeyBox IntermediateKeybox { get { if (Commons._intermediateKeybox == null) { Commons._intermediateKeybox = KeyBox.FromString(Commons._encodedIntermediateKeypair); } return Commons._intermediateKeybox; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Identity.FromString(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static KeyBox SenderKeybox { get { if (Commons._senderKeybox == null) { Commons._senderKeybox = KeyBox.FromString(Commons._encodedSenderKeybox); } return Commons._senderKeybox; } }
        public static Identity SenderIdentity { get { if (Commons._senderIdentity == null) { Commons._senderIdentity = Identity.FromString(Commons._encodedSenderIdentity); } return Commons._senderIdentity; } }
        public static KeyBox ReceiverKeybox { get { if (Commons._receiverKeybox == null) { Commons._receiverKeybox = KeyBox.FromString(Commons._encodedReceiverKeybox); } return Commons._receiverKeybox; } }
        public static Identity ReceiverIdentity { get { if (Commons._receiverIdentity == null) { Commons._receiverIdentity = Identity.FromString(Commons._encodedReceiverIdentity); } return Commons._receiverIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKeybox = "a2V5.eyJraWQiOiJhOTFhMDhhNy0xMzE2LTQ5YzgtOGMxNi04NzFiMWQ4ZDlkNDciLCJpYXQiOjE2MjYyMDcyMDAsImtleSI6IkNZSGpZYmlDVlZ1anpLdkFmdGk5VjFtQ0pOZzdpemJkS1pEWkpYOFlpQXdQYzNrblZaZktxTSIsInB1YiI6IkNZSHQ2WWVYTW5vQk5vdUV2Y2JHWHNDZEpWYzhUc2puMnVyWTlVRHlCTXprVGJ1cXB6NTNmSCJ9";
        private const string _encodedTrustedIdentity = "aWQ.eyJ1aWQiOiIyNjgyZTA5MC04YWYzLTQzZTgtODZiOS0yYjM1MTk5ZDE4ZTAiLCJzdWIiOiJjNzhjMDg2ZC1hM2RkLTQ4ZTQtOGYxOC1hNTEzNjk0N2Y5MjAiLCJpc3MiOiJjNzhjMDg2ZC1hM2RkLTQ4ZTQtOGYxOC1hNTEzNjk0N2Y5MjAiLCJpYXQiOjE2MjYyMDcyMDAsImV4cCI6MTk0MTU2NzIwMCwiaWt5IjoiQ1lIdDZZZVhNbm9CTm91RXZjYkdYc0NkSlZjOFRzam4ydXJZOVVEeUJNemtUYnVxcHo1M2ZIIiwiY2FwIjpbImdlbmVyaWMiLCJpc3N1ZSIsInNlbGYiXX0.Hlojj33jfzCdjryFidLFPzku73R5BDU0JY4DQgrTz284bk0pJsh2UcZQQzHP+TI11nTKxpJyMErQeeRB+YJ/BQ";
        private static KeyBox _trustedKeybox;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "a2V5.eyJraWQiOiJjODg1Njc3YS00Yzc0LTQzNTUtODA2Ny02ZTQwNzI4ZjE3MzMiLCJpYXQiOjE2MjYyMDczMDYsImtleSI6IkNZSGpXdXEzUGV2S0RSNG9zREUyemhIcnVBRHRDSHFuamo4UTNRQzhwRDd2YlBITkVMZGFZYSIsInB1YiI6IkNZSHQ3NUdRamVXU2M2S2poNExjMVFGdnc1VHVTVldSYkp2aFBYR2c4VEJ5MnE5YTVzeTVHcyJ9";
        private const string _encodedIntermediateIdentity = "aWQ.eyJ1aWQiOiJhYzRkNzllYi05NDJkLTQ3ZGYtYmMyMi1mZTM2MmRjMGFjZDMiLCJzdWIiOiI3NTkwNTQ1MC1iZmE1LTQwMmMtYWZiZS0xZGY2YjBiY2YzNTMiLCJpc3MiOiJjNzhjMDg2ZC1hM2RkLTQ4ZTQtOGYxOC1hNTEzNjk0N2Y5MjAiLCJpYXQiOjE2MjYyMDczMDYsImV4cCI6MTc4Mzg4NzMwNiwiaWt5IjoiQ1lIdDc1R1FqZVdTYzZLamg0TGMxUUZ2dzVUdVNWV1JiSnZoUFhHZzhUQnkycTlhNXN5NUdzIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSIsImlzc3VlIl19.sQLVHBMrkdLZEXJJA/3hwviuukxdOqGp6mDzCzhBbtPhkXZLU57oHqCCcoVih7/4Tl6wGK86c5ZaovQBG5XvAg";
        private static KeyBox _intermediateKeybox;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeybox = "a2V5.eyJraWQiOiI5ODVkN2QyNS1jZTc4LTRmMzMtYWVhZi0yMDlkYTgwNzAzNzgiLCJpYXQiOjE2MjYyMDczODksImtleSI6IkNZSGpYS2lqcXpYVnV0U3drcVY0RkhIaUY2WjN2TVhzRVVQaTROZDVHdjVMUDdSd2JYcGlrNyIsInB1YiI6IkNZSHQ2UUZMNHhKaHJMOTJ2bjlOdUhyWGRoTmU3TDZubWJzVkFvRW50UGVaZnlpcHlZN2dUbSJ9";
        private const string _encodedSenderIdentity = "aWQ.eyJ1aWQiOiJkYjkxZWU5OS1hMDVlLTRlODgtODI0NC1jZjVhNTU5NDYyOWYiLCJzdWIiOiI3MDUwMjgzMy01MjE1LTRiZTMtYjc1ZS0zZTNmMDdkMjU2MjQiLCJpc3MiOiI3NTkwNTQ1MC1iZmE1LTQwMmMtYWZiZS0xZGY2YjBiY2YzNTMiLCJpYXQiOjE2MjYyMDczODksImV4cCI6MTY1Nzc0MzM4OSwiaWt5IjoiQ1lIdDZRRkw0eEpockw5MnZuOU51SHJYZGhOZTdMNm5tYnNWQW9FbnRQZVpmeWlweVk3Z1RtIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKaFl6UmtOemxsWWkwNU5ESmtMVFEzWkdZdFltTXlNaTFtWlRNMk1tUmpNR0ZqWkRNaUxDSnpkV0lpT2lJM05Ua3dOVFExTUMxaVptRTFMVFF3TW1NdFlXWmlaUzB4WkdZMllqQmlZMll6TlRNaUxDSnBjM01pT2lKak56aGpNRGcyWkMxaE0yUmtMVFE0WlRRdE9HWXhPQzFoTlRFek5qazBOMlk1TWpBaUxDSnBZWFFpT2pFMk1qWXlNRGN6TURZc0ltVjRjQ0k2TVRjNE16ZzROek13Tml3aWFXdDVJam9pUTFsSWREYzFSMUZxWlZkVFl6WkxhbWcwVEdNeFVVWjJkelZVZFZOV1YxSmlTblpvVUZoSFp6aFVRbmt5Y1RsaE5YTjVOVWR6SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5zUUxWSEJNcmtkTFpFWEpKQS8zaHd2aXV1a3hkT3FHcDZtRHpDemhCYnRQaGtYWkxVNTdvSHFDQ2NvVmloNy80VGw2d0dLODZjNVphb3ZRQkc1WHZBZw.fWZ+pdwoYpbmvzytYwi+iwM+CYSmyfX6VX44ocGsUKZ3JKMFDNnRdHJivt0Bwv1GFBnRRCfq9+GJvPYYbGPqCA";
        private static KeyBox _senderKeybox;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeybox = "a2V5.eyJraWQiOiIwNTg2MDJjMS1kNDM4LTQxNjAtODU4Mi1jM2E3NWRiNjFiMDUiLCJpYXQiOjE2MjYyMDc0MjcsImtleSI6IkNZSGpXamdlQTRvcTJxOEhyQzY0Wks5NG12R2Z6NjNvWkdtTUQ0WEJHQlYxZjVhNktSSEhrYyIsInB1YiI6IkNZSHQ2bXROdkMzNVNnS1FESkdlV1NpQ2NDSFFYUUg1SDFROTkxem9VVTFBeHJQeTZLYkVtaSJ9";
        private const string _encodedReceiverIdentity = "aWQ.eyJ1aWQiOiI4YWM5YTBlNS1lMzE5LTRlYTEtYWRjYy1jNmZhNTk1NjBlZWYiLCJzdWIiOiJhZjM4NGQwMC05YmM1LTQwMTctODc3YS01Mzc5ZjY1M2U1ZTUiLCJpc3MiOiI3NTkwNTQ1MC1iZmE1LTQwMmMtYWZiZS0xZGY2YjBiY2YzNTMiLCJpYXQiOjE2MjYyMDc0MjcsImV4cCI6MTY1Nzc0MzQyNywiaWt5IjoiQ1lIdDZtdE52QzM1U2dLUURKR2VXU2lDY0NIUVhRSDVIMVE5OTF6b1VVMUF4clB5NktiRW1pIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKaFl6UmtOemxsWWkwNU5ESmtMVFEzWkdZdFltTXlNaTFtWlRNMk1tUmpNR0ZqWkRNaUxDSnpkV0lpT2lJM05Ua3dOVFExTUMxaVptRTFMVFF3TW1NdFlXWmlaUzB4WkdZMllqQmlZMll6TlRNaUxDSnBjM01pT2lKak56aGpNRGcyWkMxaE0yUmtMVFE0WlRRdE9HWXhPQzFoTlRFek5qazBOMlk1TWpBaUxDSnBZWFFpT2pFMk1qWXlNRGN6TURZc0ltVjRjQ0k2TVRjNE16ZzROek13Tml3aWFXdDVJam9pUTFsSWREYzFSMUZxWlZkVFl6WkxhbWcwVEdNeFVVWjJkelZVZFZOV1YxSmlTblpvVUZoSFp6aFVRbmt5Y1RsaE5YTjVOVWR6SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5zUUxWSEJNcmtkTFpFWEpKQS8zaHd2aXV1a3hkT3FHcDZtRHpDemhCYnRQaGtYWkxVNTdvSHFDQ2NvVmloNy80VGw2d0dLODZjNVphb3ZRQkc1WHZBZw.DDjeJGZJ1jr6ckoryNol48p9yuEI2J0yfB9uPCUBuldVT/J40GehiHWQq80kPVbkdTdFblegAEWHKKmQF1LaDw";
        private static KeyBox _receiverKeybox;
        private static Identity _receiverIdentity;
        #endregion
    }

}
