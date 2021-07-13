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
        private const string _encodedTrustedKeybox = "aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiJmNTBmMmUzZi01ZDllLTQwMDgtYWEyNC03ZTM1NDQ1MGE1OWQiLCJpYXQiOjE2MjU4NjE4MzcsImtleSI6IkNZSGpXb1BvM1lUZHh2dE5reVRQeFRjVnNCbnkzbVBGOTdKeHN2SnZINHFxcmRjeTFQSnlXTSIsInB1YiI6IkNZSHQ4MXN5a25kbjNxOVZTQkp3eVJmWEZMbmtyYkQ2OW9xNW1OaVI3MjFSbm1vbkNWcWRINiJ9";
        private const string _encodedTrustedIdentity = "aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiJmZTE2NTFjNC1jNjhlLTRlNzAtYjk0Mi1iYmE0OTg3ZDNlZTUiLCJzdWIiOiI3YzI1OGVjZC0zODNlLTQ1NDUtOGMyZi1lY2FmNmE4ZmYyYTAiLCJpc3MiOiI3YzI1OGVjZC0zODNlLTQ1NDUtOGMyZi1lY2FmNmE4ZmYyYTAiLCJpYXQiOjE2MjU4NjE4MzcsImV4cCI6MTk0MTIyMTgzNywiaWt5IjoiQ1lIdDgxc3lrbmRuM3E5VlNCSnd5UmZYRkxua3JiRDY5b3E1bU5pUjcyMVJubW9uQ1ZxZEg2IiwiY2FwIjpbImdlbmVyaWMiLCJpc3N1ZSIsInNlbGYiXX0.tN4+16kX19DFlvdXA+mbnNCsSX9hgpXwkd8h09T6flEyXD3kXHu1Gy58+WONbzqwQ3WIP8Hb7sjo+0onDqdFAg";
        private static KeyBox _trustedKeybox;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKeypair = "aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiIyMGVlNjIwMy1mNDBkLTRmNDQtOTg0My0wMzJjMDBjOTMxNWUiLCJpYXQiOjE2MjU4NjIzMjQsImtleSI6IkNZSGpXbnhCOTROWHFTVnFBRlVIQVpBY0FXRFVkUlE5eVYyYzJ0WnN5WW5qOTRIRVNzanRGWCIsInB1YiI6IkNZSHQ3M0JjVk5zck5ySFVIQ0t6WHNzNTFXY3d5eDltYUczSHo0cVU3WlJic1p2SnNSQnBDYiJ9";
        private const string _encodedIntermediateIdentity = "aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiJjZDY2N2E2OS00NGIxLTQyNGYtYjQwOC01MGYyNzg4MGNjOGIiLCJzdWIiOiI0NWEzOGE2Mi1lODg4LTQ2Y2ItYmRiYy1hOWE2YWJhNmFjY2YiLCJpc3MiOiI3YzI1OGVjZC0zODNlLTQ1NDUtOGMyZi1lY2FmNmE4ZmYyYTAiLCJpYXQiOjE2MjU4NjIzNDQsImV4cCI6MTc4MzU0MjM0NCwiaWt5IjoiQ1lIdDczQmNWTnNyTnJIVUhDS3pYc3M1MVdjd3l4OW1hRzNIejRxVTdaUmJzWnZKc1JCcENiIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSIsImlzc3VlIl19.+BXii/3tX8RvM0hUeFTyqKg8CCFJVKSRzd/2jbaJJm0HBUiHgzfW6HBzoBEVndl8gEHuwkbT/G1PJ6YM/+0yCQ";
        private static KeyBox _intermediateKeybox;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- SENDER IDENTITY --
        private const string _encodedSenderKeybox = "aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiJmMzRhYWQ1MC1iM2IyLTRmYzAtYTRkMC0zOTI3MGVjYjgxNjMiLCJpYXQiOjE2MjU4NjI0NTQsImtleSI6IkNZSGpYTkM5UkZYSjFabzdFZWZBR0JRYTdYbXF0QmNFWWM0RHhTR1BWQlExY3o1bnZKRkg4UiIsInB1YiI6IkNZSHQ2YkY2ZjFEbmNpNnhURWF1aWp5UEJzOERWN2hoalE3OEg5M0JBakVOamd2RmhoN0hCbiJ9";
        private const string _encodedSenderIdentity = "aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiI0YTNlMGI2Yi1iZmZiLTRmZWItYWI1NS00M2VlMzMzOGIzYmYiLCJzdWIiOiI1MzY5YTEwNS1jNjkxLTQ0Y2YtOTczZS0xYWU1MjQxNjlkMTgiLCJpc3MiOiI0NWEzOGE2Mi1lODg4LTQ2Y2ItYmRiYy1hOWE2YWJhNmFjY2YiLCJpYXQiOjE2MjU4NjI0NjMsImV4cCI6MTY1NzM5ODQ2MywiaWt5IjoiQ1lIdDZiRjZmMURuY2k2eFRFYXVpanlQQnM4RFY3aGhqUTc4SDkzQkFqRU5qZ3ZGaGg3SEJuIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoxYVdRaU9pSmpaRFkyTjJFMk9TMDBOR0l4TFRReU5HWXRZalF3T0MwMU1HWXlOemc0TUdOak9HSWlMQ0p6ZFdJaU9pSTBOV0V6T0dFMk1pMWxPRGc0TFRRMlkySXRZbVJpWXkxaE9XRTJZV0poTm1GalkyWWlMQ0pwYzNNaU9pSTNZekkxT0dWalpDMHpPRE5sTFRRMU5EVXRPR015WmkxbFkyRm1ObUU0Wm1ZeVlUQWlMQ0pwWVhRaU9qRTJNalU0TmpJek5EUXNJbVY0Y0NJNk1UYzRNelUwTWpNME5Dd2lhV3Q1SWpvaVExbElkRGN6UW1OV1RuTnlUbkpJVlVoRFMzcFljM00xTVZkamQzbDRPVzFoUnpOSWVqUnhWVGRhVW1KelduWktjMUpDY0VOaUlpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBaR1Z1ZEdsbWVTSXNJbWx6YzNWbElsMTkuK0JYaWkvM3RYOFJ2TTBoVWVGVHlxS2c4Q0NGSlZLU1J6ZC8yamJhSkptMEhCVWlIZ3pmVzZIQnpvQkVWbmRsOGdFSHV3a2JUL0cxUEo2WU0vKzB5Q1E.mYvXRzAzZw1Lnh1taFtf1MWMidlMN8Tm56niwIZhdbsz6vEpU1szS8YVnXd/AuwokkJKmxr4UMbDBAoZVj+NDg";
        private static KeyBox _senderKeybox;
        private static Identity _senderIdentity;
        #endregion

        #region -- RECEIVER IDENTITY --
        private const string _encodedReceiverKeybox = "aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiIwZmYxYzMzMS0xYzNiLTQ1NjMtOTllMC04ZmUyMmJkODAyMDciLCJpYXQiOjE2MjU4NjI1MDQsImtleSI6IkNZSGpYOWsyWGREVUpHOGdaeGRnYTdMeExHTGdRZEtSQU50U0p0M1B5N2c4MW01dzM0M29EQiIsInB1YiI6IkNZSHQ3NG95eXZ4dld2dEZKdjNwaFZ3UVR3a042UzZwV2JUQm9Fb0hncWdjQjJrblJaa3ZERiJ9";
        private const string _encodedReceiverIdentity = "aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiIzZWFkMDJiNi1kNTRhLTQ4ODQtYThlYS0yZDVjMWQwZjFiYzAiLCJzdWIiOiJkNDY5NDU5YS1jMjdkLTQ3MzYtOWIwYS1lZDkzMTczZDliZWEiLCJpc3MiOiI0NWEzOGE2Mi1lODg4LTQ2Y2ItYmRiYy1hOWE2YWJhNmFjY2YiLCJpYXQiOjE2MjU4NjI1MDQsImV4cCI6MTY1NzM5ODUwNCwiaWt5IjoiQ1lIdDc0b3l5dnh2V3Z0Rkp2M3BoVndRVHdrTjZTNnBXYlRCb0VvSGdxZ2NCMmtuUlprdkRGIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoxYVdRaU9pSmpaRFkyTjJFMk9TMDBOR0l4TFRReU5HWXRZalF3T0MwMU1HWXlOemc0TUdOak9HSWlMQ0p6ZFdJaU9pSTBOV0V6T0dFMk1pMWxPRGc0TFRRMlkySXRZbVJpWXkxaE9XRTJZV0poTm1GalkyWWlMQ0pwYzNNaU9pSTNZekkxT0dWalpDMHpPRE5sTFRRMU5EVXRPR015WmkxbFkyRm1ObUU0Wm1ZeVlUQWlMQ0pwWVhRaU9qRTJNalU0TmpJek5EUXNJbVY0Y0NJNk1UYzRNelUwTWpNME5Dd2lhV3Q1SWpvaVExbElkRGN6UW1OV1RuTnlUbkpJVlVoRFMzcFljM00xTVZkamQzbDRPVzFoUnpOSWVqUnhWVGRhVW1KelduWktjMUpDY0VOaUlpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBaR1Z1ZEdsbWVTSXNJbWx6YzNWbElsMTkuK0JYaWkvM3RYOFJ2TTBoVWVGVHlxS2c4Q0NGSlZLU1J6ZC8yamJhSkptMEhCVWlIZ3pmVzZIQnpvQkVWbmRsOGdFSHV3a2JUL0cxUEo2WU0vKzB5Q1E.Odwl3ot2NZw+5YqlrjTwXMTULGHq2vEpIco6p/KdCm+RspGHUY0gVI6CAnvXkb3oQBvZcTTBXYirGDUOHooZBQ";
        private static KeyBox _receiverKeybox;
        private static Identity _receiverIdentity;
        #endregion
    }

}
