//
//  Commons.cs
//  Di:ME - Digital Identity Message Envelope
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
        public static string SYSTEM_NAME = "dime";
        public static Key TrustedKey { get { if (Commons._trustedKey == null) { Commons._trustedKey = Item.Import<Key>(Commons._encodedTrustedKey); } return Commons._trustedKey; } }
        public static Identity TrustedIdentity { get { if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Item.Import<Identity>(Commons._encodedTrustedIdentity); } return Commons._trustedIdentity; } }
        public static Key IntermediateKey { get { if (Commons._intermediateKey == null) { Commons._intermediateKey = Item.Import<Key>(Commons._encodedIntermediateKey); } return Commons._intermediateKey; } }
        public static Identity IntermediateIdentity { get { if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Item.Import<Identity>(Commons._encodedIntermediateIdentity); } return Commons._intermediateIdentity; } }
        public static Key IssuerKey { get { if (Commons._issuerKey == null) { Commons._issuerKey = Item.Import<Key>(Commons._encodedIssuerKey); } return Commons._issuerKey; } }
        public static Identity IssuerIdentity { get { if (Commons._issuerIdentity == null) { Commons._issuerIdentity = Item.Import<Identity>(Commons._encodedIssuerIdentity); } return Commons._issuerIdentity; } }
        public static Key AudienceKey { get { if (Commons._audienceKey == null) { Commons._audienceKey = Item.Import<Key>(Commons._encodedAudienceKey); } return Commons._audienceKey; } }
        public static Identity AudienceIdentity { get { if (Commons._audienceIdentity == null) { Commons._audienceIdentity = Item.Import<Identity>(Commons._encodedAudienceIdentity); } return Commons._audienceIdentity; } }
        #endregion

        #region -- TRUSTED IDENTITY --
        private const string _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiI3OWQzNjIzMS02ZjJmLTRhN2ItOWJkMS1jOWZhOGI4YTJmODQiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjU3OjE5Ljg5NTE4MVoiLCJrZXkiOiIyVERYZDlXVVBGRDhzcU1CRnZhenY4dTNubTVSbWpWd1FVZmdLc3d2ZTNna2RaemdUV1VzQk5qYjMiLCJwdWIiOiIyVERYZG9OdzkzcUFqV0dtVkc5WTEyMkdjdER5MXZWU1ExWHFhZWV5dWRDMVFmWEJYYTNVNlhpclcifQ";
        private const string _encodedTrustedIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiYTBkNzlhNzYtMzdmNy00OGM4LWI3NzAtYTNiZWNhZmMzZTFkIiwic3ViIjoiYTNkYWZhYzYtYjEwOS00OWQyLWFhZGEtNGZkMDE0YjVlNTZmIiwiaXNzIjoiYTNkYWZhYzYtYjEwOS00OWQyLWFhZGEtNGZkMDE0YjVlNTZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMDo1NzoxOS45NTE3NjhaIiwiZXhwIjoiMjAzMS0xMS0yOVQyMDo1NzoxOS45NTE3NjhaIiwicHViIjoiMlREWGRvTnc5M3FBaldHbVZHOVkxMjJHY3REeTF2VlNRMVhxYWVleXVkQzFRZlhCWGEzVTZYaXJXIiwiY2FwIjpbImdlbmVyaWMiLCJpc3N1ZSIsInNlbGYiXX0.b8qhwxvjlV6FZuLYSeWXoTgVuI/tAht9DAx31UNDAJGz4J+7ZyE/EhqXFNkDPjv9hIknReS1SGdmt8dXqo6ZDQ";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiJkMmE4YTZlMy1kMGE4LTRiODYtYjEzNC1lN2QxM2YxMWVlM2QiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjU4OjAwLjAxODA2MloiLCJrZXkiOiIyVERYZDlXVHpHaFJuSm9XdTVmdWZHMnRMRks4b01vMjNGZjJSdXdTcGlUOW5RbU0xeFJCRVE4WlYiLCJwdWIiOiIyVERYZG9OdkpLVjZIOXllRzNjMjdrTjlBTFB0cDk2dUtqUURKUmdUQm9aZ3ZRU1lhRG9rU280cFcifQ";
        private const string _encodedIntermediateIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMjY5YTQzMDItMmZmZi00N2JlLWI1ZmYtNDFkMWI1MmM0NTgyIiwic3ViIjoiNTk4NjZjYWQtMTU1MS00NGM5LWJiNjMtMDAyNmU3ODJjMGZmIiwiaXNzIjoiYTNkYWZhYzYtYjEwOS00OWQyLWFhZGEtNGZkMDE0YjVlNTZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMDo1ODowMC4wNTY2MzJaIiwiZXhwIjoiMjAyNi0xMS0zMFQyMDo1ODowMC4wNTY2MzJaIiwicHViIjoiMlREWGRvTnZKS1Y2SDl5ZUczYzI3a045QUxQdHA5NnVLalFESlJnVEJvWmd2UVNZYURva1NvNHBXIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSIsImlzc3VlIl19.Ju7xpLx5GWe7wHowh+Ja9iwl3loEhoRTGDMMBH4Sc1HXAju7QoQy9LyR8B1WyR90Es5fj8Jka6OE/K4s7nEoCA";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- ISSUER IDENTITY (SENDER) --
        private const string _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiJiODhmNDQyMy0yNDdjLTQxNzItYTg0OS1jMWUxODkzN2U0ZDMiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjU4OjM4LjA4MTc1M1oiLCJrZXkiOiIyVERYZDlXVjhyTEN4b29GQVM5NFJMazNwSkw3dWlYOHdFVndkOEtIc3l5ZXZjYVE3cTVLS2l2bUoiLCJwdWIiOiIyVERYZG9OdlZSdEdQclM5aDhyYVROTVFRUzhzTXJmNWlrUGRGTW45eFk2cFVxUWtpZ2U5d2toSmYifQ";
        private const string _encodedIssuerIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiOTIwMjI0NjQtYmFkYi00ZDJiLTk0YjUtZDE2NmM5NWNmYjhlIiwic3ViIjoiM2Y4MTM4NjMtZWMyYy00OWE3LTkzMjAtNDM5M2Q5MTE2MzU3IiwiaXNzIjoiNTk4NjZjYWQtMTU1MS00NGM5LWJiNjMtMDAyNmU3ODJjMGZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMDo1ODozOC4xMjAwNloiLCJleHAiOiIyMDIyLTEyLTAxVDIwOjU4OjM4LjEyMDA2WiIsInB1YiI6IjJURFhkb052VlJ0R1ByUzloOHJhVE5NUVFTOHNNcmY1aWtQZEZNbjl4WTZwVXFRa2lnZTl3a2hKZiIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1qWTVZVFF6TURJdE1tWm1aaTAwTjJKbExXSTFabVl0TkRGa01XSTFNbU0wTlRneUlpd2ljM1ZpSWpvaU5UazROalpqWVdRdE1UVTFNUzAwTkdNNUxXSmlOak10TURBeU5tVTNPREpqTUdabUlpd2lhWE56SWpvaVlUTmtZV1poWXpZdFlqRXdPUzAwT1dReUxXRmhaR0V0Tkdaa01ERTBZalZsTlRabUlpd2lhV0YwSWpvaU1qQXlNUzB4TWkwd01WUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2laWGh3SWpvaU1qQXlOaTB4TVMwek1GUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2ljSFZpSWpvaU1sUkVXR1J2VG5aS1MxWTJTRGw1WlVjell6STNhMDQ1UVV4UWRIQTVOblZMYWxGRVNsSm5WRUp2V21kMlVWTlpZVVJ2YTFOdk5IQlhJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5Lkp1N3hwTHg1R1dlN3dIb3doK0phOWl3bDNsb0Vob1JUR0RNTUJINFNjMUhYQWp1N1FvUXk5THlSOEIxV3lSOTBFczVmajhKa2E2T0UvSzRzN25Fb0NB.hRqgv30qdDRlmT2+F+RXP4Rno7lA8s2gnoSqWVNuPwErMCFvWQHDQkHqKUZ+8DuRgUHrxutJlYuslWUhqeIdCA";
        private static Key _issuerKey;
        private static Identity _issuerIdentity;
        #endregion

        #region -- AUDIENCE IDENTITY (RECEIVER) --
        private const string _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiIxZTc3YTEzNi1lNTdmLTRiODAtYjc2Mi05NTI3OTdmOTNhYTkiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjU5OjA2LjM0MDQ2N1oiLCJrZXkiOiIyVERYZDlXVXhIaXdVN241QXZSdk52OE5GamhqanlVMmIxRVdvbkZ6QjlwTlNLZ1ljWnBjM01iU3ciLCJwdWIiOiIyVERYZG9OdlVlZEU1cDZmNGJXVkgyUERjNThOM2pkOEE1YndEQzl3QlRGdTRhVkJGdlplTGtzUUUifQ";
        private const string _encodedAudienceIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiOTJiZDgxOTUtM2I3ZC00MzMwLTg1ZmQtMTE3NTVhMDY2MTYwIiwic3ViIjoiMTYwYzQ1ZDctNTQwNS00ZDJkLTgyYzktMjI3NzAyNmU1ZjIzIiwiaXNzIjoiNTk4NjZjYWQtMTU1MS00NGM5LWJiNjMtMDAyNmU3ODJjMGZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMDo1OTowNi4zNzc3ODVaIiwiZXhwIjoiMjAyMi0xMi0wMVQyMDo1OTowNi4zNzc3ODVaIiwicHViIjoiMlREWGRvTnZVZWRFNXA2ZjRiV1ZIMlBEYzU4TjNqZDhBNWJ3REM5d0JURnU0YVZCRnZaZUxrc1FFIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1qWTVZVFF6TURJdE1tWm1aaTAwTjJKbExXSTFabVl0TkRGa01XSTFNbU0wTlRneUlpd2ljM1ZpSWpvaU5UazROalpqWVdRdE1UVTFNUzAwTkdNNUxXSmlOak10TURBeU5tVTNPREpqTUdabUlpd2lhWE56SWpvaVlUTmtZV1poWXpZdFlqRXdPUzAwT1dReUxXRmhaR0V0Tkdaa01ERTBZalZsTlRabUlpd2lhV0YwSWpvaU1qQXlNUzB4TWkwd01WUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2laWGh3SWpvaU1qQXlOaTB4TVMwek1GUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2ljSFZpSWpvaU1sUkVXR1J2VG5aS1MxWTJTRGw1WlVjell6STNhMDQ1UVV4UWRIQTVOblZMYWxGRVNsSm5WRUp2V21kMlVWTlpZVVJ2YTFOdk5IQlhJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5Lkp1N3hwTHg1R1dlN3dIb3doK0phOWl3bDNsb0Vob1JUR0RNTUJINFNjMUhYQWp1N1FvUXk5THlSOEIxV3lSOTBFczVmajhKa2E2T0UvSzRzN25Fb0NB.GHHrBKfsZDZCvI2pTsp4VMQHZi0ZNd1D8KtqYB9pmtINwrDOprMFYMKikZEkSLV8Zq4r/1mVgzLBV3vyet9dCQ";
        private static Key _audienceKey;
        private static Identity _audienceIdentity;
        #endregion
    }

}
