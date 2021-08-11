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
        private const string _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiI0M2ExOTNiYi00NjRlLTQ2ODItYTNmNC05NGIzNmVkZjkxZGYiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjMwOjAyLjY3NTUyMloiLCJrZXkiOiIxaEVrSko5ZVhUczZmU3B0MlZuV1RmMlVOOVg3OGdQQkpCYjZteU41VUpOYVIzeDYxb1pHUCIsInB1YiI6IjFoUEphaFp2ZUx3QkxyckZYR3UxaFFHN0RiMVVUVDFZbzRXaHppVFVOWXF4eG9XUUF3R3ljIn0";
        private const string _encodedTrustedIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiOGY1ODZlMTAtYmQ0OC00NTQwLTk1NzAtNjhmZTI2YmY2YmMwIiwic3ViIjoiYzc3Yjg1ZmYtZGQ3ZC00Y2UxLThjYjMtY2MyYjZmYmZkYmFhIiwiaXNzIjoiYzc3Yjg1ZmYtZGQ3ZC00Y2UxLThjYjMtY2MyYjZmYmZkYmFhIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzozMDowMi43ODQxODdaIiwiZXhwIjoiMjAzMS0wOC0wOVQwNzozMDowMi43ODQxODdaIiwicHViIjoiMWhQSmFoWnZlTHdCTHJyRlhHdTFoUUc3RGIxVVRUMVlvNFdoemlUVU5ZcXh4b1dRQXdHeWMiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdfQ.AR/jvc20Vfqon788pu15w2bkm2o9lp2Q2dbqXUVUz2fDPAMe96H66uCqvfMJareiu1jCMjGbNYBhymmGO9LMVQg";
        private static Key _trustedKey;
        private static Identity _trustedIdentity;
        #endregion

        #region -- INTERMEDIATE IDENTITY --
        private const string _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiJmYWZjNWE0NS0xMDRhLTQ4OWUtYTAzZC0zM2FlMTJkNDM0ZTUiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjM5OjU2Ljk5NTAwMloiLCJrZXkiOiIxaEVqNExiQzZtZENEYm5RN1BNQ0ZGeWVOSnFZeVFXMzgxWVJKVWJNbVdlVlN4YTZLUllGNCIsInB1YiI6IjFoUEtBNkZUb282OGpoQW5wVUJQRUpEd212QVB6ZTdRdThNd2hTdkdQZG50SjlyaFN6VEpxIn0";
        private const string _encodedIntermediateIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMTNkNWViMzAtZGJlZS00Zjc4LTg3ZTAtODc5ZmVhYTIyZDBjIiwic3ViIjoiNWU2OWQ5NDgtMmZlMC00Y2NmLTg2ZTUtNTFhYTNhYTY3YjZmIiwiaXNzIjoiYzc3Yjg1ZmYtZGQ3ZC00Y2UxLThjYjMtY2MyYjZmYmZkYmFhIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzozOTo1Ny4wODI3MjNaIiwiZXhwIjoiMjAyNi0wOC0xMFQwNzozOTo1Ny4wODI3MjNaIiwicHViIjoiMWhQS0E2RlRvbzY4amhBbnBVQlBFSkR3bXZBUHplN1F1OE13aFN2R1BkbnRKOXJoU3pUSnEiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXX0.AYsjnfoVvjh7YIRVL+42RPNACAjpgw9i4Lwo5Zgm7qc8C9WaVdX02uuqyP6orxA1Q7nn0lWa9FW4VWODhVfrUws";
        private static Key _intermediateKey;
        private static Identity _intermediateIdentity;
        #endregion

        #region -- ISSUER IDENTITY (SENDER) --
        private const string _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiIwMDRkOWUxNi01Y2E5LTQyZjAtOTM4Zi1lMGY4NWI2MDNiNDgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjQwOjM4LjczMjMwOFoiLCJrZXkiOiIxaEVqdTQ5NjExdUN3Z3ZobzZwWlFwbmZndVBDb1NxNXJnOFpwUUR3Y3ZYeFZ0dFNSaDhHYiIsInB1YiI6IjFoUEtRQUx4bkc0RjFFSkhZQTl5UGtVWmRYM2g3clRibVZHeGdMWjFKQTNvWmlYODhaQUIyIn0";
        private const string _encodedIssuerIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMGJiMzFkOTctNmIxZi00NjQ4LTgwNGYtYzQ3NmQ0ZTE0N2UzIiwic3ViIjoiZWQ1M2VmNWQtMGRjOC00Zjk2LWJmNmUtYjk5NjkyNzg1YTE4IiwiaXNzIjoiNWU2OWQ5NDgtMmZlMC00Y2NmLTg2ZTUtNTFhYTNhYTY3YjZmIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzo0MDozOC44MjAwMjhaIiwiZXhwIjoiMjAyMi0wOC0xMVQwNzo0MDozOC44MjAwMjhaIiwicHViIjoiMWhQS1FBTHhuRzRGMUVKSFlBOXlQa1VaZFgzaDdyVGJtVkd4Z0xaMUpBM29aaVg4OFpBQjIiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UTmtOV1ZpTXpBdFpHSmxaUzAwWmpjNExUZzNaVEF0T0RjNVptVmhZVEl5WkRCaklpd2ljM1ZpSWpvaU5XVTJPV1E1TkRndE1tWmxNQzAwWTJObUxUZzJaVFV0TlRGaFlUTmhZVFkzWWpabUlpd2lhWE56SWpvaVl6YzNZamcxWm1ZdFpHUTNaQzAwWTJVeExUaGpZak10WTJNeVlqWm1ZbVprWW1GaElpd2lhV0YwSWpvaU1qQXlNUzB3T0MweE1WUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2laWGh3SWpvaU1qQXlOaTB3T0MweE1GUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2ljSFZpSWpvaU1XaFFTMEUyUmxSdmJ6WTRhbWhCYm5CVlFsQkZTa1IzYlhaQlVIcGxOMUYxT0UxM2FGTjJSMUJrYm5SS09YSm9VM3BVU25FaUxDSmpZWEFpT2xzaVoyVnVaWEpwWXlJc0ltbGtaVzUwYVdaNUlpd2lhWE56ZFdVaVhYMC5BWXNqbmZvVnZqaDdZSVJWTCs0MlJQTkFDQWpwZ3c5aTRMd281WmdtN3FjOEM5V2FWZFgwMnV1cXlQNm9yeEExUTdubjBsV2E5Rlc0VldPRGhWZnJVd3M.Aez/Int+YNjDvnDi7FnLCzlhOPuk4z6P3eG3rtJe8pBx8N4hvUFJZ3KdZimZxNsuMUTfyYKuZRM9V/NtyTDhBwo";
        private static Key _issuerKey;
        private static Identity _issuerIdentity;
        #endregion

        #region -- AUDIENCE IDENTITY (RECEIVER) --
        private const string _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiJhYmI5YWUxYy04ZWZmLTQ1MjctYWJhNC1iMTczZjA5ZGQ1ZDgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjQxOjEyLjcwNTUyMVoiLCJrZXkiOiIxaEVqVjU0R3ZxMkhnVGVKNzFXdzJpbml0eTRHYjZERktyWEQ2cHl6c2dtRGFTNVJZWndnOCIsInB1YiI6IjFoUEp1OW9naGMxZXJtdEx6TFZqeEpMMWdDU3NKdURtMlVmY2VLWjhLclJQM2hFaHVZcWhVIn0";
        private const string _encodedAudienceIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiNDljYTcwM2ItNDcwNC00ODY1LTg4MjQtZjE4ZjMwZjcxMTUxIiwic3ViIjoiYWZlNDIzMTItZDhjMi00ZjhlLTllOWMtYzA2NjU5YzBjZmRmIiwiaXNzIjoiNWU2OWQ5NDgtMmZlMC00Y2NmLTg2ZTUtNTFhYTNhYTY3YjZmIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzo0MToxMi43OTQxNTVaIiwiZXhwIjoiMjAyMi0wOC0xMVQwNzo0MToxMi43OTQxNTVaIiwicHViIjoiMWhQSnU5b2doYzFlcm10THpMVmp4SkwxZ0NTc0p1RG0yVWZjZUtaOEtyUlAzaEVodVlxaFUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UTmtOV1ZpTXpBdFpHSmxaUzAwWmpjNExUZzNaVEF0T0RjNVptVmhZVEl5WkRCaklpd2ljM1ZpSWpvaU5XVTJPV1E1TkRndE1tWmxNQzAwWTJObUxUZzJaVFV0TlRGaFlUTmhZVFkzWWpabUlpd2lhWE56SWpvaVl6YzNZamcxWm1ZdFpHUTNaQzAwWTJVeExUaGpZak10WTJNeVlqWm1ZbVprWW1GaElpd2lhV0YwSWpvaU1qQXlNUzB3T0MweE1WUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2laWGh3SWpvaU1qQXlOaTB3T0MweE1GUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2ljSFZpSWpvaU1XaFFTMEUyUmxSdmJ6WTRhbWhCYm5CVlFsQkZTa1IzYlhaQlVIcGxOMUYxT0UxM2FGTjJSMUJrYm5SS09YSm9VM3BVU25FaUxDSmpZWEFpT2xzaVoyVnVaWEpwWXlJc0ltbGtaVzUwYVdaNUlpd2lhWE56ZFdVaVhYMC5BWXNqbmZvVnZqaDdZSVJWTCs0MlJQTkFDQWpwZ3c5aTRMd281WmdtN3FjOEM5V2FWZFgwMnV1cXlQNm9yeEExUTdubjBsV2E5Rlc0VldPRGhWZnJVd3M.AW394NnuirPP8sBOJD3BSweIdH5mVqAPvz6bluVTvfc4+3gv17OUGHXe82cEBPBfSCCqLIHAWekCLO9Q4u8vxgg";
        private static Key _audienceKey;
        private static Identity _audienceIdentity;
        #endregion
    }

}
