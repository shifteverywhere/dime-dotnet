using System;
using System.Text;

namespace ShiftEverywhere.DiME
{
    public static class Utility
    {
        public static String ToHex(byte[] bytes)
        {
            StringBuilder hex = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static string ToBase64(byte[] bytes)
        {
            return System.Convert.ToBase64String(bytes).Trim('=');
        }

        public static string ToBase64(string str)
        {
            return Utility.ToBase64(Encoding.UTF8.GetBytes(str));
        }

        public static byte[] FromBase64(String base64)
        {
            string str = base64;
            str = str.Replace('_', '/').Replace('-', '+');
            int padding = base64.Length % 4;
            if (padding > 1)
            {
                str += padding == 2 ? "==" : "=";
            }
            return System.Convert.FromBase64String(str);
        }


    }

}
