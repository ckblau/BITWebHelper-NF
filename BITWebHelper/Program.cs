using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json.Linq;

namespace BITWebHelper {

    static class XEncode {

        public static uint[] CompressBytes (byte[] raw, bool addlen) {
            int len = raw.Length;
            uint[] vec = new uint[((len + 3) >> 2) + (addlen ? 1 : 0)];
            Buffer.BlockCopy(raw, 0, vec, 0, len);
            if (addlen) {
                vec[((len + 3) >> 2)] = (uint) len;
            }
            return vec;
        }

        public static byte[] DecompressBytes (uint[] vec, bool addlen) {
            int len = vec.Length, rawlen = (len - (addlen ? 1 : 0)) << 2;
            if (addlen) {
                int m = (int) vec[len - 1];
                if ((m < rawlen - 3) || (m > rawlen))
                    return null;
                rawlen = m;
            }
            byte[] raw = new byte[rawlen];
            Buffer.BlockCopy(vec, 0, raw, 0, rawlen);
            return raw;
        }

        public static byte[] Encode (string data, string key) {
            return Encode(Encoding.ASCII.GetBytes(data), Encoding.ASCII.GetBytes(key));
        }

        public static byte[] Encode (byte[] str, byte[] key) {
            uint[] v = CompressBytes(str, true);
            uint n = (uint) v.Length - 1;
            if (n < 1) {
                return null;
            }
            uint[] k = CompressBytes(key, false);
            if (k.Length < 4) {
                uint[] kk = new uint[4];
                k.CopyTo(kk, 0);
                k = kk;
            }
            uint z = v[n],
                 y, m, e,
                 c = unchecked((uint) -1640531527),
                 q = 6 + 52 / (n + 1),
                 d = 0;
            while (0 < q--) {
                d += c;
                e = (d >> 2) & 3;
                for (int i = 0; i < n; i++) {
                    y = v[i + 1];
                    m = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4) ^ d ^ y) + (k[(i & 3) ^ e] ^ z);
                    z = v[i] = v[i] + m;
                }
                y = v[0];
                m = ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4) ^ d ^ y) + (k[(n & 3) ^ e] ^ z);
                z = v[n] = v[n] + m;
            }
            return DecompressBytes(v, false);
        }

    }

    class NetHelper {

    }

    static class WebHelper {

        private static readonly string BASE_URL = "http://10.0.0.55/cgi-bin/srun_portal";
        private static readonly string CHALLENGE_URL = "http://10.0.0.55/cgi-bin/get_challenge";

        private static readonly string RAW_B64_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly string TRANS_B64_STR = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

        private static string USER_NAME;
        private static string USER_PASSWORD;

        private static string client_ip;
        private static string challenge;

        private static string Base64ModEncode (byte[] data) {
            string base64 = Convert.ToBase64String(data);
            string modstr = "";
            for (int i = 0; i < base64.Length; ++i) {
                if (RAW_B64_STR.IndexOf(base64[i]) != -1) {
                    modstr += TRANS_B64_STR[RAW_B64_STR.IndexOf(base64[i])];
                }
                else {
                    modstr += base64[i];
                }
            }
            return modstr;
        }

        private static string ByteToHex (byte[] data) {
            string hex = "";
            for (int i = 0; i < data.Length; ++i) {
                hex += data[i].ToString("x2");
            }
            return hex;
        }

        private static string HexHMACMD5 (string data, string key) {
            HMACMD5 provider = new HMACMD5(Encoding.UTF8.GetBytes(key));
            byte[] hash = provider.ComputeHash(Encoding.UTF8.GetBytes(data));
            provider.Dispose();
            return ByteToHex(hash);
        }

        private static string HexSHA1 (string data) {
            SHA1CryptoServiceProvider provider = new SHA1CryptoServiceProvider();
            byte[] hash = provider.ComputeHash(Encoding.ASCII.GetBytes(data));
            provider.Dispose();
            return ByteToHex(hash);
        }

        private static string GetTimeStamp () {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalMilliseconds).ToString();
        }

        private static string GetChallengeReqStr (string ispname) {
            string callbackstr = "jsonp" + GetTimeStamp(),
                   username = USER_NAME + "@" + ispname,
                   usernamestr = HttpUtility.UrlEncode(username);
            string ChallengeReqStr = string.Format("callback={0}&username={1}", callbackstr, usernamestr);
            return ChallengeReqStr;
        }

        private static string GetLogoutReqStr () {
            string callbackstr = "jsonp" + GetTimeStamp(),
                   actionstr = "logout",
                   usernamestr = USER_NAME;
            string LogoutReqStr = string.Format("callback={0}&action={1}&username={2}", callbackstr, actionstr, usernamestr);
            return LogoutReqStr;
        }

        private static string GetLoginReqStr (string ac_id, string ispname) {
            string callbackstr = "jsonp" + GetTimeStamp(),
                   actionstr = "login",
                   nstr = "200",
                   typestr = "1",
                   ipstr = client_ip,
                   username = USER_NAME + "@" + ispname,
                   usernamestr = HttpUtility.UrlEncode(username),
                   hmd5 = HexHMACMD5(/*USER_PASSWORD*/ "" , challenge),  
                   passwordstr = HttpUtility.UrlEncode("{MD5}" + hmd5);
            string infojson = string.Format("{{\"username\":\"{0}\",\"password\":\"{1}\",\"ip\":\"{2}\",\"acid\":\"{3}\",\"enc_ver\":\"srun_bx1\"}}", username, USER_PASSWORD, client_ip, ac_id);
            string info = "{SRBX1}" + Base64ModEncode(XEncode.Encode(infojson, challenge)),  
                   infostr = HttpUtility.UrlEncode(info);
            string checksumstr = HexSHA1(challenge + username + challenge + hmd5 + challenge + ac_id + challenge + ipstr + challenge + nstr + challenge + typestr + challenge + info); 
            string LoginReqStr = string.Format("callback={0}&action={1}&n={2}&type={3}&ac_id={4}&ip={5}&username={6}&password={7}&info={8}&chksum={9}", callbackstr, actionstr, nstr, typestr, ac_id, ipstr, usernamestr, passwordstr, infostr, checksumstr);
            return LoginReqStr;
        }

        private static async Task<JObject> SendReqAsync (string url, string reqstr) {
            string target = url + "?" + reqstr;
            Console.WriteLine("Request: {0}", target);
            string response = "";
            using (HttpClient client = new HttpClient()) {
                try {
                    response = await client.GetStringAsync(target);
                }
                catch (HttpRequestException e) {
                    Console.WriteLine("\nException Caught!");
                    Console.WriteLine("Message: {0}", e.Message);
                    return null;
                }
            }
            Console.WriteLine("Response: {0}", response);
            response = response.Substring(19, response.Length - 20);
            JObject jsonobj = JObject.Parse(response);
            string res = (string) jsonobj.SelectToken(@"$.res");
            if (res != "ok") {
                Console.WriteLine("\nAn error occurred: {0}, {1}, {2}", res, (string) jsonobj.SelectToken(@"$.error"), (string) jsonobj.SelectToken(@"$.error_msg"));
                return null;
            }
            return jsonobj;
        }

        private static void RefreshChallenge (string ispname) {
            JObject retjson = SendReqAsync(CHALLENGE_URL, GetChallengeReqStr(ispname)).GetAwaiter().GetResult();
            if (retjson != null) {
                client_ip = (string) retjson.SelectToken(@"$.client_ip");
                challenge = (string) retjson.SelectToken(@"$.challenge");
                Console.WriteLine("Get-Challenge succeeded.");
                Console.WriteLine("IP: {0}", client_ip);
                Console.WriteLine("Challenge: {0}", challenge);
            }
            else {
                Console.WriteLine("Get-Challenge failed.");
            }
        }

        public static void Init (string username, string password) {
            USER_NAME = username;
            USER_PASSWORD = password;
            Console.WriteLine("\n\nTIME: {0}", DateTime.Now.ToString());
        }

        public static void Logout () {
            RefreshChallenge("");
            JObject retjson = SendReqAsync(BASE_URL, GetLogoutReqStr()).GetAwaiter().GetResult();
            if (retjson != null) {
                Console.WriteLine("Logout succeeded.");
            }
            else {
                Console.WriteLine("Logout failed.");
            }
            //Console.WriteLine("\n");
        }

        public static void Login (string ac_id, string ispname) {
            RefreshChallenge(ispname);
            JObject retjson = SendReqAsync(BASE_URL, GetLoginReqStr(ac_id, ispname)).GetAwaiter().GetResult();
            if (retjson != null) {
                Console.WriteLine("Login succeeded.");
            }
            else {
                Console.WriteLine("Login failed.");
            }
            //Console.WriteLine("\n");
        }
    }

    class Program {

        static int Main (string[] args) {

            if (args.Length != 4) {
                Console.WriteLine("Bad arguments!");
                Console.WriteLine("BITWebHelper <access_id> <ispname> <username> <password>");
                return 0;
            }
            string ac_id = args[0],
                   ispname = args[1],
                   username = args[2],
                   password = args[3];
            WebHelper.Init(username, password);
            WebHelper.Logout();
            WebHelper.Login(ac_id, ispname);
            //Console.ReadLine();
            return 0;

        }

    }

}
