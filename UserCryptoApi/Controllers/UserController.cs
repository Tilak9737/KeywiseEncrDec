using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Keywise_Enc_Dec.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly JwtConfig _config;

        public UserController(IOptions<JwtConfig> config)
        {
            _config = config.Value;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            if (string.IsNullOrWhiteSpace(model.UserName) || string.IsNullOrWhiteSpace(model.Password))
                return BadRequest("Username and password required.");

            var passwordHash = SHA256.HashData(Encoding.UTF8.GetBytes(model.Password));
            var passwordHashText = Convert.ToBase64String(passwordHash);
            var time = DateTime.UtcNow.ToString("o");

            var claims = new List<Claim>
            {
                new Claim("username", model.UserName),
                new Claim("hash", passwordHashText),
                new Claim("time", time),
                new Claim("salt", _config.StaticSalt)
            };

            var keyBytes = Encoding.UTF8.GetBytes(_config.SecretKey);
            var securityKey = new SymmetricSecurityKey(keyBytes);
            var creds = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds,
                expires: DateTime.UtcNow.AddMinutes(10)
            );

            var tokenText = new JwtSecurityTokenHandler().WriteToken(token);
            HttpContext.Session.SetString("userToken", tokenText);

            return Ok("Logged in. Token saved in session.");
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt([FromBody] TextModel model)
        {
            var token = HttpContext.Session.GetString("userToken");
            if (token == null) return Unauthorized("Session expired.");

            var key = GetKeyFromToken(token);
            var encryptedText = EncryptText(model.Text, key);
            var keyHex = BitConverter.ToString(key).Replace("-", "");
            return Ok(new
            {
                encrypted = encryptedText,
                keyUsed = keyHex,
                JwtToken = token
            });
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt([FromBody] TextModel model)
        {
            var token = HttpContext.Session.GetString("userToken");
            if (token == null) return Unauthorized("Session expired.");

            var key = GetKeyFromToken(token);
            var result = DecryptText(model.Text, key);
            return Ok(result);
        }

        private byte[] GetKeyFromToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            var username = jwt.Claims.First(c => c.Type == "username").Value;
            var hash = jwt.Claims.First(c => c.Type == "hash").Value;
            var time = jwt.Claims.First(c => c.Type == "time").Value;
            var salt = jwt.Claims.First(c => c.Type == "salt").Value;

            var combined = username + hash + time + salt + _config.SecretKey;
            return SHA256.HashData(Encoding.UTF8.GetBytes(combined));
        }

        private string EncryptText(string plainText, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var writer = new StreamWriter(cs))
            {
                writer.Write(plainText);
            }

            return Convert.ToBase64String(ms.ToArray());
        }

        private string DecryptText(string encryptedText, byte[] key)
        {
            var fullData = Convert.FromBase64String(encryptedText);
            using var aes = Aes.Create();
            aes.Key = key;

            var iv = new byte[16];
            Array.Copy(fullData, iv, 16);
            aes.IV = iv;

            using var ms = new MemoryStream(fullData.Skip(16).ToArray());
            using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var reader = new StreamReader(cs);
            return reader.ReadToEnd();
        }
    }

    public class LoginModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    public class TextModel
    {
        public string Text { get; set; }
    }
    public class JwtConfig
    {
        public string SecretKey { get; set; }
        public string StaticSalt { get; set; }
    }
}
