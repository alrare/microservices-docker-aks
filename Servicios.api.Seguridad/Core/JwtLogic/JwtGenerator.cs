using Microsoft.IdentityModel.Tokens;
using Servicios.api.Seguridad.Core.Entities;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Servicios.api.Seguridad.Core.JwtLogic
{
    public class JwtGenerator : IJwtGenerator
    {
        public string CreateToken(Usuario usuario)
        {
            var claims = new List<Claim>
            {
                new Claim("username", usuario.UserName),
                new Claim("nombre", usuario.Nombre),
                new Claim("apellido", usuario.Apellido),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1"));
            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(3),
                SigningCredentials = credential
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescription);

            return tokenHandler.WriteToken(token);
        }
    }
}
