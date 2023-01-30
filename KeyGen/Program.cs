using System.Security.Cryptography;

//RSA : ASymmetric key 

var rsaKey = RSA.Create();

var privateKey = rsaKey.ExportRSAPrivateKey();

File.WriteAllBytes("key", privateKey);