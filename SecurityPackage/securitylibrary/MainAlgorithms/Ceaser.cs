using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string cipherText ="";
            for (int i=0; i< plainText.Length; i++)
            {
                cipherText += (char)(((plainText.ToLower()[i] - 'a' + key) % 26)+'a');
            }
            cipherText = cipherText.ToUpper();
            return cipherText;
            
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += (char)(((cipherText.ToLower()[i] - 'a' - key + 26) % 26) + 'a');
            }
            return plainText;
            
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            return (cipherText.ToLower()[0] - plainText.ToLower()[0] + 26)%26;
        }
    }
}
