using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            string key = "";
            cipherText = cipherText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                // K = (CT - PT) mod 26
                key += (char)((((cipherText[i] - 'a') - (plainText[i] - 'a') + 26) % 26) + 'a');
                string check = Encrypt(plainText, key);
                if (check.Equals(cipherText))
                    break;
            }

            return key;        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            int padLength = 0;
            key = key.ToUpper();

            // decrypt the characters using the key 
            for (int i = 0; i < key.Length; i++)
            {   //PT = (CT - K) mod 26
                plainText += (char)((((cipherText[i] - 'A') - (key[i] - 'A') + 26) % 26) + 'A');
            }

            // if key is exhausted, decrypt the remaining characters using the already decrypted text
            if (key.Length < cipherText.Length)
            {
                padLength = cipherText.Length - key.Length;
                for (int i = 0; i < padLength; i++)
                {
                    plainText += (char)((((cipherText[i + key.Length] - 'A') - (plainText[i] - 'A') + 26) % 26) + 'A');
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        { 
          /*
          pad the key with plainText until its
          length is equal to the length of plainText
          */
            while (key.Length < plainText.Length)
            {
                key += plainText.Substring(0, plainText.Length - key.Length);
            }

            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {   //CT = (PT + K) mod 26
                cipherText += (char)(((plainText[i] - 'a' + key[i] - 'a') % 26) + 'a');
            }
            return cipherText;
        }
    }
}
