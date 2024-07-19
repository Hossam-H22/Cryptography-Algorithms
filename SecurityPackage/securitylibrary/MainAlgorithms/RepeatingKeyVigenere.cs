using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string repeatedKey = "";
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                int col = GetCharIndex(plainText[i]);
                int intersection = GetCharIndex(cipherText[i]);

                char repeatedKeyChar = 'a';
                for (int j = 0; j < 26; j++)
                {
                    if((col+j)%26  == intersection)
                    {
                        repeatedKeyChar = GetIndexChar(j);
                    }
                }


                repeatedKey += repeatedKeyChar;
            }


            string key = repeatedKey;
            for (int i = repeatedKey.Length - 1; i > 0; i--)
            {
                if (repeatedKey[i] == repeatedKey[0] && checkIfKey(i, repeatedKey))
                {
                    key = "";
                    for (int j = 0; j < i; j++)
                    {
                        key += repeatedKey[j];
                    }
                }
            }

            return key;
        }

        private bool checkIfKey(int ind, string repeatedKey)
        {
            for (int i = ind, j = 0; i < repeatedKey.Length; i++, j++)
            {
                j = j % ind;

                if (repeatedKey[i] != repeatedKey[j])
                {
                    return false;
                }
            }

            return true;
        }


        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            for (int i = 0; i < cipherText.Length; i++)
            {
                int intersection = GetCharIndex(cipherText[i]);
                int row = GetCharIndex(key[(i % key.Length)]);


                char plainTextChar = 'a';
                for (int j = 0; j < 26; j++)
                {
                    if ((row + j) % 26 == intersection)
                    {
                        plainTextChar = GetIndexChar(j);
                    }
                }


                plainText += plainTextChar;
            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string ret = "";
            plainText = plainText.ToLower();
            key = key.ToLower();

            for (int i = 0; i < plainText.Length; i++) 
            {
                int col = GetCharIndex(plainText[i]);
                int row = GetCharIndex(key[ (i % key.Length) ]);

                int retChar = (col + row) % 26;

                ret += GetIndexChar(retChar);
            }

            return ret;
        }


        private int GetCharIndex(char x)
        {
            return Convert.ToInt32(x) - 97;
        }

        private char GetIndexChar(int x)
        {
            return Convert.ToChar((x + 97));
        }
    }
}

