using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        public static int[] PC1_Arr = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };

        public static int[] PC2_Arr = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

        public static int[] IP_Arr = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

        public static int[] IP_Inverse_Arr = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

        public static int[] Expansion_Arr = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

        public static int[] P_Arr = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

        public static int[] Shift_Arr = { 0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public static List<int[,]> S_Arrays = new List<int[,]> {
            new int[,] {
                {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
            },
            new int[,] {
                {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
            },
            new int[,] {
                {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
            },
            new int[,] {
                {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
            },
            new int[,] {
                {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
            },
            new int[,] {
                {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
            },
            new int[,] {
                {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
            },
            new int[,] {
                {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11},
            },
        };

        public string ConvertHexNumberToBinaryNumber(string hexNumber)
        {
            string binary = Convert.ToString(Convert.ToInt64(hexNumber, 16), 2);
            binary = binary.PadLeft((hexNumber.Length * 4) - binary.Length, '0');
            return binary;
        }

        public string ConvertBinaryNumberToHexNumber(string binaryNumber)
        {
            if (binaryNumber.Length % 4 != 0)
            {
                int x = binaryNumber.Length / 4;
                binaryNumber = MissingZerosBinary(binaryNumber, (x + 1) * 4);
            }
            string hexNumber = "0x" + MissingZerosBinary(Convert.ToInt64(binaryNumber, 2).ToString("X"), 16);
            return hexNumber;
        }

        public string MissingZerosBinary(string number, int len)
        {
            string zeroes = "";
            for (int i = 0; i < len - number.Length; i++)
            {
                zeroes += '0';
            }
            string completeNumber = zeroes + number;
            return completeNumber;
        }

        public string ShiftLeftBinary(string binaryNumber)
        {
            string shiftedBinaryNumber = binaryNumber.Substring(1, binaryNumber.Length - 1);
            shiftedBinaryNumber += binaryNumber[0];
            return shiftedBinaryNumber;
        }

        public string HexXOR(string hexNumber1, string hexNumber2)
        {
            string binaryNumber1 = ConvertHexNumberToBinaryNumber(hexNumber1);
            string binaryNumber2 = ConvertHexNumberToBinaryNumber(hexNumber2);
            string binaryResult = XOR(binaryNumber1, binaryNumber2);
            string hexResult = ConvertBinaryNumberToHexNumber(binaryResult);
            return hexResult;
        }

        public string XOR(string binaryNumber1, string binaryNumber2)
        {
            string result = "";
            for (int i = 0; i < binaryNumber1.Length; i++)
            {
                result += (binaryNumber1[i] == binaryNumber2[i]) ? "0" : "1";
            }
            return result;
        }

        public string PermutationBinary(string binaryNumber, int[] permutationList)
        {
            string permutedBinaryNumber = "";
            for (int i = 0; i < permutationList.Length; i++)
            {
                permutedBinaryNumber += binaryNumber[permutationList[i] - 1];
            }
            return permutedBinaryNumber;
        }

        public string InversePermutationBinary(string permutedBinaryNumber, int[] permutationList)
        {
            char[] binaryNumberArr = new char[permutedBinaryNumber.Length];
            for (int i = 0; i < permutationList.Length; i++)
            {
                binaryNumberArr[permutationList[i] - 1] = permutedBinaryNumber[i];
            }
            string binaryNumber = new string(binaryNumberArr);
            return binaryNumber;
        }

        public string ShiftLeft(string binaryNumber, int shiftValue)
        {
            string shiftedNumber = binaryNumber.Substring(shiftValue);
            for(int i=0; i<shiftValue; i++)
            {
                shiftedNumber += binaryNumber[i];
            }
            return shiftedNumber;
        }

        public int BinaryToDecimal(string binaryString)
        {
            int decimalNumber = 0;
            int power = 0;
            for (int i = binaryString.Length - 1; i >= 0; i--)
            {
                int digit = binaryString[i] - '0';
                decimalNumber += digit * (int)Math.Pow(2, power);
                power+=1;
            }
            return decimalNumber;
        }

        public string DecimalToBinary(int decimalNumber)
        {
            if (decimalNumber == 0)
                return "0";

            string binaryString = "";
            while (decimalNumber > 0)
            {
                int remainder = decimalNumber % 2;
                binaryString = (char)remainder + binaryString;
                decimalNumber /= 2;
            }

            return binaryString;
        }

        public string SBoxPermutation(string binary)
        {
            string result = "";
            for(int i=0; i<8; i++)
            {
                string num = binary.Substring(i*6, 6);
                string rowBinary = "";
                rowBinary += num[0];
                rowBinary += num[5];
                int row = BinaryToDecimal(rowBinary);                
                string columnBinary = num.Substring(1, 4);
                int column = BinaryToDecimal(columnBinary);                
                int[,] SBOX = S_Arrays[i];
                int SBox_Result = SBOX[row, column];
                result += MissingZerosBinary(Convert.ToString(SBox_Result, 2), 4); //Convert Hex to Bin
            }
            return result;
        }

        public string Mangler(string R, string L, string key)
        {
            string new_R = PermutationBinary(R, Expansion_Arr);
            new_R = XOR(new_R, key);
            new_R = SBoxPermutation(new_R);
            new_R = PermutationBinary(new_R, P_Arr);
            new_R = XOR(new_R, L);
            return new_R;
        }

        public List<string> GenerateKeys(string initkey)
        {
            List<string> keys = new List<string>();
            initkey = ConvertHexNumberToBinaryNumber(initkey);
            initkey = MissingZerosBinary(initkey, 64);
            initkey = PermutationBinary(initkey, PC1_Arr);
            keys.Add(initkey);

            List<string> C = new List<string>();
            List<string> D = new List<string>();

            C.Add(initkey.Substring(0, 28));
            D.Add(initkey.Substring(28));
            for (int i=1; i<=16; i++)
            {
                C.Add(ShiftLeft(C[i - 1], Shift_Arr[i]));
                D.Add(ShiftLeft(D[i - 1], Shift_Arr[i]));
            }

            for (int i=1; i<=16; i++)
            {
                keys.Add( PermutationBinary(C[i] + D[i], PC2_Arr) );
            }
            return keys;
        }


        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            List<string> keys = GenerateKeys(key);

            plainText = ConvertHexNumberToBinaryNumber(plainText);
            plainText = MissingZerosBinary(plainText, 64);
            plainText = PermutationBinary(plainText, IP_Arr);

            string L = plainText.Substring(0, 32);
            string R = plainText.Substring(32);

            for (int i = 1; i <= 16; i++)
            {
                string temp = Mangler(R, L, keys[i]);
                L = R;
                R = temp;
            }

            string cipherText = PermutationBinary(R + L, IP_Inverse_Arr);
            cipherText = ConvertBinaryNumberToHexNumber(cipherText);
            return cipherText;
        }


        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            List<string> keys = GenerateKeys(key);

            cipherText = ConvertHexNumberToBinaryNumber(cipherText);
            cipherText = MissingZerosBinary(cipherText, 64);
            cipherText = InversePermutationBinary(cipherText, IP_Inverse_Arr);

            string R = cipherText.Substring(0, 32);
            string L = cipherText.Substring(32);
            for (int i = 16; i >= 1; i--)
            {
                string temp = Mangler(L, R, keys[i]);
                R = L;
                L = temp;
            }

            string plainText = InversePermutationBinary(L+R, IP_Arr);
            plainText = ConvertBinaryNumberToHexNumber(plainText);
            return plainText;
        }


    }
}
