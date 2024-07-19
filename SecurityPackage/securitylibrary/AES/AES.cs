using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        // Constants
        public static string x1B = "00011011";

        public static int[,] MixColumnMatrix = {
            { 2, 3, 1, 1 },
            { 1, 2, 3, 1 },
            { 1, 1, 2, 3 },
            { 3, 1, 1, 2 }
        };

        public static string[,] InverseMixColumnMatrix = new string[4, 4] {
            {"0e", "0b", "0d", "09"},
            {"09", "0e", "0b", "0d"},
            {"0d", "09", "0e", "0b"},
            {"0b", "0d", "09", "0e"}
        };

        public static string[,] sBoxMatrix = new string[16, 16]{
           // 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},// 0
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},// 1
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},// 2
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},// 3
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},// 4
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},// 5
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},// 6
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},// 7
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},// 8
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},// 9
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},// 10
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},// 11
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},// 12
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},// 13
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},// 14
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"} // 15
        };

        public static string[,] inverseSBoxMatrix = new string[16, 16] {
           // 0     1     2     3     4     5     6     7     8     9     10    11    12    13    14    15
            {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},// 0
            {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},// 1
            {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},// 2
            {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},// 3
            {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},// 4
            {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},// 5
            {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},// 6
            {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},// 7
            {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},// 8
            {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},// 9
            {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},// 10
            {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},// 11
            {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},// 12
            {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},// 13
            {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},// 14
            {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}// 15
        };

        public static string[,] Rcon = new string[4, 10] {
            {"01", "02", "04", "08", "10", "20", "40", "80", "1B", "36"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
        };




        // Functions


        #region Task 1 (Convert String <=> Matrix) & (Convert HEX <=> Binary)
        // TODO: Task 1 (Convert String <=> Matrix) & (Convert HEX <=> Binary)
        public string ConvertHexMatrixToHexString(string[,] hexMatrix)
        {
            // throw new NotImplementedException();
            string hexWord = "0x";
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    hexWord += hexMatrix[col, row];
                }
            }
            return hexWord;
        }

        public string[,] ConvertHexStringToHexMatrix(string hexString)
        {
            // throw new NotImplementedException();
            string[,] hexMatrix = new string[4, 4];
            for (int row = 0; row < 4; row++)
            {
                for (int col = 0; col < 4; col++)
                {
                    int index = (col * 2) + (row * 8);
                    index += 2; // skip x0 at start of string
                    hexMatrix[col, row] = hexString.Substring(index, 2);
                }
            }
            return hexMatrix;
        }

        public string ConvertHexNumberToBinaryNumber(string hexNumber)
        {
            // throw new NotImplementedException();
            string binary = Convert.ToString(Convert.ToInt64(hexNumber, 16), 2).PadLeft(hexNumber.Length * 4, '0');
            return binary;
        }

        public string ConvertBinaryNumberToHexNumber(string binaryNumber)
        {
            // throw new NotImplementedException();
            if (binaryNumber.Length % 4 != 0)
            {
                int x = binaryNumber.Length / 4;
                binaryNumber = MissingZerosBinary(binaryNumber, (x + 1) * 4);
            }
            string hexNumber = MissingZerosBinary(Convert.ToInt64(binaryNumber, 2).ToString("X"), 2);
            return hexNumber;
        }
        #endregion


        #region Task 2 (Supported Functions)
        // TODO: Task 2 (Supported Functions)
        public string MultiplyGaloisField(string binaryNumber1, string binaryNumber2)
        {
            // throw new NotImplementedException();

            string result = "00000000";
            for (int i = 0; i < result.Length; i++)
            {
                if (binaryNumber2[binaryNumber2.Length - 1 - i] == '1')
                {
                    result = XOR(binaryNumber1, result);
                }
                char last = binaryNumber1[0];
                binaryNumber1 = ShiftLeftBinary(binaryNumber1);
                if (last == '1')
                {
                    binaryNumber1 = XOR(binaryNumber1, x1B);
                }
            }
            return result;
        }

        public string XOR(string binaryNumber1, string binaryNumber2)
        {
            // throw new NotImplementedException();
            string result = "";
            binaryNumber1 = MissingZerosBinary(binaryNumber1, 8);
            binaryNumber2 = MissingZerosBinary(binaryNumber2, 8);
            for (int i = 0; i < binaryNumber1.Length; i++)
            {
                result += (binaryNumber1[i] == binaryNumber2[i]) ? "0" : "1";
            }
            return result;
        }

        #endregion


        #region Task 3 (SubByte)
        // TODO: Task 3 (SubByte)

        public string[,] SubByte(string[,] wordMatrix, bool IsInverse)
        {
            // IsInverse => send it to ConvertStringWithSBOX()

            // throw new NotImplementedException();
            string[,] resultMarex = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    resultMarex[i, j] = ConvertStringWithSBOX(wordMatrix[i, j], IsInverse);
                }
            }
            return resultMarex;
        }

        public string ConvertStringWithSBOX(string hexString, bool IsInverse)
        {
            /*
             Ex. hexString = "9d"  after sBox ot will be "5e"
             return "5e"

            IsInverse => if true us inverseSBoxMatrix and if false sBoxMatrix
            */

            // throw new NotImplementedException();
            char c1 = hexString[0], c2 = hexString[1];
            int sRow = (c1 >= '0' && c1 <= '9') ? c1 - '0' : c1 - 'A' + 10;
            int sCol = (c2 >= '0' && c2 <= '9') ? c2 - '0' : c2 - 'A' + 10;
            string result = IsInverse ? inverseSBoxMatrix[sRow, sCol] : sBoxMatrix[sRow, sCol];
            return result;
        }

        #endregion


        #region Task 4 (ShiftRow)
        // TODO: Task 5 (ShiftRow)
        public string[,] ShiftRow(string[,] wordMatrix)
        {
            // throw new NotImplementedException();
            int numRows = wordMatrix.GetLength(0);
            int numCols = wordMatrix.GetLength(1);

            string[,] resultMatrix = new string[numRows, numCols];

            for (int row = 0; row < numRows; row++)
            {
                string[] x = new string[numCols];
                for (int i = 0; i < numCols; i++)
                {
                    x[i] = wordMatrix[row, i];
                }

                string[] x2 = new string[numCols];
                for (int j = 0; j < numCols; j++)
                {
                    x2[j] = x[(j + row) % numCols];
                }

                for (int z = 0; z < numCols; z++)
                {
                    resultMatrix[row, z] = x2[z];
                }
            }

            return resultMatrix;
        }

        public string[,] InverseShiftRow(string[,] wordMatrix)
        {
            // throw new NotImplementedException();
            int numRows = wordMatrix.GetLength(0);
            int numCols = wordMatrix.GetLength(1);

            string[,] resultMatrix = new string[numRows, numCols];

            for (int row = 0; row < numRows; row++)
            {
                string[] x = new string[numCols];
                for (int i = 0; i < numCols; i++)
                {
                    x[i] = wordMatrix[row, i];
                }

                string[] x2 = new string[numCols];
                for (int j = 0; j < numCols; j++)
                {
                    x2[(j + row) % numCols] = x[j];
                }

                for (int z = 0; z < numCols; z++)
                {
                    resultMatrix[row, z] = x2[z];
                }
            }

            return resultMatrix;
        }
        #endregion


        #region Task 5 (MixColums)
        // TODO: Task 5 (MixColums)
        public string[,] MixColumns(string[,] wordMatrix)
        {
            string[,] output = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string[] arr = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        string value = Convert.ToString(Convert.ToInt32(wordMatrix[k, i], 16), 2);
                        value = MissingZerosBinary(value, 8);
                        int mixValue = MixColumnMatrix[j, k];

                        if (mixValue == 2 || mixValue == 3)
                        {
                            string res = MultiplyGaloisField(value, mixValue == 2 ? "00000010" : "00000011");
                            arr[k] = res;
                        }
                        else
                        {
                            arr[k] = value;
                        }
                    }
                    string result = "00000000";
                    for (int m = 0; m < 4; m++)
                    {
                        result = XOR(result, arr[m]);
                    }
                    output[j, i] = ConvertBinaryNumberToHexNumber(result);
                    if (output[j, i].Length == 1)
                        output[j, i] = "0" + output[j, i];
                }
            }
            return output;
        }
        public string[,] InverseMixColumns(string[,] wordMatrix)
        {
            string[,] output = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string[] arr = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        string value = Convert.ToString(Convert.ToInt32(wordMatrix[k, i], 16), 2);
                        value = MissingZerosBinary(value, 8);
                        string mixValue = InverseMixColumnMatrix[j, k];
                        string res = MultiplyGaloisField(value, ConvertHexNumberToBinaryNumber(mixValue));
                        arr[k] = res;
                    }
                    string result = "00000000";
                    for (int m = 0; m < 4; m++)
                    {
                        result = XOR(result, arr[m]);
                    }
                    output[j, i] = ConvertBinaryNumberToHexNumber(result);

                }
            }
            return output;
        }
        #endregion


        #region Task 6 (generateKeys)
        public List<string[,]> generateKeys(string[,] initkeyMatrix)
        {
            List<string[,]> keys = new List<string[,]>();
            keys.Add(initkeyMatrix);

            int round = 1;
            while (round <= 10)
            {
                string[,] oldKey = keys[round - 1];
                string[,] newKey = new string[4, 4];

                for (int col = 0; col < 4; col++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        if (col == 0)
                        {
                            newKey[i, 0] = oldKey[(i + 1) % 4, 3];
                            newKey[i, 0] = ConvertStringWithSBOX(newKey[i, 0], false);
                            newKey[i, 0] = HexXOR(newKey[i, 0], Rcon[i, round - 1]);
                            newKey[i, 0] = HexXOR(newKey[i, 0], oldKey[i, 0]);
                        }
                        else
                        {
                            newKey[i, col] = HexXOR(newKey[i, col - 1], oldKey[i, col]);
                        }
                    }
                }

                keys.Add(newKey);
                round++;
            }

            return keys;
        }
        #endregion


        #region Task 7 (Encrypt & Decrypt)
        // TODO: Task 7 (Encrypt & Decrypt)
        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            string[,] plainTextMatrix = ConvertHexStringToHexMatrix(plainText);
            string[,] keyMatrix = ConvertHexStringToHexMatrix(key);
            List<string[,]> listKeys = generateKeys(keyMatrix);
            string[,] cypherextMatrix = AddRoundKey(plainTextMatrix, listKeys[0]);
            for (int i = 1; i <= 10; i++)
            {
                cypherextMatrix = SubByte(cypherextMatrix, false);
                cypherextMatrix = ShiftRow(cypherextMatrix);
                if (i < 10) cypherextMatrix = MixColumns(cypherextMatrix);
                cypherextMatrix = AddRoundKey(cypherextMatrix, listKeys[i]);
            }
            string cipherText = ConvertHexMatrixToHexString(cypherextMatrix);
            return cipherText;
        }

        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string[,] cipherTextMatrix = ConvertHexStringToHexMatrix(cipherText);
            string[,] keyMatrix = ConvertHexStringToHexMatrix(key);
            List<string[,]> listKeys = generateKeys(keyMatrix);
            string[,] plainTextMatrix = AddRoundKey(cipherTextMatrix, listKeys[10]);
            for (int i = 9; i >= 0; i--)
            {
                if (i < 9) plainTextMatrix = InverseMixColumns(plainTextMatrix);
                plainTextMatrix = InverseShiftRow(plainTextMatrix);
                plainTextMatrix = SubByte(plainTextMatrix, true);
                plainTextMatrix = AddRoundKey(plainTextMatrix, listKeys[i]);
            }
            string plainText = ConvertHexMatrixToHexString(plainTextMatrix);
            return plainText;
        }
        #endregion




        public string[,] AddRoundKey(string[,] wordMatrix, string[,] keyMatrix)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = HexXOR(wordMatrix[i, j], keyMatrix[i, j]);
                }
            }
            return result;
        }

        public string HexXOR(string hexNumber1, string hexNumber2)
        {
            string binaryNumber1 = ConvertHexNumberToBinaryNumber(hexNumber1);
            string binaryNumber2 = ConvertHexNumberToBinaryNumber(hexNumber2);
            string binaryResult = XOR(binaryNumber1, binaryNumber2);
            string hexResult = ConvertBinaryNumberToHexNumber(binaryResult);
            return hexResult;
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
            shiftedBinaryNumber += 0;
            return shiftedBinaryNumber;
        }

        public void printMatrix(string[,] matrix)
        {
            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    Console.Write($"{matrix[i, j]} ");
                }
                Console.WriteLine(" ");
            }
            Console.WriteLine("--------------------");
        }

    }
}