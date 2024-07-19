using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public void printMatrix(int[,] matrix)
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

        public int modulus(int num, int m)
        {
            return (num % m + m) % m;
        }

        public int[,] convert1DTo2D(List<int> list, int rows, int cols, bool isKey)
        {
            if (list.Count != rows * cols)
            {
                throw new ArgumentException("The count of the input list must be equal to rows * cols");
            }

            int[,] result = new int[rows, cols];
            if (isKey)
            {
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < cols; j++)
                    {
                        result[i, j] = list[i * cols + j];
                    }
                }
            }
            else
            {
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < cols; j++)
                    {
                        result[i, j] = list[j * rows + i];
                    }
                }
            }
            return result;
        }

        public List<int> convert2DTo1D(int[,] array, bool iskey=false)
        {
            int rows = array.GetLength(0);
            int cols = array.GetLength(1);
            List<int> result = new List<int>();
            if (iskey)
            {
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < cols; j++)
                    {
                        result.Add(array[i, j]);
                    }
                }
            }
            else
            {
                for (int i = 0; i < cols; i++)
                {
                    for (int j = 0; j < rows; j++)
                    {
                        result.Add(array[j, i]);
                    }
                }
            }
            return result;
        }

        public int[,] multiply2DArrays(int[,] array1, int[,] array2)
        {
            int rows1 = array1.GetLength(0);
            int cols1 = array1.GetLength(1);
            int rows2 = array2.GetLength(0);
            int cols2 = array2.GetLength(1);
            if (cols1 != rows2)
            {
                throw new ArgumentException("Number of columns in the first array must be equal to the number of rows in the second array");
            }
            int[,] result = new int[rows1, cols2];
            for (int i = 0; i < rows1; i++)
            {
                for (int j = 0; j < cols2; j++)
                {
                    for (int k = 0; k < cols1; k++)
                    {
                        result[i, j] += (array1[i, k] * array2[k, j]);
                    }
                    result[i, j] = modulus(result[i, j], 26);
                }
            }
            return result;
        }

        public int[,] createSubMatrix(int[,] matrix, int excludeRow, int excludeCol)
        {
            int size = matrix.GetLength(0);
            int[,] subMatrix = new int[size - 1, size - 1];
            int row = 0, col = 0;
            for (int i = 0; i < size; i++)
            {
                if (i != excludeRow)
                {
                    col = 0;
                    for (int j = 0; j < size; j++)
                    {
                        if (j != excludeCol)
                        {
                            subMatrix[row, col] = matrix[i, j];
                            col++;
                        }
                    }
                    row++;
                }
            }
            return subMatrix;
        }

        public int calculateDeterminant(int[,] matrix)
        {
            int size = matrix.GetLength(0);
            if (size != matrix.GetLength(1))
            {
                throw new ArgumentException("Input matrix must be square");
            }
            if (size == 1)
            {
                return matrix[0, 0]; // Base case: determinant of a 1x1 matrix
            }
            else if (size == 2)
            {
                return (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]); // Base case: determinant of a 2x2 matrix
            }
            else
            {
                int determinant = 0;
                int sign = 1;

                for (int j = 0; j < size; j++)
                {
                    int[,] subMatrix = createSubMatrix(matrix, 0, j);
                    determinant += (sign * matrix[0, j] * calculateDeterminant(subMatrix));
                    sign *= -1; // Alternate signs for cofactors
                }
                return determinant;
            }
        }

        public int calculateSubDeterminant(int[,] matrix, int i, int j)
        {
            if (matrix.GetLength(0) != 3 || matrix.GetLength(1) != 3)
            {
                throw new ArgumentException("The input matrix must be a 3x3 matrix");
            }

            // Calculate sub-determinant based on row i and column j
            int r1 = modulus(i + 1, 3);
            int r2 = modulus(i + 2, 3);
            int c1 = modulus(j + 1, 3);
            int c2 = modulus(j + 2, 3);
            int row1 = r1 >= r2 ? r1 : r2;
            int row2 = r1 < r2 ? r1 : r2;
            int col1 = c1 >= c2 ? c1 : c2;
            int col2 = c1 < c2 ? c1 : c2;

            int subDeterminant = matrix[row1, col1] * matrix[row2, col2] - matrix[row1, col2] * matrix[row2, col1];
            return subDeterminant;
        }

        public int calculateGCD(int a, int b)
        {
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }

        public int calculateB(int det)
        {
            det = modulus(det, 26);
            if (det == 0)
            {
                throw new InvalidAnlysisException();
            }
            int b=1;
            while (b<26)
            {
                if (modulus(b * det, 26) == 1) 
                    return b;
                b++;
            }
            if (b == 26)
                throw new InvalidAnlysisException();

            return b;
        }

        public int[,] transposeMatrix(int[,] matrix)
        {
            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);
            int[,] transposedMatrix = new int[cols, rows];
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    transposedMatrix[j, i] = matrix[i, j];
                }
            }
            return transposedMatrix;
        }

        public int[,] inverseMatrix3By3(int[,] matrix)
        {
            int det = calculateDeterminant(matrix);
            int b = calculateB(det);

            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);
            int[,] inverseMatrix = new int[cols, rows];

            int one = 1;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    one = (i + j) % 2 == 0 ? 1 : -1;
                    int value = one * b * calculateSubDeterminant(matrix, i, j);
                    inverseMatrix[i, j] = modulus(value, 26);
                }
            }
            return inverseMatrix;
        }

        public int[,] inverseMatrix2By2(int[,] matrix)
        {
            int det = calculateDeterminant(matrix);
            int b = calculateB(det);

            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);
            int[,] inverse = new int[cols, rows];

            inverse[0, 0] = modulus(matrix[1, 1], 26);
            inverse[0, 1] = modulus(-matrix[0, 1], 26);
            inverse[1, 0] = modulus(-matrix[1, 0], 26);
            inverse[1, 1] = modulus(matrix[0, 0], 26);
            
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    inverse[i, j] = modulus(inverse[i, j] * b, 26);
                }
            }
            return inverse;
        }

        public List<int[,]> getBest2x2Matrix(int[,] matrix1, int[,] matrix2)
        {
            List<int[,]> newMatrixs = new List<int[,]>();
            newMatrixs.Add(new int[2, 2]);
            newMatrixs.Add(new int[2, 2]);
            
            int len = matrix1.GetLength(1), det=0;
            for(int i=0; i<len-1; i++)
            {
                newMatrixs[0][0, 0] = matrix1[0, i];
                newMatrixs[0][1, 0] = matrix1[1, i];
                for(int j=i+1; j<len; j++)
                {
                    newMatrixs[0][0, 1] = matrix1[0, j];
                    newMatrixs[0][1, 1] = matrix1[1, j];
                    det = modulus(calculateDeterminant(newMatrixs[0]), 26);
                    if(det%2==1 && det != 13)
                    {
                        newMatrixs[1][0, 0] = matrix2[0, i];
                        newMatrixs[1][1, 0] = matrix2[1, i];
                        newMatrixs[1][0, 1] = matrix2[0, j];
                        newMatrixs[1][1, 1] = matrix2[1, j];
                        break;
                    }
                }
                if (det % 2 == 1 && det != 13) break;
            }
            return newMatrixs;
        }


        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            // throw new NotImplementedException();
            int[,] plainTextMatrix = convert1DTo2D(plainText, 2, plainText.Count/2, false);
            int[,] cipherTextMatrix = convert1DTo2D(cipherText, 2, cipherText.Count/2, false);
            
            // convert any matrix 2xN => 2x2 matrix
            List<int[,]> newMatrixs = getBest2x2Matrix(plainTextMatrix, cipherTextMatrix);
            // newMatrixs[0] => plainMatrix 2x2
            // newMatrixs[1] => cipherMatrix 2x2

            int[,] inverseMatrix = inverseMatrix2By2(newMatrixs[0]);
            int[,] result = multiply2DArrays(newMatrixs[1], inverseMatrix);
            List<int> key = convert2DTo1D(result, true);
            return key;
        }
        
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            List<int> plainTextArr = new List<int>();
            List<int> cipherTextArr = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                plainTextArr.Add((int)plainText[i]);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherTextArr.Add((int)cipherText[i]);
            }

            List<int> keyArr = Analyse(plainTextArr, cipherTextArr);
            string key = "";
            for (int i = 0; i < keyArr.Count; i++)
            {
                key += (char)keyArr[i];
            }
            return key;
        }
        
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // throw new NotImplementedException();
            int keyDimensional = key.Count == 4 ? 2 : 3;
            int[,] keyMatrix = convert1DTo2D(key, keyDimensional, keyDimensional, true);
            int[,] cipherTextMatrix = convert1DTo2D(cipherText, keyDimensional, cipherText.Count / keyDimensional, false);
            int[,] inverseMatrix;
            if (keyDimensional == 2)
            {
                inverseMatrix = inverseMatrix2By2(keyMatrix);
            }
            else
            {
                inverseMatrix = inverseMatrix3By3(keyMatrix);
                inverseMatrix = transposeMatrix(inverseMatrix);
            }

            int[,] result = multiply2DArrays(inverseMatrix, cipherTextMatrix);
            List<int> plainText = convert2DTo1D(result);
            return plainText;
        }
        
        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            List<int> keyArr = new List<int>();
            List<int> cipherTextArr = new List<int>();
            for (int i = 0; i < key.Length; i++)
            {
                keyArr.Add((int)keyArr[i]);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherTextArr.Add((int)cipherText[i]);
            }

            List<int> plainTextArr = Decrypt(cipherTextArr, keyArr);
            string plainText = "";
            for (int i = 0; i < plainTextArr.Count; i++)
            {
                plainText += (char)plainTextArr[i];
            }
            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            // throw new NotImplementedException();
            int keyDimensional = key.Count == 4 ? 2 : 3;
            int[,] keyMatrix = convert1DTo2D(key, keyDimensional, keyDimensional, true);
            int[,] plainTextMatrix = convert1DTo2D(plainText, keyDimensional, plainText.Count / keyDimensional, false);
            int[,] result = multiply2DArrays(keyMatrix, plainTextMatrix);
            List<int> cipherText = convert2DTo1D(result);
            return cipherText;
        }
        
        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            List<int> plainTextArr = new List<int>();
            List<int> keyArr = new List<int>();
            for(int i=0; i<plainText.Length; i++)
            {
                plainTextArr.Add((int)plainText[i]);
            }
            for (int i = 0; i < key.Length; i++)
            {
                keyArr.Add((int)key[i]);
            }

            List<int> cipherTextArr = Encrypt(plainTextArr, keyArr);
            string cipherText = "";
            for (int i = 0; i < cipherTextArr.Count; i++)
            {
                cipherText += (char)cipherTextArr[i];
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            // throw new NotImplementedException();
            int[,] plainTextMatrix = convert1DTo2D(plain3, 3, plain3.Count/3, false);
            int[,] cipherTextMatrix = convert1DTo2D(cipher3, 3, cipher3.Count/3, false);
            int[,] inverseMatrix = inverseMatrix3By3(plainTextMatrix);
            inverseMatrix = transposeMatrix(inverseMatrix);
            int[,] result = multiply2DArrays(cipherTextMatrix, inverseMatrix);
            List<int> key = convert2DTo1D(result, true);
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            // throw new NotImplementedException();
            List<int> plainTextArr = new List<int>();
            List<int> cipherTextArr = new List<int>();
            for (int i = 0; i < plain3.Length; i++)
            {
                plainTextArr.Add((int)plain3[i]);
            }
            for (int i = 0; i < cipher3.Length; i++)
            {
                cipherTextArr.Add((int)cipher3[i]);
            }

            List<int> keyArr = Analyse3By3Key(plainTextArr, cipherTextArr);
            string key = "";
            for (int i = 0; i < keyArr.Count; i++)
            {
                key += (char)keyArr[i];
            }
            return key;
        }


    }
}

