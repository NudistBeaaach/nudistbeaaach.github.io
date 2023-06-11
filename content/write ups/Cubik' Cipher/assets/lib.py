from pyfinite import ffield, genericmatrix

GF_512 = ffield.FField(9)
XOR = lambda x,y: GF_512.Add(x,y)
MUL = lambda x,y: GF_512.Multiply(x,y)
DIV = lambda x,y: GF_512.Multiply(x, GF_512.Inverse(y))

def int_to_bin(hex_string, padding):
    return format(hex_string,"0{}b".format(padding))[::-1]

def bin_to_int(x):
    return int(x[::-1], 2)

m_0 = genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV)

m_0.SetRow(0, [3,0,2,6])
m_0.SetRow(1, [6,3,0,2])
m_0.SetRow(2, [2,6,3,0])
m_0.SetRow(3, [0,2,6,3])

m_1 = genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV)

m_1.SetRow(0, [6,4,3,0])
m_1.SetRow(1, [0,6,4,3])
m_1.SetRow(2, [3,0,6,4])
m_1.SetRow(3, [4,3,0,6])

m_2 = genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV)

m_2.SetRow(0, [4,0,9,3])
m_2.SetRow(1, [3,4,0,9])
m_2.SetRow(2, [9,3,4,0])
m_2.SetRow(3, [0,9,3,4])

m_3 = genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV)

m_3.SetRow(0, [2,4,0,9])
m_3.SetRow(1, [9,2,4,0])
m_3.SetRow(2, [0,9,2,4])
m_3.SetRow(3, [4,0,9,2])

def matrix_str_to_int(matrix):
    for i in range(4):
        row = [bin_to_int(j) for j in matrix.GetRow(i)]
        matrix.SetRow(i,row)
    return matrix

def matrix_int_to_str(matrix):
    for i in range(4):
        row = [int_to_bin(j,9) for j in matrix.GetRow(i)]
        matrix.SetRow(i,row)
    return matrix
    
def round_cubix(cubix,cubix_key):
    return [matrix_int_to_str(matrix_str_to_int(cubix[i]) + matrix_str_to_int(cubix_key[i])) for i in range(4)]

def shift_matrix(matrix_list, p):
    ret = [j for j in range(4)]
    for i in range(4):
        ret[i] = matrix_list[(i+p) % 4]
    return ret

def galois_lfsr(key):

    key = list(key)

    high_bit = key[1023]
    key[23] = str(int(key[23]) ^ int(high_bit))
    key[420] = str(int(key[420]) ^ int(high_bit))
    key[475] = str(int(key[475]) ^ int(high_bit))
    key[544] = str(int(key[544]) ^ int(high_bit))
    key[922] = str(int(key[922]) ^ int(high_bit))

    key = "".join(key)
    key = high_bit + key[:1023]

    return key

def extract_cubix(cubix):

    bitvector = [b for b in range(576)]
    for i in range(4):

        matrix_data = [b for b in range(4)]
        for j in range(4):

            row_data = [b for b in range(4)]
            for k in range(4):

                row_data[9*k:9*(k+1)] = cubix[i].GetRow(j)[k]

            matrix_data[36*j:36*(j+1)] = row_data

        bitvector[144*i:144*(i+1)] = matrix_data
        
    return "".join(bitvector)

def fill_cubix(bitvector):
    cubix = [m for m in range(4)]
    for i in range(4):

        matrix = genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV)
        matrix_data = bitvector[144*i:144*(i+1)]

        for j in range(4):

            row = [v for v in range(4)]
            row_data = matrix_data[36*j:36*(j+1)]

            for k in range(4):
                row[k] = row_data[9*k:9*(k+1)]

            matrix.SetRow(j,row)
        
        cubix[i] = matrix

    return cubix

def reverse_mix_cubix(cubix, matrix_list):
    for i in range(4):

        matrix_list_i = shift_matrix(matrix_list,i)
        cubix[i] = matrix_str_to_int(cubix[i])

        for j in range(4):
            cubix[i].SetRow(j,matrix_list_i[j].Solve(cubix[i].GetRow(j)))
        
        cubix[i] = matrix_int_to_str(cubix[i])
    
    return cubix

def mix_cubix(cubix, matrix_list):
    for i in range(4):

        matrix_list_i = shift_matrix(matrix_list,i)
        cubix[i] = matrix_str_to_int(cubix[i])

        for j in range(4):
            cubix[i].SetRow(j,matrix_list_i[j].LeftMulColumnVec(cubix[i].GetRow(j)))

        cubix[i] = matrix_int_to_str(cubix[i])

    return cubix


def permutation(cubix):

    tmp_cubix = [genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV) for i in range(4)]

    tmp_cubix[0].SetRow(0,cubix[1].GetRow(1))
    tmp_cubix[0].SetRow(1,cubix[3].GetRow(3))
    tmp_cubix[0].SetRow(2,cubix[2].GetRow(2))
    tmp_cubix[0].SetRow(3,cubix[2].GetRow(1))
    tmp_cubix[1].SetRow(0,cubix[3].GetRow(1))
    tmp_cubix[1].SetRow(1,cubix[2].GetRow(0))
    tmp_cubix[1].SetRow(2,cubix[0].GetRow(1))
    tmp_cubix[1].SetRow(3,cubix[1].GetRow(2))
    tmp_cubix[2].SetRow(0,cubix[1].GetRow(0))
    tmp_cubix[2].SetRow(1,cubix[0].GetRow(3))
    tmp_cubix[2].SetRow(2,cubix[2].GetRow(3))
    tmp_cubix[2].SetRow(3,cubix[3].GetRow(0))
    tmp_cubix[3].SetRow(0,cubix[3].GetRow(2))
    tmp_cubix[3].SetRow(1,cubix[0].GetRow(0))
    tmp_cubix[3].SetRow(2,cubix[1].GetRow(3))
    tmp_cubix[3].SetRow(3,cubix[0].GetRow(2))

    return tmp_cubix

def reverse_permutation(cubix):
    tmp_cubix = [genericmatrix.GenericMatrix(size=(4,4),zeroElement=0,identityElement=1,add=XOR,mul=MUL,sub=XOR,div=DIV) for i in range(4)]

    tmp_cubix[1].SetRow(1,cubix[0].GetRow(0))
    tmp_cubix[3].SetRow(3,cubix[0].GetRow(1))
    tmp_cubix[2].SetRow(2,cubix[0].GetRow(2))
    tmp_cubix[2].SetRow(1,cubix[0].GetRow(3))
    tmp_cubix[3].SetRow(1,cubix[1].GetRow(0))
    tmp_cubix[2].SetRow(0,cubix[1].GetRow(1))
    tmp_cubix[0].SetRow(1,cubix[1].GetRow(2))
    tmp_cubix[1].SetRow(2,cubix[1].GetRow(3))
    tmp_cubix[1].SetRow(0,cubix[2].GetRow(0))
    tmp_cubix[0].SetRow(3,cubix[2].GetRow(1))
    tmp_cubix[2].SetRow(3,cubix[2].GetRow(2))
    tmp_cubix[3].SetRow(0,cubix[2].GetRow(3))
    tmp_cubix[3].SetRow(2,cubix[3].GetRow(0))
    tmp_cubix[0].SetRow(0,cubix[3].GetRow(1))
    tmp_cubix[1].SetRow(3,cubix[3].GetRow(2))
    tmp_cubix[0].SetRow(2,cubix[3].GetRow(3))

    return tmp_cubix
