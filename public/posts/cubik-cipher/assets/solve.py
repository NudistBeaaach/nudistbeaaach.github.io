from lib import *

def encryption(data_bitvector, key_bitvector):

    key_list = list()

    for i in range(9):
        key_list.append(key_bitvector)

        cubix_key = fill_cubix(key_bitvector[0:576])

        cubix = fill_cubix(data_bitvector)

        cubix = mix_cubix(cubix,[m_0,m_1,m_2,m_3])

        cubix = round_cubix(cubix,cubix_key)

        cubix = permutation(cubix)
        
        data_bitvector = extract_cubix(cubix)

        key_bitvector = galois_lfsr(key_bitvector)

    return (data_bitvector,key_list)

def decryption(data_bitvector, key_list):

    cubix = fill_cubix(data_bitvector)

    for l in range(9):

        key_bitvector = key_list[l]
        cubix_key = fill_cubix(key_bitvector[0:576])

        cubix = reverse_permutation(cubix)

        cubix = round_cubix(cubix,cubix_key)

        cubix = reverse_mix_cubix(cubix,[m_0,m_1,m_2,m_3])

    extracted = extract_cubix(cubix)[::-1]

    return extracted



if __name__ == "__main__":

    key = 0xf0ae2e1abee8afbe3ea424cc71f4ce17455a21d5df15cc4f6362e3af095cfb6da7188a9777c2c875ab39145a88a2142aea7b5411607110d70cd3d37c20f259b1920031990709d8e0e8d661b1a05fe8b5719aab6569835b3e52be738982608fda36549fd1e3398c725190356fbe97998b79f84f0ef23c4dea63898b52319a47a2

    data = 0x4841434B4441590000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    flag_encrypted = 0x79EEEF596B960C42262DFD1D0A2DB218FA3C71C681963F0CC389D3F0F5234C8023CA79D315186AF55621289F92AD6D9B657D999E074C84E13BFDAEDC94A3BA4FCB95B4013BFC40E5

    key_bitvector = int_to_bin(key,1024)
    data_bitvector = int_to_bin(data,576)
    flag_encrypted_bitvector = int_to_bin(flag_encrypted,576)

    data_bitvector,key_list = encryption(data_bitvector,key_bitvector)
    
    key_list = key_list[::-1]

    extracted = decryption(flag_encrypted_bitvector,key_list)
    
    flag = list()
    for i in range(0,576,8):

        byte = extracted[i:i+8]
        flag.append(chr(int(byte,2)))

    print("".join(flag))
    # HACKDAY{99b6b6d2c037a65d509c401c7d2f5052914e0a4e3420627d23d0b969daf1df3}



    

