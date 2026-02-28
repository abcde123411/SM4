class SM4(object):
    """
    根据 SM4 国密标准文档编写
    """

    def __init__(self, plaintext=None):
        # 明文
        self.plaintext = plaintext.zfill(32)

        # 密文
        self.ciphertext = None

        # 加密密钥(默认)
        self.main_key = '0123456789abcdeffedcba9876543210'

        # 加密密钥 MK=(MK0,MK1,MK2,MK3)
        self.MK = [self.main_key[i*8: i*8+8] for i in range(4)]

        # S盒
        self.s_box = ['d6', '90', 'e9', 'fe', 'cc', 'e1', '3d', 'b7', '16', 'b6', '14', 'c2', '28', 'fb', '2c', '05',
                      '2b', '67', '9a', '76', '2a', 'be', '04', 'c3', 'aa', '44', '13', '26', '49', '86', '06', '99',
                      '9c', '42', '50', 'f4', '91', 'ef', '98', '7a', '33', '54', '0b', '43', 'ed', 'cf', 'ac', '62',
                      'e4', 'b3', '1c', 'a9', 'c9', '08', 'e8', '95', '80', 'df', '94', 'fa', '75', '8f', '3f', 'a6',
                      '47', '07', 'a7', 'fc', 'f3', '73', '17', 'ba', '83', '59', '3c', '19', 'e6', '85', '4f', 'a8',
                      '68', '6b', '81', 'b2', '71', '64', 'da', '8b', 'f8', 'eb', '0f', '4b', '70', '56', '9d', '35',
                      '1e', '24', '0e', '5e', '63', '58', 'd1', 'a2', '25', '22', '7c', '3b', '01', '21', '78', '87',
                      'd4', '00', '46', '57', '9f', 'd3', '27', '52', '4c', '36', '02', 'e7', 'a0', 'c4', 'c8', '9e',
                      'ea', 'bf', '8a', 'd2', '40', 'c7', '38', 'b5', 'a3', 'f7', 'f2', 'ce', 'f9', '61', '15', 'a1',
                      'e0', 'ae', '5d', 'a4', '9b', '34', '1a', '55', 'ad', '93', '32', '30', 'f5', '8c', 'b1', 'e3',
                      '1d', 'f6', 'e2', '2e', '82', '66', 'ca', '60', 'c0', '29', '23', 'ab', '0d', '53', '4e', '6f',
                      'd5', 'db', '37', '45', 'de', 'fd', '8e', '2f', '03', 'ff', '6a', '72', '6d', '6c', '5b', '51',
                      '8d', '1b', 'af', '92', 'bb', 'dd', 'bc', '7f', '11', 'd9', '5c', '41', '1f', '10', '5a', 'd8',
                      '0a', 'c1', '31', '88', 'a5', 'cd', '7b', 'bd', '2d', '74', 'd0', '12', 'b8', 'e5', 'b4', 'b0',
                      '89', '69', '97', '4a', '0c', '96', '77', '7e', '65', 'b9', 'f1', '09', 'c5', '6e', 'c6', '84',
                      '18', 'f0', '7d', 'ec', '3a', 'dc', '4d', '20', '79', 'ee', '5f', '3e', 'd7', 'cb', '39', '48']

        # 系统参数 FK
        self.FK = ['a3b1bac6', '56aa3350', '677d9197', 'b27022dc']

        # 32个固定参数 CK
        self.CK = ['00070e15', '1c232a31', '383f464d', '545b6269',
                   '70777e85', '8c939aa1', 'a8afb6bd', 'c4cbd2d9',
                   'e0e7eef5', 'fc030a11', '181f262d', '343b4249',
                   '50575e65', '6c737a81', '888f969d', 'a4abb2b9',
                   'c0c7ced5', 'dce3eaf1', 'f8ff060d', '141b2229',
                   '30373e45', '4c535a61', '686f767d', '848b9299',
                   'a0a7aeb5', 'bcc3cad1', 'd8dfe6ed', 'f4fb0209',
                   '10171e25', '2c333a41', '484f565d', '646b7279']

        # 32比特
        self.K = [''] * 36

        # 轮密钥(32比特)
        self.rk = [''] * 32

        # 每轮状态(32比特)
        self.X = [''] * 36

    @staticmethod
    def shift_to_left(string, num):
        """
        循环左移
        :param string: 32比特
        :param num: 循环左移位数
        :return: 循环左移后的新32比特
        """
        return string[num % len(string):] + string[:num % len(string)]

    @staticmethod
    def x_o_r(string_list):
        """
        异或
        :param string_list: 整数列表
        :return: 列表中所有数据异或结果 (16进制)
        """
        result = 0
        for i in range(len(string_list)):
            result = result ^ string_list[i]
        return hex(result)[2:].zfill(8)

    def Sbox(self, row_column):
        """
        S盒为固定的8比特输入8比特输出的置换
        :param row_column: S盒的行列
        :return: 按照行列所对应置换后的8比特 (16进制)
        """
        index = int(row_column, 16)
        return self.s_box[index]

    def tal(self, A):
        """
        非线性变换 tal
        :param A: A=(a0,a1,a2,a3) ai,i=0,1,2,3是8比特
        :return: 经过S盒转换后的32比特B, B=(b0,b1,b2,b3)
        """
        B = ''
        for i in range(4):
            B += self.Sbox(A[i*2: i*2+2])
        return B

    def key_extension(self, times=None):
        """
        密钥扩展算法
        :return: 生成轮密钥 rk
        """
        T_ = lambda tmp: self.L_(self.tal(tmp))
        for i in range(0, 4):
            self.K[i] = self.x_o_r([int(self.MK[i], 16), int(self.FK[i], 16)])

        for i in range(0, 32):
            self.rk[i] = self.K[i+4] = self.x_o_r([int(self.K[i], 16), int(T_(self.x_o_r([int(self.K[i+1], 16), int
            (self.K[i+2], 16), int(self.K[i+3], 16), int(self.CK[i], 16)])), 16)])

    def L(self, B):
        """
        线性变换 L
        :param B: tal生成的32比特B
        :return: 异或后的32比特C(16进制)
        """
        # bin_B, 32比特B的二进制格式
        bin_B = bin(int(B, 16))[2:].zfill(32)
        B_shift_2 = self.shift_to_left(bin_B, 2)
        B_shift_10 = self.shift_to_left(bin_B, 10)
        B_shift_18 = self.shift_to_left(bin_B, 18)
        B_shift_24 = self.shift_to_left(bin_B, 24)
        C = self.x_o_r([int(bin_B, 2), int(B_shift_2, 2), int(B_shift_10, 2), int(B_shift_18, 2), int(B_shift_24, 2)])
        return C

    def L_(self, B):
        """
        线性变换 L'
        :param B: tal生成的32比特B
        :return: 异或后的32比特C(16进制)
        """
        # bin_B, 32比特B的二进制格式
        bin_B = bin(int(B, 16))[2:].zfill(32)
        B_shift_13 = self.shift_to_left(bin_B, 13)
        B_shift_23 = self.shift_to_left(bin_B, 23)
        C = self.x_o_r([int(bin_B, 2), int(B_shift_13, 2), int(B_shift_23, 2)])
        return C

    def F(self, X0, X1, X2, X3, rk):
        """
        轮函数 F
        :param X:
        :param rk: 轮密钥
        :return: 迭代运算结果
        """
        T = lambda tmp: self.L(self.tal(tmp))
        result = self.x_o_r([int(X0, 16), int(T(self.x_o_r([int(X1, 16), int(X2, 16), int(X3, 16), int(rk, 16)])), 16)])
        return result

    def encrypt(self):
        """
        加密
        :return: ciphertext密文 128比特16进制
        """
        self.X[0] = self.plaintext[0:8]
        self.X[1] = self.plaintext[8:16]
        self.X[2] = self.plaintext[16:24]
        self.X[3] = self.plaintext[24:32]
        for i in range(0, 32):
            self.X[i+4] = self.F(self.X[i], self.X[i+1], self.X[i+2], self.X[i+3], self.rk[i])
        ciphertext = ''.join(self.X[::-1][:4])
        self.ciphertext = ciphertext
        return ciphertext

    def decrypt(self):
        """
        解密
        :return: plaintext明文 128比特16进制
        """
        self.X[0] = self.ciphertext[0:8]
        self.X[1] = self.ciphertext[8:16]
        self.X[2] = self.ciphertext[16:24]
        self.X[3] = self.ciphertext[24:32]
        for i in range(0, 32):
            self.X[i+4] = self.F(self.X[i], self.X[i+1], self.X[i+2], self.X[i+3], self.rk[31-i])
        plaintext = ''.join(self.X[::-1][:4])
        return plaintext

# 明文 012
a = SM4('012')

# 密钥保持默认的
a.key_extension()

# 加密
t = a.encrypt()
print(t)

# 解密
t = a.decrypt()
print(t)
