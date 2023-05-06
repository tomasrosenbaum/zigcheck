from Crypto.Cipher import AES
from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppDataPayload, ZigbeeNWK


class Decrypter:
    """
    A helper tool for deciphering ZigBee messages. Follows ZigBee specification.
    """
    NWK_SECURITY_LEVELS = {0x05: 4, 0x06: 8, 0x07: 16, }
    ENDIAN = 'big'

    def decrypt(self, pkt, key, source=None):
        """
        Try to decrypt the packet for each possible MIC length until successfully decrypted.

        Args:
            pkt (Packet): packet (or its part) to decipher
            key (bytes): key to decipher the packet with
            source (int|None): source address to use if the security header doesn't contain one

        Returns:
            True if deciphering was successful, False otherwise
        """
        for nwk_security_level in self.NWK_SECURITY_LEVELS:
            if self.__security_processing(pkt, key, nwk_security_level, source):
                return True

        return False

    # 4.3.1.2 Security Processing of Incoming Frames
    def __security_processing(self, pkt, key, nwk_security_level, source):
        """
        Security processing as defined in 4.3.1.2 Security Processing of Incoming Frames of ZigBee specification.

        Args:
            pkt (Packet): packet (or its part) to decipher
            key (bytes): key to decipher the packet with
            nwk_security_level (int): the guessed security level to try deciphering with
            source (int|None): source address to use if the security header doesn't contain one

        Returns:
            True if deciphering was successful, False otherwise
        """
        # 1)
        auxiliary_header = pkt.getlayer(ZigbeeSecurityHeader)
        auxiliary_header.data += auxiliary_header.mic
        auxiliary_header.mic = b''
        auxiliary_header.nwk_seclevel = nwk_security_level
        sender_address = auxiliary_header.source
        if sender_address is None:
            sender_address = source

        sender_address = sender_address.to_bytes(8, self.ENDIAN)
        received_frame_count = auxiliary_header.fc.to_bytes(4, self.ENDIAN)
        if received_frame_count == 2 ** 32 - 1:
            return False

        # 4) a)
        m_capital = self.NWK_SECURITY_LEVELS[nwk_security_level]
        # c)
        security_control_field = ((auxiliary_header.reserved1.reserved1 << 7) |
                                  (auxiliary_header.reserved1.reserved2 << 6) |
                                  (auxiliary_header.extended_nonce << 5) |
                                  (auxiliary_header.key_type << 3) |
                                  auxiliary_header.nwk_seclevel).to_bytes(1, self.ENDIAN)
        n_capital = self.__ccm_nonce(sender_address, received_frame_count, security_control_field)
        # d)
        secured_payload = auxiliary_header.data
        # e)
        if pkt.haslayer(ZigbeeAppDataPayload):
            if auxiliary_header.key_type == 2:
                key = self.__key_hash(bytes.fromhex('00'), key)
            elif auxiliary_header.key_type == 3:
                key = self.__key_hash(bytes.fromhex('02'), key)

            a = bytes(pkt.getlayer(ZigbeeAppDataPayload))
        else:
            a = bytes(pkt.getlayer(ZigbeeNWK))

        a = a[:-len(secured_payload)]
        c = secured_payload
        # 5) a)
        result, m = self.__ccm_decrypt_check(key, n_capital, c, a, m_capital)
        if not result:
            auxiliary_header.nwk_seclevel = 0
            return False

        if pkt.haslayer(ZigbeeAppDataPayload):
            pkt.getlayer(ZigbeeAppDataPayload).frame_control &= (~0x02)
            pkt.add_payload(pkt.getlayer(ZigbeeAppDataPayload).guess_payload_class(m)(m))
        else:
            pkt.getlayer(ZigbeeNWK).flags.security = 0
            pkt.add_payload(pkt.getlayer(ZigbeeNWK).guess_payload_class(m)(m))

        auxiliary_header.post_dissect(0)
        return True

    def __key_hash(self, m_capital, key):
        """
        Key hashing as defined in C.6 Keyed Hash Function for Message Authentication of ZigBee specification.

        Args:
            m_capital (byte): a one byte value to be hashed
            key (bytes): the key to be hashed

        Returns:
            Key hashed with the give m_capital byte.
        """
        ipad = bytes.fromhex('36363636363636363636363636363636')
        key1 = self.bytes_xor(key, ipad)
        m_capital1 = bytearray(key1)
        m_capital1.extend(m_capital)
        m_capital1 = bytes(m_capital1)
        hash1 = self.__matyas_meyer_oseas(m_capital1)
        opad = bytes.fromhex('5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C')
        key2 = self.bytes_xor(key, opad)
        m_capital2 = bytearray(key2)
        m_capital2.extend(hash1)
        m_capital2 = bytes(m_capital2)
        hash2 = self.__matyas_meyer_oseas(m_capital2)
        return hash2

    def __matyas_meyer_oseas(self, m_capital):
        """
        Matyas-Meyer-Oseas hashing function as defined in
        B.4 Block-Cipher-Based Cryptographic Hash Function of ZigBee specification.

        Args:
            m_capital (bytes): bytes to hash

        Returns:
            hashed m_capital
        """
        # 1)
        n = 16
        m_capital_len = len(m_capital) * 8
        if m_capital_len < 2 ** n:
            # a)
            m_capital = bytearray(m_capital)
            m_capital.extend(bytes.fromhex('80'))
            while (len(m_capital) * 8) % (8 * n) != 7 * n:
                m_capital.extend(bytes.fromhex('00'))

            m_capital = bytes(m_capital)
            # b)
            m_capital2 = bytearray(m_capital)
            m_capital2.extend(m_capital_len.to_bytes(n // 8, self.ENDIAN))
            m_capital2 = bytes(m_capital2)
        # 2)
        else:
            # a)
            m_capital = bytearray(m_capital)
            m_capital.extend(bytes.fromhex('80'))
            while (len(m_capital) * 8) % (8 * n) != 5 * n:
                m_capital.extend(bytes.fromhex('00'))

            m_capital = bytes(m_capital)
            # b)
            m_capital2 = bytearray(m_capital)
            m_capital2.extend(int(1).to_bytes(2 * n // 8, self.ENDIAN))
            m_capital2.extend(int(0).to_bytes(n // 8, self.ENDIAN))
            m_capital2 = bytes(m_capital2)

        # 3)
        m_capital_arr = []
        for i in range(len(m_capital2) // n):
            m_capital_arr.append(m_capital2[i * 16:(i + 1) * 16])

        # 4)
        hashes = [int(0).to_bytes(n, self.ENDIAN)]
        for i in range(len(m_capital_arr)):
            cipher = AES.new(hashes[i], AES.MODE_ECB)
            hashes.append(self.bytes_xor(cipher.encrypt(m_capital_arr[i]), m_capital_arr[i]))

        return hashes[-1]

    def __input_transformation(self, a, m):
        """
        Input transformation as defined in A.2.1 Input Transformation of ZigBee specification.
        """
        # 1)
        a_len = len(a)
        # a)
        if a_len == 0:
            l_capital = b''  # b)
        elif a_len < 2 ** 16 - 2 ** 8:
            l_capital = a_len.to_bytes(2, self.ENDIAN)  # c)
        elif a_len < 2 ** 32:
            l_capital = bytearray.fromhex('FFFE')
            l_capital.extend(a_len.to_bytes(4, self.ENDIAN))
            l_capital = bytes(l_capital)  # d)
        elif a_len < 2 ** 64:
            l_capital = bytearray.fromhex('FFFF')
            l_capital.extend(a_len.to_bytes(8, self.ENDIAN))
            l_capital = bytes(l_capital)
        else:
            return b''

        # 2)
        l_capital = bytearray(l_capital)
        l_capital.extend(a)
        l_capital = bytes(l_capital)
        # 3)
        add_auth_data = self.add_padding(l_capital)
        # 4)
        plaintext_data = self.add_padding(m)
        # 5)
        auth_data = bytearray(add_auth_data)
        auth_data.extend(plaintext_data)
        return bytes(auth_data)

    def __authentication_transformation(self, auth_data, a, m_capital, n_capital, m, key):
        """
        Input transformation as defined in A.2.2 Authentication Transformation of ZigBee specification.
        """
        # 1)
        flags = 1
        if m_capital > 0:
            flags |= ((m_capital - 2) // 2) << 3

        if len(a) > 0:
            flags |= 1 << 6

        flags = flags.to_bytes(1, self.ENDIAN)
        # 2)
        b_capital = [bytearray(flags)]
        b_capital[0].extend(n_capital)
        b_capital[0].extend(len(m).to_bytes(2, self.ENDIAN))
        b_capital[0] = bytes(b_capital[0])
        # 3)
        for i in range(len(auth_data) // 16):
            b_capital.append(auth_data[i * 16:(i + 1) * 16])

        cipher = AES.new(key, AES.MODE_ECB)
        x_capital = [int(0).to_bytes(16, self.ENDIAN)]
        for i in range(1, len(auth_data) // 16 + 2):
            x_capital.append(cipher.encrypt(self.bytes_xor(x_capital[i - 1], b_capital[i - 1])))

        return x_capital[-1][:m_capital]

    def __ccm_encrypt(self, plaintext_data, t_capital, key, n, m_len, m_capital):
        """
        Input transformation as defined in A.2.3 Encryption Transformation of ZigBee specification.
        """
        # 1)
        flags = bytes.fromhex('01')
        a_capital = []
        for i in range(len(plaintext_data) // 16 + 1):
            a_capital.append(bytearray(flags))
            a_capital[i].extend(n)
            a_capital[i].extend(int(i).to_bytes(2, self.ENDIAN))
            a_capital[i] = bytes(a_capital[i])

        m_capital_arr = []
        for i in range(len(plaintext_data) // 16):
            m_capital_arr.append(plaintext_data[i * 16:(i + 1) * 16])

        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = bytearray()
        for i in range(len(plaintext_data) // 16):
            ciphertext.extend(self.bytes_xor(cipher.encrypt(a_capital[i + 1]), m_capital_arr[i]))

        ciphertext = ciphertext[:m_len]
        s_capital = cipher.encrypt(a_capital[0])
        # 2)
        u_capital = self.bytes_xor(s_capital[:m_capital], t_capital)
        output = bytearray(ciphertext)
        output.extend(u_capital)
        return bytes(output)

    def __ccm_decrypt_check(self, key, n_capital, c, a, m_capital):
        """
        Input transformation as defined in
        A.3 CCM* Mode Decryption and Authentication Checking Transformation of ZigBee specification.
        """
        m, t_capital = self.__ccm_decrypt(key, n_capital, c, m_capital)
        return self.__ccm_check(a, m, n_capital, key, t_capital, m_capital), m

    def __ccm_decrypt(self, key, n_capital, c, m_capital):
        """
        Input transformation as defined in A.3.1 Decryption Transformation of ZigBee specification.
        """
        # 1)
        if m_capital == 0:
            c_capital = c
            u_capital = b''
        else:
            c_capital = c[:-m_capital]
            u_capital = c[-m_capital:]

        # 2)
        ciphertext_data = self.add_padding(c_capital)
        # 3)
        output = self.__ccm_encrypt(ciphertext_data, u_capital, key, n_capital, len(c_capital), m_capital)
        # 4)
        if m_capital == 0:
            m = output
            t_capital = b''
        else:
            m = output[:-m_capital]
            t_capital = output[-m_capital:]
        return m, t_capital

    def __ccm_check(self, a, m, n_capital, key, t_capital, m_capital):
        """
        Input transformation as defined in A.3.2 Authentication Checking Transformation of ZigBee specification.
        """
        # 1)
        auth_data = self.__input_transformation(a, m)
        # 2)
        mac_tag = self.__authentication_transformation(auth_data, a, m_capital, n_capital, m, key)
        # 3)
        return mac_tag == t_capital

    # 4.5.2.2 CCM Nonce
    @staticmethod
    def __ccm_nonce(source_address, frame_counter, security_control):
        """
        Construct CCM* nonce.

        Args:
            source_address (bytes): source address to use
            frame_counter (bytes): frame counter to use
            security_control (bytes): security control field from the security header

        Returns:
            nonce to be used with CCM* mode
        """
        nonce = bytearray(source_address[::-1])
        nonce.extend(frame_counter[::-1])
        nonce.extend(security_control[::-1])
        return bytes(nonce)

    @staticmethod
    def add_padding(x):
        """
        Pads input with zeroes so that the length is divisible by 16

        Args:
            x (bytes): bytes to pad

        Returns:
            padded bytes
        """
        if len(x) % 16 == 0:
            return x

        return x.ljust((len(x) // 16 + 1) * 16, b'\0')

    @staticmethod
    def bytes_xor(a, b):
        """
        XORs 2 byte strings.

        Args:
            a, b (bytes, bytes): byte strings to XOR

        Returns:
            a XOR b
        """
        return bytes(x ^ y for x, y in zip(a, b))
