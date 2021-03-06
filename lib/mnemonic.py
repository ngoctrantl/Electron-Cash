#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Electron Cash - lightweight Bitcoin Cash client
# Copyright (C) 2020 The Electron Cash Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import binascii
import ecdsa
import hashlib
import hmac
import math
import os
import pkgutil
import string
import unicodedata

from typing import List, Optional, Tuple, Union

from . import version
from .bitcoin import is_old_seed, is_new_seed, sha256
from .util import PrintError

# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html
CJK_INTERVALS = [
    (0x4E00, 0x9FFF, 'CJK Unified Ideographs'),
    (0x3400, 0x4DBF, 'CJK Unified Ideographs Extension A'),
    (0x20000, 0x2A6DF, 'CJK Unified Ideographs Extension B'),
    (0x2A700, 0x2B73F, 'CJK Unified Ideographs Extension C'),
    (0x2B740, 0x2B81F, 'CJK Unified Ideographs Extension D'),
    (0xF900, 0xFAFF, 'CJK Compatibility Ideographs'),
    (0x2F800, 0x2FA1D, 'CJK Compatibility Ideographs Supplement'),
    (0x3190, 0x319F , 'Kanbun'),
    (0x2E80, 0x2EFF, 'CJK Radicals Supplement'),
    (0x2F00, 0x2FDF, 'CJK Radicals'),
    (0x31C0, 0x31EF, 'CJK Strokes'),
    (0x2FF0, 0x2FFF, 'Ideographic Description Characters'),
    (0xE0100, 0xE01EF, 'Variation Selectors Supplement'),
    (0x3100, 0x312F, 'Bopomofo'),
    (0x31A0, 0x31BF, 'Bopomofo Extended'),
    (0xFF00, 0xFFEF, 'Halfwidth and Fullwidth Forms'),
    (0x3040, 0x309F, 'Hiragana'),
    (0x30A0, 0x30FF, 'Katakana'),
    (0x31F0, 0x31FF, 'Katakana Phonetic Extensions'),
    (0x1B000, 0x1B0FF, 'Kana Supplement'),
    (0xAC00, 0xD7AF, 'Hangul Syllables'),
    (0x1100, 0x11FF, 'Hangul Jamo'),
    (0xA960, 0xA97F, 'Hangul Jamo Extended A'),
    (0xD7B0, 0xD7FF, 'Hangul Jamo Extended B'),
    (0x3130, 0x318F, 'Hangul Compatibility Jamo'),
    (0xA4D0, 0xA4FF, 'Lisu'),
    (0x16F00, 0x16F9F, 'Miao'),
    (0xA000, 0xA48F, 'Yi Syllables'),
    (0xA490, 0xA4CF, 'Yi Radicals'),
]

def is_CJK(c) -> bool:
    n = ord(c)
    for imin,imax,name in CJK_INTERVALS:
        if n>=imin and n<=imax: return True
    return False


def normalize_text(seed: str) -> str:
    # normalize
    seed = unicodedata.normalize('NFKD', seed)
    # lower
    seed = seed.lower()
    # remove accents
    seed = u''.join([c for c in seed if not unicodedata.combining(c)])
    # normalize whitespaces
    seed = u' '.join(seed.split())
    # remove whitespaces between CJK
    seed = u''.join([seed[i] for i in range(len(seed)) if not (seed[i] in string.whitespace and is_CJK(seed[i-1]) and is_CJK(seed[i+1]))])
    return seed

def load_wordlist(filename: str) -> List[str]:
    data = pkgutil.get_data(__name__, os.path.join('wordlist', filename))
    s = data.decode('utf-8').strip()
    s = unicodedata.normalize('NFKD', s)
    lines = s.split('\n')
    wordlist = []
    for line in lines:
        line = line.split('#')[0]
        line = line.strip(' \r')
        assert ' ' not in line
        if line:
            wordlist.append(normalize_text(line))
    return wordlist


filenames = {
    'en':'english.txt',
    'es':'spanish.txt',
    'ja':'japanese.txt',
    'pt':'portuguese.txt',
    'zh':'chinese_simplified.txt'
}

class MnemonicBase(PrintError):
    """ Base class for both Mnemonic (BIP39-based) and Mnemonic_Electrum.
    They both use the same word list, so the commonality between them is
    captured in this class. """
    def __init__(self, lang=None):
        lang = lang or 'en'
        self.print_error('language', lang)
        filename = filenames.get(lang[:2], 'english.txt')
        self.wordlist = load_wordlist(filename)
        self.wordlist_indices = dict()
        for i, word in enumerate(self.wordlist):
            self.wordlist_indices[word] = i  # saves on O(N) lookups for words. The alternative is to call worlist.index(w) for each word which is slow.
        assert len(self.wordlist) == len(self.wordlist_indices)  # Paranoia to ensure word list is composed of unique words.
        self.print_error("wordlist has %d words"%len(self.wordlist))

    def get_suggestions(self, prefix):
        for w in self.wordlist:
            if w.startswith(prefix):
                yield w

    @classmethod
    def list_languages(cls):
        return list(filenames.keys())

    @classmethod
    def normalize_text(cls, txt: Union[str, bytes]) -> str:
        if isinstance(txt, bytes):
            txt = txt.decode('utf8')
        elif not isinstance(txt, str):  # noqa: F821
            raise TypeError("String value expected")

        return normalize_text(txt)

    @classmethod
    def detect_language(cls, code):
        code = cls.normalize_text(code)
        first = code.split(' ')[0]
        languages = cls.list_languages()

        for lang in languages:
            mnemo = cls(lang)
            if first in mnemo.wordlist:
                return lang

        raise Exception("Language not detected")

    def mnemonic_encode(self, i):
        n = len(self.wordlist)
        words = []
        while i:
            x = i%n
            i = i//n
            words.append(self.wordlist[x])
        return ' '.join(words)

    def mnemonic_decode(self, seed):
        n = len(self.wordlist)
        words = seed.split()
        i = 0
        while words:
            w = words.pop()
            k = self.wordlist.index(w)
            i = i*n + k
        return i

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, passphrase: Optional[str]) -> bytes:
        raise NotImplementedError(f'mnemonic_to_seed is not implemented in {cls.__name__}')

    def make_seed(self, seed_type=None, num_bits=128, custom_entropy=1) -> str:
        raise NotImplementedError(f'make_seed is not implemented in {type(self).__name__}')

    @classmethod
    def is_checksum_valid(cls, mnemonic : str, lang : Optional[str] = None) -> Tuple[bool, bool]:
        raise NotImplementedError(f'is_checksum_valid is not implemented in {cls.__name__}')

    @classmethod
    def is_wordlist_valid(cls, mnemonic: str, lang: Optional[str] = None) -> Tuple[bool, str]:
        """ Returns (True, lang) if the passed-in `mnemonic` phrase has all its
        words found in the wordlist for `lang`. Pass in a None value for `lang`
        to auto-detect language. The fallback language is always "en".

        If the `mnemonic` contains any word not in the wordlist for `lang`,
        returns (False, lang) if lang was specified or (False, "en") if it was
        not. """
        if lang is None:
            try:
                lang = cls.detect_language(mnemonic)
            except:
                lang = 'en'
        elif lang not in cls.list_languages():
            lang = 'en'
        words = cls.normalize_text(mnemonic).split()
        wordlist_indices = cls(lang).wordlist_indices
        while words:
            w = words.pop()
            try:
                wordlist_indices[w]
            except KeyError:
                return False, lang
        return True, lang


class Mnemonic(MnemonicBase):
    """ Implements seed derivation following BIP39, which is now the Electron
    Cash default. The previous 'Electrum' seedformat is provided by the
    Mnemonic_Electrum class later in this file.

    BIP39 uses a wordlist-dependent checksum. Because of this we should always
    accept seeds that fail checksum otherwise users will not always be able to
    restore their seeds."""

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, passphrase: Optional[str]) -> bytes:
        PBKDF2_ROUNDS = 2048
        mnemonic = cls.normalize_text(mnemonic)
        passphrase = cls.normalize_text(passphrase or '')
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'mnemonic' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)

    def make_seed(self, seed_type=None, num_bits=128, custom_entropy=1) ->str:
        if num_bits not in (128, 160, 192, 224, 256):
            raise ValueError('Strength should be one of the following [128, 160, 192, 224, 256], not %d.' % num_bits)
        data = os.urandom(num_bits // 8)
        h = hashlib.sha256(data).hexdigest()
        b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + bin(int(h, 16))[2:].zfill(256)[:len(data) * 8 // 32]
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11:(i + 1) * 11], 2)
            result.append(self.wordlist[idx])
        if self.detect_language(' '.join(result)) == 'japanese':  # Japanese must be joined by ideographic space.
            result_phrase = u'\u3000'.join(result)
        else:
            result_phrase = ' '.join(result)
        return result_phrase

    @classmethod
    def is_checksum_valid(cls, mnemonic : str, lang : Optional[str] = None) -> Tuple[bool, bool]:
        """Test checksum of bip39 mnemonic for lang, assuming English wordlist if
        lang = None. Returns tuple (is_checksum_valid, is_wordlist_valid) """
        if lang is None:
            lang = 'en'
        words = cls.normalize_text(mnemonic).split()
        words_len = len(words)
        worddict = cls(lang).wordlist_indices
        n = len(worddict)
        i = 0
        words.reverse()
        while words:
            w = words.pop()
            try:
                k = worddict[w]
            except KeyError:
                return False, False
            i = i*n + k
        if words_len not in (12, 15, 18, 21, 24):
            return False, True
        checksum_length = 11 * words_len // 33  # num bits
        entropy_length = 32 * checksum_length  # num bits
        entropy = i >> checksum_length
        checksum = i % 2**checksum_length
        entropy_bytes = int.to_bytes(entropy, length=entropy_length//8, byteorder="big")
        hashed = int.from_bytes(sha256(entropy_bytes), byteorder="big")
        calculated_checksum = hashed >> (256 - checksum_length)
        return checksum == calculated_checksum, True


class Mnemonic_Electrum(MnemonicBase):
    """ This implements the "Electrum" mnemonic seed phrase format, which was
    used for many years, but starting in 2020, Electron Cash switched back to
    BIP39 since it has wider support.

    The Electrum seed phrase format uses a hash based checksum of the normalized
    text data, instead of a wordlist-dependent checksum. """

    @classmethod
    def mnemonic_to_seed(cls, mnemonic, passphrase):
        """ Electrum format """
        PBKDF2_ROUNDS = 2048
        mnemonic = cls.normalize_text(mnemonic)
        passphrase = cls.normalize_text(passphrase or '')
        return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'electrum' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)

    def make_seed(self, seed_type=None, num_bits=132, custom_entropy=1):
        """ Electrum format """
        if seed_type is None:
            seed_type = 'standard'
        prefix = version.seed_prefix(seed_type)
        # increase num_bits in order to obtain a uniform distibution for the last word
        bpw = math.log(len(self.wordlist), 2)
        num_bits = int(math.ceil(num_bits/bpw) * bpw)
        # handle custom entropy; make sure we add at least 16 bits
        n_custom = int(math.ceil(math.log(custom_entropy, 2)))
        n = max(16, num_bits - n_custom)
        self.print_error("make_seed", prefix, "adding %d bits"%n)
        my_entropy = 1
        while my_entropy < pow(2, n - bpw):
            # try again if seed would not contain enough words
            my_entropy = ecdsa.util.randrange(pow(2, n))
        nonce = 0
        while True:
            nonce += 1
            i = custom_entropy * (my_entropy + nonce)
            seed = self.mnemonic_encode(i)
            assert i == self.mnemonic_decode(seed)
            if is_old_seed(seed):
                continue
            if is_new_seed(seed, prefix):
                break
        self.print_error('%d words'%len(seed.split()))
        return seed

    def check_seed(self, seed: str, custom_entropy: int) -> bool:
        assert is_new_seed(seed)
        i = self.mnemonic_decode(seed)
        return i % custom_entropy == 0

    @classmethod
    def is_checksum_valid(cls, mnemonic : str, lang : Optional[str] = None, *, prefix=version.SEED_PREFIX) -> Tuple[bool, bool]:
        if lang is None:
            lang = 'en'
        is_valid_words, lang = cls.is_wordlist_valid(mnemonic)
        return is_new_seed(mnemonic, prefix), is_valid_words
