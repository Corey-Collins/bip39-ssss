from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39WordsNum,
    Bip39MnemonicDecoder,
    Bip39Mnemonic,
    Bip39MnemonicValidator,
)
from bip_utils.bip.bip39.bip39_mnemonic import Bip39MnemonicConst
from ssss import make_random_shares, recover_secret
from typing import Union, List, Tuple


generator = Bip39MnemonicGenerator()
decoder = Bip39MnemonicDecoder()
validator = Bip39MnemonicValidator()


def create_mnemonic(wordsNum: Union[int, Bip39WordsNum]):
    return Bip39MnemonicGenerator().FromWordsNumber(wordsNum)


def mnemonic_to_shares(
    mnemonic: Union[Bip39Mnemonic, str], share_threshold: int, num_shares: int
) -> List[Tuple[int, Bip39Mnemonic]]:
    if isinstance(mnemonic, str):
        mnemonic = Bip39Mnemonic.FromString(mnemonic)
    validator.Validate(mnemonic)
    mnemonic_bytes = decoder.Decode(mnemonic)
    mnemonic_hex = mnemonic_bytes.hex()
    mnemonic_entropy_len = mnemonic_len_to_entropy_bit_len(mnemonic.WordsCount())
    dec_shares = make_random_shares(
        int(mnemonic_hex, 16),
        share_threshold,
        num_shares,
        prime=(2 ** mnemonic_entropy_len - 1),
    )
    mnemonic_shares = []
    for share_num, share_dec in dec_shares:
        share_hex = safe_pad_hex(format(share_dec, "x"), mnemonic.WordsCount())
        share_bytes = bytes.fromhex(share_hex)
        share_mnemonic = generator.FromEntropy(share_bytes)
        mnemonic_shares.append((share_num, share_mnemonic))
    return mnemonic_shares


def shares_to_mnemonic(
    mnemonic_shares: List[Tuple[int, Union[Bip39Mnemonic, str]]]
) -> Bip39Mnemonic:
    dec_shares = []
    mnemonic_entropy_len = 0
    mnemonic_len = 0
    for index, (share_num, share_mnemonic) in enumerate(mnemonic_shares):
        if isinstance(share_mnemonic, str):
            share_mnemonic = Bip39Mnemonic.FromString(share_mnemonic)
        if index == 0:
            mnemonic_entropy_len = mnemonic_len_to_entropy_bit_len(
                share_mnemonic.WordsCount()
            )
            mnemonic_len = share_mnemonic.WordsCount()
        share_bytes = decoder.Decode(share_mnemonic)
        share_hex = share_bytes.hex()
        share_dec = int(share_hex, 16)
        dec_shares.append((share_num, share_dec))
    secret_dec = recover_secret(dec_shares, prime=(2 ** mnemonic_entropy_len - 1))
    secret_hex = safe_pad_hex(format(secret_dec, "x"), mnemonic_len)
    secret_bytes = bytes.fromhex(secret_hex)
    secret_mnemonic = generator.FromEntropy(secret_bytes)
    return secret_mnemonic


def safe_pad_hex(hex: str, mnemonic_len: Bip39WordsNum) -> str:
    entropy_bit_len = mnemonic_len_to_entropy_bit_len(mnemonic_len)
    entropy_hex_len = int(entropy_bit_len / 4)
    if len(hex) < entropy_hex_len:
        hex = ("0" * (entropy_hex_len - len(hex))) + hex
    return hex


def mnemonic_len_to_entropy_bit_len(mnemonic_len: Bip39WordsNum):
    return (mnemonic_len * Bip39MnemonicConst.WORD_BIT_LEN) - (mnemonic_len // 3)


def create_and_confirm(
    mnemonic_len: Bip39WordsNum = Bip39WordsNum.WORDS_NUM_24, verbose: bool = False
):
    mnemonic = create_mnemonic(mnemonic_len)
    shares = mnemonic_to_shares(mnemonic, 2, 3)
    if verbose:
        print(mnemonic)
        print()
        for share_num, share_mnemonic in shares:
            print(share_num, share_mnemonic)
        print()
    for share_num, share_mnemonic in shares:
        share_mnemonic_len = share_mnemonic.WordsCount()
        if share_mnemonic_len != mnemonic_len:
            print(
                f"share #{share_num} length is {share_mnemonic_len} and not {mnemonic_len}"
            )
            return False
    possibilities = [[0, 1], [1, 2], [2, 0]]
    for possibility in possibilities:
        shares_input = [shares[possibility[0]], shares[possibility[1]]]
        reconstructed_mnemonic = shares_to_mnemonic(shares_input)
        if verbose:
            print(f"from {shares[possibility[0]][0]} and {shares[possibility[1]][0]}")
            print(shares[possibility[0]][1])
            print(shares[possibility[1]][1])
            print()
            print(reconstructed_mnemonic)
            print()
        if reconstructed_mnemonic.ToStr() != mnemonic.ToStr():
            print(f"{reconstructed_mnemonic.ToStr()} != {mnemonic.ToStr()}")
            return False
    return True


if __name__ == "__main__":
    while True:
        print("Enter an option:\n1) Create mnemonic shares\n2) Recover secret mnemonic")
        try:
            choice = int(input())
        except Exception as e:
            print(f"\n{e}\n")
            continue
        if choice == 1:
            print(
                "\nEnter an option:\n1) Create new secret mnemonic\n2) Enter existing secret mnemonic"
            )
            choice = int(input())
            if choice == 1:
                while True:
                    print("\nEnter mnemonic length: [12, 15, 18, 21, 24 (default)]")
                    try:
                        choice = input()
                        choice = 24 if choice == "" else int(choice)
                        mnemonic = create_mnemonic(choice)
                        break
                    except Exception as e:
                        print(f"\n{e}")
            elif choice == 2:
                print("\nEnter existing mnemonic:")
                while True:
                    try:
                        mnemonic = Bip39Mnemonic.FromString(input())
                        validator.Validate(mnemonic)
                        break
                    except Exception as e:
                        print(f"\n{e}")
            while True:
                print("\nEnter total mnemonic shares to create:")
                shares_total = int(input())
                if shares_total > 2:
                    break
                print("\nShares must be 3 or more")
            while True:
                print("\nEnter shares needed to recover secret:")
                shares_threshold = int(input())
                if shares_threshold < 2:
                    print("\nYou'll need 2 or more shares to recover the secret")
                    continue
                if shares_threshold > shares_total:
                    print(
                        "\nYou can't require more shares than shares available to recover the secret"
                    )
                    continue
                try:
                    shares = mnemonic_to_shares(
                        mnemonic, shares_threshold, shares_total
                    )
                    break
                except Exception as e:
                    print(f"\n{e}")
            print(
                f"\n\nYour {mnemonic.WordsCount()} word secret mnemonic:\n\n{mnemonic.ToStr()}"
            )
            print(
                f"\nShares created, any {shares_threshold} of {shares_total} are needed to recover secret:\n"
            )
            for share_num, mnemonic_share in shares:
                print(f"{share_num}) {mnemonic_share}")
            print("\nRecord them carefully, including the share number!")
        elif choice == 2:
            while True:
                print("\nHow many shares do you have?")
                try:
                    shares_total = int(input())
                    if shares_total > 1:
                        break
                except Exception as e:
                    print(f"\n{e}")
                    continue
                print("\nYou'll need at least 2 shares to recover the secret")
            share_nums = set()
            mnemonic_len = None
            shares = []
            for i in range(shares_total):
                while True:
                    print(
                        f"\nEntering share {i+1} of {shares_total}\nWhich share number is this?"
                    )
                    try:
                        share_num = int(input())
                        if share_num > 0:
                            if share_num not in share_nums:
                                share_nums.add(share_num)
                                break
                            else:
                                print(
                                    f"\nShare number {share_num} has already been entered"
                                )
                                continue
                        else:
                            print("\nShare number must at least be 1")
                    except Exception as e:
                        print(f"\n{e}")
                while True:
                    print(f"\nEnter mnemonic for share number {share_num}:")
                    try:
                        mnemonic = Bip39Mnemonic.FromString(input())
                        validator.Validate(mnemonic)
                        if not mnemonic_len:
                            mnemonic_len = mnemonic.WordsCount()
                        elif mnemonic.WordsCount() != mnemonic_len:
                            print(
                                f"\n{mnemonic.WordsCount()} word mnemonic entered does not match the length of previous {mnemonic_len} word mnemonic given"
                            )
                            continue
                    except Exception as e:
                        print(f"\n{e}")
                        continue
                    break
                shares.append((share_num, mnemonic))
            secret_mnemonic = shares_to_mnemonic(shares)
            print("\n\nUsing mnemonic shares:\n")
            for share_num, share_mnemonic in shares:
                print(f"{share_num}) {share_mnemonic}")
            print(
                f"\nSecret recovered:\n\n{secret_mnemonic.ToStr()}\n\nKeep it secret!"
            )
        else:
            print("\nInvalid option\n")
            continue
        break
