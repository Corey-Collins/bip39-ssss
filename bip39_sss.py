from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39WordsNum,
    Bip39MnemonicDecoder,
    Bip39Mnemonic,
    Bip39MnemonicValidator,
)
from secretsharing import SecretSharer
from typing import Dict, Union

generator = Bip39MnemonicGenerator()
decoder = Bip39MnemonicDecoder()
validator = Bip39MnemonicValidator()


def create_mnemonic(wordsNum: Union[int, Bip39WordsNum]):
    return Bip39MnemonicGenerator().FromWordsNumber(wordsNum)


def mnemonic_to_shares(
    mnemonic: Union[Bip39Mnemonic, str], share_threshold: int, num_shares: int
) -> Dict[int, Bip39Mnemonic]:
    if type(mnemonic) is str:
        mnemonic = Bip39Mnemonic.FromString(mnemonic)
    validator.Validate(mnemonic)
    mnemonic_bytes = decoder.Decode(mnemonic)
    mnemonic_hex = mnemonic_bytes.hex()
    shares = SecretSharer.split_secret(mnemonic_hex, share_threshold, num_shares)
    share_mnemonics = {}
    for index, share in enumerate(shares):
        share_hex = share.split("-")[-1]
        if len(share_hex) % 2 != 0:
            share_hex = "0" + share_hex
        share_bytes = bytes.fromhex(share_hex)
        share_mnemonic = generator.FromEntropy(share_bytes)
        share_mnemonics[index + 1] = share_mnemonic
    return share_mnemonics


def shares_to_mnemonic(shares: Dict[int, Union[Bip39Mnemonic, str]]) -> Bip39Mnemonic:
    shares_list = []
    for share_num, share in shares.items():
        share_bytes = decoder.Decode(share)
        share_hex = share_bytes.hex()
        share_str = f"{share_num}-{share_hex}"
        shares_list.append(share_str)
    mnemonic_hex = SecretSharer.recover_secret(shares_list)
    mnemonic_bytes = bytes.fromhex(mnemonic_hex)
    mnemonic = generator.FromEntropy(mnemonic_bytes)
    return mnemonic


def run_console_app():
    print("Enter an option:\n1) Create shares\n2) Reconstruct secret")
    option = int(input())
    print("\nEnter mnemonic length (Options: 12, 15, 18, 21, 24 [default]):")
    mnemonic_length_input = input()
    mnemonic_length = 24
    if mnemonic_length_input != "":
        mnemonic_length = Bip39WordsNum(int(mnemonic_length_input))
    if option == 1:
        print("\n1) Create mnemonic\n2) Enter existing mnemonic")
        mnemonic_option = int(input())
        mnemonic = None
        if mnemonic_option == 1:
            mnemonic = create_mnemonic(mnemonic_length)
        elif mnemonic_option == 2:
            print(f"\nEnter {mnemonic_length} word mnemonic:")
            mnemonic_words = []
            for i in range(mnemonic_length):
                while True:
                    print(f"\nEnter word #{i+1}:")
                    input_word = input()
                    if input_word.isalpha():
                        mnemonic_words.append(input_word)
                        break
                    else:
                        print("\nWord must be within [A-Za-z]")
            mnemonic = Bip39Mnemonic(mnemonic_words)
            validator.Validate(mnemonic)
            print(f"\nRe-enter to confirm mnemonic:")
            for i in range(mnemonic_length):
                while True:
                    print(f"\nEnter word #{i+1}:")
                    confirmation_word = input()
                    if confirmation_word == mnemonic_words[i]:
                        break
                    print("\nWord does not match. Try again:")
        print(f"\nMnemonic:\n{mnemonic}")
        print("\nEnter total shares")
        shares_total = int(input())
        while True:
            print("\nEnter shares threshold:")
            shares_threshold = int(input())
            if shares_threshold >= 2:
                if shares_threshold < shares_total:
                    break
                else:
                    print(f"Threshold must be < shares total of {shares_total}")
            else:
                print("Threshold must be >= 2")
        shares = mnemonic_to_shares(mnemonic, shares_threshold, shares_total)
        print("\nrecord shares:\n")
        for share_num, share_mnemonic in shares.items():
            print(f"{share_num}) {share_mnemonic}\n")
        print("\nPress ENTER to continue:")
        input()
        for share_num, share_mnemonic in shares.items():
            share_mnemonic_words = share_mnemonic.ToList()
            for index, word in enumerate(share_mnemonic_words):
                while True:
                    print(f"\nConfirm share {share_num} word {index+1}:")
                    confirm_word = input()
                    if confirm_word == share_mnemonic_words[index]:
                        break
                    print("f\n\nWrong word, try again.")
            print(f"\nShare {share_num} confirmed!")
        print("Shares confirmed. Keep them safe!!")
    elif option == 2:
        print("\nHow many shares do you have?")
        total_shares = int(input())
        mnemonic_shares = {}
        for share_num in range(total_shares):
            print("\nWhat share number are you entering in?")
            input_share_num = int(input())
            mnemonic_words = []
            for i in range(mnemonic_length):
                while True:
                    print(f"\nEnter word #{i+1}:")
                    input_word = input()
                    if input_word.isalpha():
                        mnemonic_words.append(input_word)
                        break
                    else:
                        print("\nWord must be within [A-Za-z]")
            mnemonic = Bip39Mnemonic(mnemonic_words)
            validator.Validate(mnemonic)
            print(f"\nRe-enter to confirm mnemonic share #{input_share_num}:")
            for i in range(mnemonic_length):
                while True:
                    print(f"\nEnter word #{i+1}:")
                    confirmation_word = input()
                    if confirmation_word == mnemonic_words[i]:
                        break
                    print("\nWord does not match. Try again:")
            mnemonic_shares[input_share_num] = mnemonic
            print(f"\nMnemonic share entered:\n{input_share_num}-{mnemonic}")
        print(f"\nReview mnemonic shares:\n")
        for share_num, mnemonic in mnemonic_shares.items():
            print(f"{share_num}-{mnemonic}")
        print("\nPress ENTER to continue:")
        input()
        mnemonic = shares_to_mnemonic(mnemonic_shares)
        print(f"\nThe secret mnemonic is:\n\n{mnemonic}")
        print("\nRecord the mnemonic and press ENTER to confirm:")
        input()
        for index, word in enumerate(mnemonic.ToList()):
            while True:
                print(f"\nEnter word #{index+1}:")
                confirmation_word = input()
                if confirmation_word == word:
                    break
                print("\nWord does not match. Try again:")
        print("\nYou're good! Keep it secret!!")


if __name__ == "__main__":
    run_console_app()
