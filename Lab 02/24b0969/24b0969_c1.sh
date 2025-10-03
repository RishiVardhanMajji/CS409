openssl enc -aes-128-cbc -d \
  -in ciphertext.bin \
  -K "$(cat key.hex | tr -d '\n')" \
  -iv "$(cat iv.hex | tr -d '\n')" \
  -out -


#cs409{op3n551_2_d3crypt10n_1_4m}
