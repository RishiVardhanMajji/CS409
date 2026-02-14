KEY=$(cat key.hex)
IV=$(cat iv.hex)

MAC1=$(openssl mac -digest SHA256 -macopt hexkey:$KEY -in message.txt HMAC | tr -d '\n' | tr '[:lower:]' '[:upper:]')

MAC2=$(openssl mac -cipher AES-128-CBC -macopt hexkey:$KEY -in message.txt CMAC | tr -d '\n' | tr '[:lower:]' '[:upper:]')

MAC3=$(openssl mac -cipher AES-128-GCM -macopt hexiv:$IV -macopt hexkey:$KEY -in message.txt GMAC | tr -d '\n' | tr '[:lower:]' '[:upper:]')

printf 'cs409{%s_%s_%s}\n' "$MAC1" "$MAC2" "$MAC3"