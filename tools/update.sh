new_file=$(ls -t ~/pwn/.target | sed -n "1p")
chmod a+x ~/pwn/.target/$new_file
sed -i "s/target.*.\"/target\/$new_file\"/g" ~/pwn/main.py
echo "main.py updated."
