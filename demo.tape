# demo.tape — scripted terminal recording for Hardcoded-Key-Decryptor
#
# Generates .github/demo.gif deterministically (no manual recording).
#
# Prerequisites:
#   1. Install vhs:  https://github.com/charmbracelet/vhs
#   2. Install the runtime dependency so the tool can run:
#        pip install -r requirements.txt
#
# Then, from the repo root:
#   vhs demo.tape
#
# Tip: if `python` is not on your PATH, replace it below with `python3`
# (or the full path to a virtualenv's python).

Output .github/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 760
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

# --- hidden setup: silence the single-key-DES deprecation warning, clear screen ---
Hide
Type "export PYTHONWARNINGS=ignore"
Enter
Type "clear"
Enter
Show

Sleep 500ms

Type "# 1) List the key profiles in keys.json"
Enter
Sleep 400ms
Type "python hardcoded_key_decryptor.py --list"
Enter
Sleep 2s

Type "# 2) Encrypt a secret with a DES key + IV (no profile needed)"
Enter
Sleep 400ms
Type 'python hardcoded_key_decryptor.py -e "RiverDragon#Storm25" --key "B4 3F 84 D1 10 B4 E9 91" --iv "01 D8 AE E6 49 AD 92 27"'
Enter
Sleep 2500ms

Type "# 3) Decrypt the base64 back to plaintext with the same key/IV"
Enter
Sleep 400ms
Type 'python hardcoded_key_decryptor.py -d "66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby" --key "B4 3F 84 D1 10 B4 E9 91" --iv "01 D8 AE E6 49 AD 92 27"'
Enter
Sleep 3s
