# Demo GIF for the README. Regenerate with `make demo` (needs vhs, ttyd, ffmpeg).
Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1500
Set Height 860
Set Padding 16
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PATH=$PWD/bin:$PATH NO_COLOR= && chmod 600 examples/hardened-node/secrets.toml && clear"
Enter
Show

Type "oraclint rules list | head -12"
Enter
Sleep 3s

Type "clear && oraclint scan --min-severity high examples/insecure-node"
Enter
Sleep 6s

Type "clear && oraclint rules explain NS-DKR-001 | head -20"
Enter
Sleep 4s

Type "clear && oraclint scan --experimental examples/hardened-node"
Enter
Sleep 3s
