# The README demo: `just demo` records it into dist/demo.gif (and a text transcript beside it).
# It runs the real bento in the demo's own dirs ($DEMO_DIR, set by the recipe).

Output dist/demo.gif
Output dist/demo.txt

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme { "name": "mono", "black": "#1a1a1a", "red": "#d0d0d0", "green": "#e8e8e8", "yellow": "#d0d0d0", "blue": "#c0c0c0", "magenta": "#d0d0d0", "cyan": "#c8c8c8", "white": "#e8e8e8", "brightBlack": "#808080", "brightRed": "#ffffff", "brightGreen": "#ffffff", "brightYellow": "#ffffff", "brightBlue": "#ffffff", "brightMagenta": "#ffffff", "brightCyan": "#ffffff", "brightWhite": "#ffffff", "background": "#111111", "foreground": "#e8e8e8", "selection": "#444444", "cursor": "#e8e8e8" }
Set TypingSpeed 25ms

Hide
Type `cd "$DEMO_DIR/bento-demo" && export PS1='bento-demo $ '` Enter
Type "clear" Enter
Sleep 500ms
Show

Type "bento secret set anthropic --sandbox claude-bento-demo" Enter
Wait@30s /input hidden/
Sleep 200ms
Type "sk-ant-demo-not-a-real-key" Enter
Wait@30s /^bento-demo \$\s*$/
Sleep 600ms

Type "bento run claude" Enter
Wait+Screen@60s /Choice \[2\]/
Sleep 600ms
Type "2" Enter
# Claude draws its own screen, which Wait can't read: wait on bento's last line, then give it time.
Wait+Screen@5m /Created sandbox/
Sleep 8s
Ctrl+C
Sleep 300ms
Ctrl+C
Wait@60s /^bento-demo \$\s*$/
Sleep 600ms

Type "bento exec claude-bento-demo env | grep -i anthropic" Enter
Wait@2m /^bento-demo \$\s*$/
Sleep 3s
