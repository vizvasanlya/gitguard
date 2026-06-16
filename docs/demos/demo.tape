# GitGuard Demo Tape

# Run with: vhs demo.tape
# Install VHS: go install github.com/charmbracelet/vhs@latest

output demo.gif

set font-size 20
set theme Monokai Extended
set width 120
set height 30

type "pip install gitguard"
enter

sleep 2s

type "gitguard scan ."
enter

sleep 4s

type "gitguard fix ."
enter

sleep 3s

type "gitguard explain SEC001"
enter

sleep 3s

type "gitguard history ."
enter

sleep 3s

type "gitguard ai-providers"
enter

sleep 2s

type "gitguard sbom ."
enter

sleep 2s
