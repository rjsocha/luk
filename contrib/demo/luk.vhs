hide
  # Recorded from the root of the repository:
  #   asciinema-vhs record contrib/demo/luk.vhs --cols 120 --rows 30 --title "luk"
  # Nothing runs for real: every command is typed, its output comes from
  # contrib/demo/render (captured from luk and lukd, hosts rewritten).
  demo=contrib/demo
  prompt '$ '
  speed 45ms
show
vhs-start
style splash bold white on "#1e3a5f"
style frame bright-cyan
effect dissolve 800ms
splash "luk + lukd"
splash "SSH-Authenticated Storage Server"
splash ""
splash "Send files with the SSH key or certificate you already have:"
splash "no accounts, no passwords, no tokens to rotate."
splash ""
splash "lukd takes them in and runs your pipelines: store, encrypt, relay,"
splash "run your jobs as other users, keep backups per host, hand out links."
splash ""
splash "Uploads travel in an end-to-end encrypted channel pinned to the key of lukd,"
splash "over HTTP, HTTPS or any proxy in between."
splash --show 8s
effect left 450ms

chapter "Trust the server"
type -n 'luk scan --pin https://drop.example.com/drop'
run "cat $demo/render/scan.txt"
pause 500ms
note "The pin is the key of lukd, not of TLS: the same over HTTP, HTTPS or a proxy" 5s
pause 4s
type -n "luk config endpoint add -e drop --url 'https://drop.example.com/drop#bimur-gumut-bojir-jufid-tazig-zugos'"
run 'true'
pause 1500ms

effect dissolve 400ms
splash "Uploads in parts"
splash ""
splash "luk opens an encrypted channel to lukd and signs the upload with your SSH key."
splash "The file goes in parts, several at once; a part that stalls or breaks"
splash "is sent again on its own. Proxies in between only see short requests."
splash --show --alt 11s

effect left 450ms
chapter "Send in parts"
type -n 'luk send -e drop --file backup.tar --parallel 4 --progress'
run "$demo/progress"
pause 500ms
note "End-to-end encrypted channel; four parts at once, each retried on its own" 5s
pause 6s
type -n "echo 'deploy token' | luk send -e drop --stdin --ttl 1h"
run "cat $demo/render/stdin.txt"
pause 500ms
note "A pipe works too: the stream goes in parts, the link expires in an hour" 5s
pause 5s
effect dissolve 400ms
splash "Secrets and private files"
splash ""
splash "--secret: a reveal page, kept in RAM, shown once. A convenience, not a vault."
splash "--private --any: only keys of the team fetch it; the link alone is not enough."
splash --show --alt 9s
effect left 450ms
chapter "Secrets and private files"
type -n 'luk send -e drop --secret --once --ttl 1h'
run "$demo/secret"
pause 500ms
note "A secret typed twice, masked: kept in RAM, shown once on a reveal page, then gone" 6s
pause 7s
note "Not a secure channel for secrets, a convenience: share real secrets encrypted" 5s
pause 6s
type -n 'luk send -e drop --file report.pdf --private --any'
run "cat $demo/render/private.txt"
pause 500ms
note "Private to the team: only keys of the allow list fetch it, the link alone is not enough" 6s
pause 7s

effect dissolve 400ms
splash "Links"
splash ""
splash "An upload can answer with a link that expires by itself."
splash "The link stays yours: list it, change its lifetime, replace or remove it."
splash --show --alt 8s
effect left 450ms
chapter "Links"
type -n 'luk link ls -e drop'
run "cat $demo/render/linkls.txt"
pause 500ms
note "Your own links: remove them, change their ttl, replace the content" 5s
pause 6s

effect dissolve 400ms
splash "Downloads"
splash ""
splash "Storages are served over HTTPS. A storage with auth.ssh answers only"
splash "requests signed by the keys it allows, and lists its directories to them."
splash --show --alt 8s
effect left 450ms
chapter "Download"
type -n 'luk get https://drop.example.com/a/luk.vm/2026/10/06/'
run "cat $demo/render/ls.txt"
pause 1s
type -n 'luk get -O https://drop.example.com/a/luk.vm/2026/10/06/jobtest.txt'
run "cat $demo/render/getO.txt"
pause 500ms
note "Signed downloads: only the keys of the expose allow list" 4s
pause 5s

effect dissolve 400ms
splash "Fail early"
splash ""
splash "A wrong pin, a key not allowed, a rate below the minimum of the endpoint:"
splash "luk stops before anything is sent."
splash --show --alt 7s
effect left 450ms
chapter "Refusals"
type -n "luk send --endpoint 'https://drop.example.com/drop#lusab-babad-gutih-tugad-hajop-kizof' --file notes.txt"
run "cat $demo/render/wrongpin.txt"
pause 500ms
note "A wrong pin stops luk before anything is sent" 4s
pause 5s
type -n 'luk send -e drop --file backup.tar --bwlimit 10K'
run "cat $demo/render/bwlimit.txt"
pause 2s

effect dissolve 900ms
splash "luk + lukd"
splash ""
splash "Uploads in parts, in parallel: a stalled part is sent again, not the file."
splash "Private and one-time links, secrets, permanent names, quotas, retention."
splash "Signed downloads, a catalog, a directory listing, a pin you can check."
splash ""
splash "Single static binaries, systemd units, Debian packages."
splash "github.com/rjsocha/luk"
splash --show 4s --stay
vhs-stop
