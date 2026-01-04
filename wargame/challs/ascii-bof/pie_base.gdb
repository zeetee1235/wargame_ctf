
set pagination off
file ./main
b *main
run
p/x $rip - 0x1229
quit
